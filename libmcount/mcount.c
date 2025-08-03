/*
 * mcount() handling routines for uftrace
 *
 * Copyright (C) 2014-2018, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "mcount"
#define PR_DOMAIN DBG_MCOUNT

#include "libmcount/dynamic.h"
#include "libmcount/internal.h"
#include "libmcount/mcount.h"
#include "mcount-arch.h"
#include "utils/filter.h"
#include "utils/script.h"
#include "utils/socket.h"
#include "utils/symbol.h"
#include "utils/utils.h"
#include "version.h"

/*
 * mcount global variables.
 *
 * These are to control various features in the libmcount.
 * They are set during initialization (mcount_startup) which I believe, runs in
 * a single thread.  After that multiple threads (mostly) read the value so it's
 * not protected by lock or something.  So special care needs to be taken if you
 * want to change it at runtime (like in the agent).
 *
 * Some are marked as 'maybe unused' because they are only used when filter
 * functions are implemented.  Note that libmcount is built with different
 * settings like -fast and -single to be more efficient in some situation like
 * when no filter is specified in the command line and/or single-thread only.
 */

/* time filter in nsec */
uint64_t mcount_threshold;

/* size filter */
unsigned mcount_min_size;

/* symbol info for current process */
struct uftrace_sym_info mcount_sym_info = {
	.flags = SYMTAB_FL_DEMANGLE | SYMTAB_FL_ADJ_OFFSET,
};

/* size of shmem buffer to save uftrace_record */
int shmem_bufsize = SHMEM_BUFFER_SIZE;

/* recover return address of parent automatically */
bool mcount_auto_recover = ARCH_SUPPORT_AUTO_RECOVER;

/* global flag to control mcount behavior */
unsigned long mcount_global_flags = MCOUNT_GFL_SETUP;

/* TSD key to save mtd below */
pthread_key_t mtd_key = (pthread_key_t)-1;

/*
 * A thread local data to trace function execution.
 * While this is itself TLS so ok to by accessed safely by each thread,
 * mcount routines use TSD APIs to access it for performance reason.
 * Also TSD provides destructor so it can release the resources when the thread
 * exits.
 */
TLS struct mcount_thread_data mtd;

/* pipe file descriptor to communite to uftrace */
int mcount_pfd = -1;

/* maximum depth of mcount rstack */
static int mcount_rstack_max = MCOUNT_RSTACK_MAX;

/* name of main executable */
char *mcount_exename;

/* whether it should update pid filter manually */
bool kernel_pid_update;

/* system page size */
int page_size_in_kb;

/* call depth to filter */
int __maybe_unused mcount_depth = MCOUNT_DEFAULT_DEPTH;

/* setting for all filter actions */
struct uftrace_filter_setting mcount_filter_setting = {
	.ptype = PATT_REGEX,
	.auto_args = false,
	.allow_kernel = false,
};

/* boolean flag to turn on/off recording */
bool __maybe_unused mcount_enabled = true;

/* triggers definition and counters */
struct uftrace_triggers_info __maybe_unused *mcount_triggers;

/* bitmask of active watch points */
static unsigned long __maybe_unused mcount_watchpoints;

/* address of function will be called when a function returns */
unsigned long mcount_return_fn;

/* address of function will be called when a PLT function returns */
unsigned long plthook_return_fn;

/* do not hook return address and inject EXIT record between functions */
bool mcount_estimate_return;

/* list of watch points (of global variables) */
static LIST_HEAD(mcount_watch_list);

#ifdef DISABLE_MCOUNT_FILTER
/*
 * These functions are only the FAST version of libmcount libraries which don't
 * implement filters (other than time and size filters).
 */

static void mcount_filter_init(struct uftrace_filter_setting *filter_setting, bool force)
{
	if (getenv("UFTRACE_SRCLINE") == NULL)
		return;

	load_module_symtabs(&mcount_sym_info);

	/* use debug info if available */
	prepare_debug_info(&mcount_sym_info, filter_setting->ptype, NULL, NULL, false, force);
	save_debug_info(&mcount_sym_info, mcount_sym_info.dirname);
}

static void mcount_filter_finish(void)
{
	finish_debug_info(&mcount_sym_info);
}

static void mcount_watch_finish(void)
{
}

#else
/*
 * Here goes the regular libmcount's filter and trigger functions.
 */

/* be careful: this can be called from signal handler */
static void mcount_finish_trigger(void)
{
	if (mcount_global_flags & MCOUNT_GFL_FINISH)
		return;

	/* mark other threads can see the finish flag */
	mcount_global_flags |= MCOUNT_GFL_FINISH;
}

static LIST_HEAD(siglist);

struct signal_trigger_item {
	struct list_head list;
	int sig;
	struct uftrace_trigger tr;
};

static struct uftrace_trigger *get_signal_trigger(int sig)
{
	struct signal_trigger_item *item;

	list_for_each_entry(item, &siglist, list) {
		if (item->sig == sig)
			return &item->tr;
	}

	return NULL;
}

static void add_signal_trigger(int sig, const char *name, struct uftrace_trigger *tr)
{
	struct signal_trigger_item *item;

	item = xmalloc(sizeof(*item));
	item->sig = sig;
	memcpy(&item->tr, tr, sizeof(*tr));

	pr_dbg("add signal trigger: %s (%d), flags = %lx\n", name, sig, (unsigned long)tr->flags);

	list_add(&item->list, &siglist);
}

static void mcount_signal_trigger(int sig)
{
	struct uftrace_trigger *tr;

	tr = get_signal_trigger(sig);
	if (tr == NULL)
		return;

	pr_dbg("got signal %d\n", sig);

	if (tr->flags & TRIGGER_FL_TRACE_ON) {
		mcount_enabled = true;
	}
	if (tr->flags & TRIGGER_FL_TRACE_OFF) {
		mcount_enabled = false;
	}
	if (tr->flags & TRIGGER_FL_FINISH) {
		mcount_finish_trigger();
	}
}

/* clang-format off */
#define SIGTABLE_ENTRY(s)  { #s, s }
/* clang-format on */

static const struct sigtable {
	const char *name;
	int sig;
} sigtable[] = {
	SIGTABLE_ENTRY(SIGHUP),	   SIGTABLE_ENTRY(SIGINT),    SIGTABLE_ENTRY(SIGQUIT),
	SIGTABLE_ENTRY(SIGILL),	   SIGTABLE_ENTRY(SIGTRAP),   SIGTABLE_ENTRY(SIGABRT),
	SIGTABLE_ENTRY(SIGBUS),	   SIGTABLE_ENTRY(SIGFPE),    SIGTABLE_ENTRY(SIGKILL),
	SIGTABLE_ENTRY(SIGUSR1),   SIGTABLE_ENTRY(SIGSEGV),   SIGTABLE_ENTRY(SIGUSR2),
	SIGTABLE_ENTRY(SIGPIPE),   SIGTABLE_ENTRY(SIGALRM),   SIGTABLE_ENTRY(SIGTERM),
	SIGTABLE_ENTRY(SIGSTKFLT), SIGTABLE_ENTRY(SIGCHLD),   SIGTABLE_ENTRY(SIGCONT),
	SIGTABLE_ENTRY(SIGSTOP),   SIGTABLE_ENTRY(SIGTSTP),   SIGTABLE_ENTRY(SIGTTIN),
	SIGTABLE_ENTRY(SIGTTOU),   SIGTABLE_ENTRY(SIGURG),    SIGTABLE_ENTRY(SIGXCPU),
	SIGTABLE_ENTRY(SIGXFSZ),   SIGTABLE_ENTRY(SIGVTALRM), SIGTABLE_ENTRY(SIGPROF),
	SIGTABLE_ENTRY(SIGWINCH),  SIGTABLE_ENTRY(SIGIO),     SIGTABLE_ENTRY(SIGPWR),
	SIGTABLE_ENTRY(SIGSYS),
};

#undef SIGTABLE_ENTRY

static int parse_sigspec(char *spec, struct uftrace_filter_setting *setting)
{
	char *pos, *tmp;
	unsigned i;
	int sig = -1;
	int off = 0;
	const char *signame = NULL;
	bool num_spec = false;
	char num_spec_str[16];
	struct uftrace_trigger tr = {
		.flags = 0,
	};
	struct sigaction old_sa;
	struct sigaction sa = {
		.sa_handler = mcount_signal_trigger,
		.sa_flags = SA_RESTART,
	};
	const char *sigrtm = "SIGRTM";
	const char *sigrtmin = "SIGRTMIN";
	const char *sigrtmax = "SIGRTMAX";

	pos = strchr(spec, '@');
	if (pos == NULL)
		return -1;
	*pos = '\0';

	if (isdigit(spec[0]))
		num_spec = true;
	else if (strncmp(spec, "SIG", 3))
		off = 3; /* skip "SIG" prefix */

	for (i = 0; i < ARRAY_SIZE(sigtable); i++) {
		if (num_spec) {
			int num = strtol(spec, &tmp, 0);

			if (num == sigtable[i].sig) {
				sig = num;
				signame = sigtable[i].name;
				break;
			}

			continue;
		}

		if (!strcmp(sigtable[i].name + off, spec)) {
			sig = sigtable[i].sig;
			signame = sigtable[i].name;
			break;
		}
	}

	/* real-time signals */
	if (!strncmp(spec, sigrtm + off, 6 - off)) {
		if (!strncmp(spec, sigrtmin + off, 8 - off))
			sig = SIGRTMIN + strtol(&spec[8 - off], NULL, 0);
		if (!strncmp(spec, sigrtmax + off, 8 - off))
			sig = SIGRTMAX + strtol(&spec[8 - off], NULL, 0);
		signame = spec;
	}

	if (sig == -1 && num_spec) {
		int sigrtmid = (SIGRTMIN + SIGRTMAX) / 2;

		sig = strtol(spec, &tmp, 0);

		/* SIGRTMIN/MAX might not be constant, avoid switch/case */
		if (sig == SIGRTMIN) {
			strcpy(num_spec_str, "SIGRTMIN");
		}
		else if (SIGRTMIN < sig && sig <= sigrtmid) {
			snprintf(num_spec_str, sizeof(num_spec_str), "%s+%d", "SIGRTMIN",
				 sig - SIGRTMIN);
		}
		else if (sigrtmid < sig && sig < SIGRTMAX) {
			snprintf(num_spec_str, sizeof(num_spec_str), "%s-%d", "SIGRTMAX",
				 SIGRTMAX - sig);
		}
		else if (sig == SIGRTMAX) {
			strcpy(num_spec_str, "SIGRTMAX");
		}
		else {
			sig = -1;
		}
		signame = num_spec_str;
	}

	if (sig == -1) {
		pr_use("failed to parse signal: %s\n", spec);
		return -1;
	}

	/* setup_trigger_action() requires the '@' sign */
	*pos = '@';

	tmp = NULL;
	if (setup_trigger_action(spec, &tr, &tmp, TRIGGER_FL_SIGNAL, setting) < 0)
		return -1;

	if (tmp != NULL) {
		pr_warn("invalid signal action: %s\n", tmp);
		free(tmp);
		return -1;
	}

	add_signal_trigger(sig, signame, &tr);
	if (sigaction(sig, &sa, &old_sa) < 0) {
		pr_warn("cannot overwrite signal handler for %s\n", spec);
		sigaction(sig, &old_sa, NULL);
		return -1;
	}

	return 0;
}

static int mcount_signal_init(char *sigspec, struct uftrace_filter_setting *setting)
{
	struct strv strv = STRV_INIT;
	char *spec;
	int i;
	int ret = 0;

	if (sigspec == NULL)
		return 0;

	strv_split(&strv, sigspec, ";");

	strv_for_each(&strv, spec, i) {
		if (parse_sigspec(spec, setting) < 0)
			ret = -1;
	}
	strv_free(&strv);

	return ret;
}

static void mcount_signal_finish(void)
{
	struct signal_trigger_item *item;

	while (!list_empty(&siglist)) {
		item = list_first_entry(&siglist, typeof(*item), list);
		list_del(&item->list);
		free(item);
	}
}

struct uftrace_triggers_info *mcount_trigger_init(struct uftrace_filter_setting *filter_setting)
{
	struct uftrace_triggers_info *triggers;
	char *filter_str = getenv("UFTRACE_FILTER");
	char *trigger_str = getenv("UFTRACE_TRIGGER");
	char *argument_str = getenv("UFTRACE_ARGUMENT");
	char *retval_str = getenv("UFTRACE_RETVAL");
	char *autoargs_str = getenv("UFTRACE_AUTO_ARGS");
	char *patch_str = getenv("UFTRACE_PATCH");
	char *caller_str = getenv("UFTRACE_CALLER");
	char *loc_str = getenv("UFTRACE_LOCATION");
	bool needs_debug_info = false;

	/* setup auto-args only if argument/return value is used */
	if (argument_str || retval_str || autoargs_str ||
	    (trigger_str && (strstr(trigger_str, "arg") || strstr(trigger_str, "retval")))) {
		setup_auto_args(filter_setting);
		needs_debug_info = true;
	}

	if (getenv("UFTRACE_SRCLINE"))
		needs_debug_info = true;

	/* use debug info if available */
	if (needs_debug_info) {
		prepare_debug_info(&mcount_sym_info, filter_setting->ptype, argument_str,
				   retval_str, !!autoargs_str, !!patch_str);
		save_debug_info(&mcount_sym_info, mcount_sym_info.dirname);
	}

	if (!filter_str && !trigger_str && !argument_str && !retval_str && !autoargs_str &&
	    !caller_str && !loc_str)
		return NULL;

	triggers = xzalloc(sizeof(*triggers));
	triggers->root = RB_ROOT;

	filter_setting->auto_args = false;

	uftrace_setup_filter(filter_str, &mcount_sym_info, triggers, filter_setting);
	uftrace_setup_trigger(trigger_str, &mcount_sym_info, triggers, filter_setting);
	uftrace_setup_argument(argument_str, &mcount_sym_info, triggers, filter_setting);
	uftrace_setup_retval(retval_str, &mcount_sym_info, triggers, filter_setting);

	if (needs_debug_info)
		uftrace_setup_loc_filter(loc_str, &mcount_sym_info, triggers, filter_setting);

	if (caller_str)
		uftrace_setup_caller_filter(caller_str, &mcount_sym_info, triggers, filter_setting);

	if (autoargs_str) {
		char *autoarg = ".";
		char *autoret = ".";

		if (filter_setting->ptype == PATT_GLOB)
			autoarg = autoret = "*";

		filter_setting->auto_args = true;

		uftrace_setup_argument(autoarg, &mcount_sym_info, triggers, filter_setting);
		uftrace_setup_retval(autoret, &mcount_sym_info, triggers, filter_setting);
	}

	return triggers;
}

static void mcount_filter_init(struct uftrace_filter_setting *filter_setting, bool force)
{
	filter_setting->lp64 = host_is_lp64();
	filter_setting->arch = host_cpu_arch();

	load_module_symtabs(&mcount_sym_info);

	mcount_signal_init(getenv("UFTRACE_SIGNAL"), filter_setting);

	mcount_triggers = mcount_trigger_init(filter_setting);
	if (mcount_triggers == NULL) {
		/* make sure it has the root of triggers */
		mcount_triggers = xzalloc(sizeof(*mcount_triggers));
		mcount_triggers->root = RB_ROOT;
	}

	if (getenv("UFTRACE_DEPTH"))
		mcount_depth = strtol(getenv("UFTRACE_DEPTH"), NULL, 0);

	if (getenv("UFTRACE_TRACE_OFF"))
		mcount_enabled = false;
}

static void mcount_filter_setup(struct mcount_thread_data *mtdp)
{
	mtdp->filter.max_depth = FILTER_NO_MAX_DEPTH;
	mtdp->filter.depth = 0;
	mtdp->filter.time = FILTER_NO_TIME;
	mtdp->filter.size = mcount_min_size;
	mtdp->enable_cached = mcount_enabled;
	mtdp->argbuf = xmalloc(mcount_rstack_max * ARGBUF_SIZE);
	INIT_LIST_HEAD(&mtdp->pmu_fds);
}

static void mcount_filter_release(struct mcount_thread_data *mtdp)
{
	free(mtdp->argbuf);
	mtdp->argbuf = NULL;
	finish_pmu_event(mtdp);
}

static void mcount_filter_finish(void)
{
	uftrace_cleanup_triggers(mcount_triggers);
	free(mcount_triggers);
	finish_auto_args();

	finish_debug_info(&mcount_sym_info);

	mcount_signal_finish();
}

static void mcount_watch_init(void)
{
	char *watch_str = getenv("UFTRACE_WATCH");
	struct strv watch = STRV_INIT;
	char *str;
	int i;

	if (watch_str == NULL)
		return;

	strv_split(&watch, watch_str, ";");

	strv_for_each(&watch, str, i) {
		if (!strcasecmp(str, "cpu")) {
			mcount_watchpoints |= MCOUNT_WATCH_CPU;
			continue;
		}

		if (!strncasecmp(str, "var:", 4)) {
			struct mcount_watchpoint_item *w;
			struct uftrace_mmap *map = mcount_sym_info.exec_map;
			struct uftrace_symbol *sym;

			w = xmalloc(sizeof(*w));
			sym = find_symname(&map->mod->symtab, str + 4);
			if (sym == NULL) {
				pr_dbg("ignore watchpoint for %s\n", str);
				free(w);
				continue;
			}

			w->kind = MCOUNT_WATCH_VAR;
			w->addr = map->start + sym->addr;
			w->size = sym->size;
			if (w->size > 8) {
				pr_dbg("symbol is too big, ignored... %s\n", str);
				free(w);
				continue;
			}

			list_add_tail(&w->list, &mcount_watch_list);

			mcount_watchpoints |= MCOUNT_WATCH_VAR;
			continue;
		}
	}
	strv_free(&watch);
}

static void mcount_watch_finish(void)
{
	struct mcount_watchpoint_item *w;

	while (!list_empty(&mcount_watch_list)) {
		w = list_first_entry(&mcount_watch_list, typeof(*w), list);
		list_del(&w->list);
		free(w);
	}
}

bool mcount_watch_update(unsigned long addr, void *data, int size)
{
	static pthread_mutex_t watch_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct mcount_watchpoint_item *w;
	bool updated = false;

	pthread_mutex_lock(&watch_mutex);
	list_for_each_entry(w, &mcount_watch_list, list) {
		if (w->addr != addr)
			continue;

		/* someone already updated for us? */
		if (w->inited && !memcmp(data, w->data, size))
			break;

		mcount_memcpy1(w->data, data, size);
		w->inited = true;
		updated = true;
		break;
	}
	pthread_mutex_unlock(&watch_mutex);

	return updated;
}

static void mcount_watch_setup(struct mcount_thread_data *mtdp)
{
	struct mcount_watchpoint_item *pos, *w;

	mtdp->watch.cpu = -1;
	INIT_LIST_HEAD(&mtdp->watch.list);

	/* each thread gets a copy of the global watch items */
	list_for_each_entry(pos, &mcount_watch_list, list) {
		w = xmalloc(sizeof(*w) + pos->size);

		memcpy(w, pos, sizeof(*w));
		memcpy(w->data, (void *)w->addr, w->size);

		list_add_tail(&w->list, &mtdp->watch.list);
	}
}

static void mcount_watch_release(struct mcount_thread_data *mtdp)
{
	struct mcount_watchpoint_item *w;

	while (!list_empty(&mtdp->watch.list)) {
		w = list_first_entry(&mtdp->watch.list, typeof(*w), list);
		list_del(&w->list);
		free(w);
	}
}

#endif /* DISABLE_MCOUNT_FILTER */

/*
 * These are common routines used in every libmcount libraries.
 */

static void send_session_msg(struct mcount_thread_data *mtdp, const char *sess_id)
{
	struct uftrace_msg_sess sess = {
		.task = {
			.time = mcount_gettime(),
			.pid = getpid(),
			.tid = mcount_gettid(mtdp),
		},
		.namelen = strlen(mcount_exename),
	};
	struct uftrace_msg msg = {
		.magic = UFTRACE_MSG_MAGIC,
		.type = UFTRACE_MSG_SESSION,
		.len = sizeof(sess) + sess.namelen,
	};
	struct iovec iov[3] = {
		{
			.iov_base = &msg,
			.iov_len = sizeof(msg),
		},
		{
			.iov_base = &sess,
			.iov_len = sizeof(sess),
		},
		{
			.iov_base = mcount_exename,
			.iov_len = sess.namelen,
		},
	};
	int len = sizeof(msg) + msg.len;

	if (mcount_pfd < 0)
		return;

	mcount_memcpy4(sess.sid, sess_id, sizeof(sess.sid));

	if (writev(mcount_pfd, iov, 3) != len) {
		if (!mcount_should_stop())
			pr_err("send session msg failed");
	}
}

static void mcount_trace_finish(bool send_msg)
{
	static pthread_mutex_t finish_lock = PTHREAD_MUTEX_INITIALIZER;
	static bool trace_finished = false;

	pthread_mutex_lock(&finish_lock);
	if (trace_finished)
		goto unlock;

	/* dtor for script support */
	if (SCRIPT_ENABLED && script_str)
		script_uftrace_end();

	/* notify to uftrace that we're finished */
	if (send_msg)
		uftrace_send_message(UFTRACE_MSG_FINISH, NULL, 0);

	if (mcount_pfd != -1) {
		close(mcount_pfd);
		mcount_pfd = -1;
	}

	trace_finished = true;
	pr_dbg("mcount trace finished\n");

unlock:
	pthread_mutex_unlock(&finish_lock);
}

static void mcount_rstack_estimate_finish(struct mcount_thread_data *mtdp)
{
	uint64_t ret_time = mcount_gettime();

	pr_dbg2("generates EXIT records for task %d (idx = %d)\n", mcount_gettid(mtdp), mtdp->idx);

	while (mtdp->idx > 0) {
		mtdp->idx--;
		ret_time++;

		/* add fake exit records */
		mtdp->rstack[mtdp->idx].end_time = ret_time;
		mcount_exit_filter_record(mtdp, &mtdp->rstack[mtdp->idx], NULL);
	}
}

/* to be used by pthread_create_key() */
void mtd_dtor(void *arg)
{
	struct mcount_thread_data *mtdp = arg;
	struct uftrace_msg_task tmsg;

	if (mtdp->dead)
		return;

	if (mcount_should_stop())
		mcount_trace_finish(true);

	/* this thread is done, do not enter anymore */
	mtdp->recursion_marker = true;
	mtdp->dead = true;

	if (mcount_estimate_return)
		mcount_rstack_estimate_finish(mtdp);

	if (!mtdp->exited)
		mcount_rstack_restore(mtdp);

	if (ARCH_CAN_RESTORE_PLTHOOK || !mcount_rstack_has_plthook(mtdp)) {
		free(mtdp->rstack);
		mtdp->rstack = NULL;
		mtdp->idx = 0;
	}

	mcount_filter_release(mtdp);
	mcount_watch_release(mtdp);
	finish_mem_region(&mtdp->mem_regions);
	shmem_finish(mtdp);

	tmsg.pid = getpid();
	tmsg.tid = mcount_gettid(mtdp);
	tmsg.time = mcount_gettime();

	uftrace_send_message(UFTRACE_MSG_TASK_END, &tmsg, sizeof(tmsg));
}

void __mcount_guard_recursion(struct mcount_thread_data *mtdp)
{
	mtdp->recursion_marker = true;
}

void __mcount_unguard_recursion(struct mcount_thread_data *mtdp)
{
	mtdp->recursion_marker = false;
}

bool mcount_guard_recursion(struct mcount_thread_data *mtdp)
{
	if (unlikely(mtdp->recursion_marker))
		return false;

	if (unlikely(mcount_should_stop())) {
		mtd_dtor(mtdp);
		return false;
	}

	mtdp->recursion_marker = true;
	return true;
}

void mcount_unguard_recursion(struct mcount_thread_data *mtdp)
{
	mtdp->recursion_marker = false;

	if (unlikely(mcount_should_stop()))
		mtd_dtor(mtdp);
}

static struct sigaction old_sigact[2];

static const struct {
	int code;
	char *msg;
} sigsegv_codes[] = {
	{ SEGV_MAPERR, "address not mapped" },
	{ SEGV_ACCERR, "invalid permission" },
#ifdef SEGV_BNDERR
	{ SEGV_BNDERR, "bound check failed" },
#endif
#ifdef SEGV_PKUERR
	{ SEGV_PKUERR, "protection key check failed" },
#endif
};

static void segv_handler(int sig, siginfo_t *si, void *ctx)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	int idx;
	int i;

	/* set line buffer mode not to discard crash message */
	setlinebuf(outfp);

	mtdp = get_thread_data();
	if (check_thread_data(mtdp))
		goto out;

	if (mtdp->idx <= 0)
		goto out;

	mcount_rstack_restore(mtdp);

	idx = mtdp->idx - 1;
	/* flush current rstack on crash */
	rstack = &mtdp->rstack[idx];
	record_trace_data(mtdp, rstack, NULL);

	/* print backtrace */
	for (i = 0; i < (int)ARRAY_SIZE(sigsegv_codes); i++) {
		if (sig != SIGSEGV)
			break;

		if (si->si_code == sigsegv_codes[i].code) {
			pr_warn("Segmentation fault: %s (addr: %p)\n", sigsegv_codes[i].msg,
				si->si_addr);
			break;
		}
	}
	if (sig != SIGSEGV || i == (int)ARRAY_SIZE(sigsegv_codes)) {
		pr_warn("process crashed by signal %d: %s (si_code: %d)\n", sig, strsignal(sig),
			si->si_code);
	}

	if (!mcount_estimate_return) {
		pr_warn(" if this happens only with uftrace,"
			" please consider -e/--estimate-return option.\n\n");
	}

	pr_warn("Backtrace from uftrace " UFTRACE_VERSION "\n");
	pr_warn("=====================================\n");

	while (rstack >= mtdp->rstack) {
		struct uftrace_symbol *parent, *child;
		char *pname, *cname;

		parent = find_symtabs(&mcount_sym_info, rstack->parent_ip);
		pname = symbol_getname(parent, rstack->parent_ip);
		child = find_symtabs(&mcount_sym_info, rstack->child_ip);
		cname = symbol_getname(child, rstack->child_ip);

		pr_warn("[%d] (%s[%lx] <= %s[%lx])\n", idx--, cname, rstack->child_ip, pname,
			rstack->parent_ip);

		symbol_putname(parent, pname);
		symbol_putname(child, cname);

		rstack--;
	}

	pr_out("\n");
	pr_red(BUG_REPORT_MSG);

out:
	sigaction(sig, &old_sigact[(sig == SIGSEGV)], NULL);
	raise(sig);
}

static void mcount_init_file(void)
{
	struct sigaction sa = {
		.sa_sigaction = segv_handler,
		.sa_flags = SA_SIGINFO,
	};

	send_session_msg(&mtd, mcount_session_name());
	pr_dbg("new session started: %.*s: %s\n", SESSION_ID_LEN, mcount_session_name(),
	       uftrace_basename(mcount_exename));

	sigemptyset(&sa.sa_mask);
	sigaction(SIGABRT, &sa, &old_sigact[0]);
	sigaction(SIGSEGV, &sa, &old_sigact[1]);
}

struct mcount_thread_data *mcount_prepare(void)
{
	static pthread_once_t once_control = PTHREAD_ONCE_INIT;
	struct mcount_thread_data *mtdp = &mtd;
	struct uftrace_msg_task tmsg;

	if (unlikely(mcount_should_stop()))
		return NULL;

	/*
	 * If an executable implements its own malloc(),
	 * following recursion could occur
	 *
	 * mcount_entry -> mcount_prepare -> xmalloc -> mcount_entry -> ...
	 */
	if (!mcount_guard_recursion(mtdp))
		return NULL;

	compiler_barrier();

	mcount_filter_setup(mtdp);
	mcount_watch_setup(mtdp);
	mtdp->rstack = xmalloc(mcount_rstack_max * sizeof(*mtd.rstack));

	pthread_once(&once_control, mcount_init_file);
	prepare_shmem_buffer(mtdp);

	pthread_setspecific(mtd_key, mtdp);

	/* time should be get after session message sent */
	tmsg.pid = getpid(), tmsg.tid = mcount_gettid(mtdp), tmsg.time = mcount_gettime();

	uftrace_send_message(UFTRACE_MSG_TASK_START, &tmsg, sizeof(tmsg));

	update_kernel_tid(tmsg.tid);

	return mtdp;
}

static void mcount_finish(void)
{
	if (!mcount_should_stop())
		mcount_trace_finish(false);

	if (mcount_estimate_return) {
		struct mcount_thread_data *mtdp = get_thread_data();
		if (!check_thread_data(mtdp))
			mcount_rstack_estimate_finish(mtdp);
	}

	mcount_global_flags |= MCOUNT_GFL_FINISH;
}

static bool mcount_check_rstack(struct mcount_thread_data *mtdp)
{
	if (mtdp->idx >= mcount_rstack_max) {
		if (!mtdp->warned) {
			struct mcount_ret_stack *rstack;

			pr_warn("call depth beyond %d is not recorded.\n"
				"      (use --max-stack=DEPTH to record more)\n",
				mtdp->idx);
			/* flush current rstack */
			rstack = &mtdp->rstack[mcount_rstack_max - 1];
			record_trace_data(mtdp, rstack, NULL);
			mtdp->warned = true;
		}
		return true;
	}
	mtdp->warned = false;
	return false;
}

#ifndef DISABLE_MCOUNT_FILTER
/*
 * Again, this implements filter functionality used in !fast versions.
 */

extern void *get_argbuf(struct mcount_thread_data *, struct mcount_ret_stack *);

/**
 * mcount_get_filter_mode - compute the filter mode from the filter count
 */
static inline enum filter_mode mcount_get_filter_mode(void)
{
	return mcount_triggers->filter_count > 0 ? FILTER_MODE_IN : FILTER_MODE_OUT;
}

/**
 * mcount_get_loc_mode - compute the location filter mode from the location count
 */
static inline enum filter_mode mcount_get_loc_mode(void)
{
	return mcount_triggers->loc_count > 0 ? FILTER_MODE_IN : FILTER_MODE_OUT;
}

static void mcount_save_filter(struct mcount_thread_data *mtdp)
{
	/* save original depth and time to restore at exit time */
	mtdp->filter.saved_depth = mtdp->filter.depth;
	mtdp->filter.saved_max_depth = mtdp->filter.max_depth;
	mtdp->filter.saved_time = mtdp->filter.time;
	mtdp->filter.saved_size = mtdp->filter.size;
}

/* update filter state from trigger result */
enum filter_result mcount_entry_filter_check(struct mcount_thread_data *mtdp, unsigned long child,
					     struct mcount_regs *regs,
					     const struct uftrace_filter **pfilter)
{
	int max_depth = mtdp->filter.max_depth;
	enum trigger_flag flags = 0;
	const struct uftrace_trigger *tr = NULL;

	if (max_depth == FILTER_NO_MAX_DEPTH)
		max_depth = mcount_depth;

	*pfilter = NULL;

	pr_dbg3("<%d> enter %lx\n", mtdp->idx, child);
	if (mcount_check_rstack(mtdp))
		return FILTER_RSTACK;

	mcount_save_filter(mtdp);

	/* already filtered by notrace option */
	if (mtdp->filter.out_count > 0)
		return FILTER_OUT;

	*pfilter = uftrace_match_filter(mcount_triggers, child);
	if (*pfilter) {
		tr = &(*pfilter)->trigger;
		flags = tr->flags; /* !0 means tr is not NULL */
	}

	pr_dbg3(" tr->flags: %x, filter mode: %d, count: %d/%d, depth: %d\n", flags,
		tr ? tr->fmode : FILTER_MODE_NONE, mtdp->filter.in_count, mtdp->filter.out_count,
		mtdp->filter.depth);

	if ((flags & TRIGGER_FL_CONDITION) && regs) {
		struct mcount_arg_context ctx;
		struct uftrace_arg_spec spec = {
			.idx = tr->cond.idx,
			.fmt = ARG_FMT_AUTO,
			.type = ARG_TYPE_INDEX,
		};

		mcount_memset4(&ctx, 0, sizeof(ctx));
		ctx.regs = regs;
		ctx.regions = &mtdp->mem_regions;
		ctx.arch = &mtdp->arch;

		mcount_arch_get_arg(&ctx, &spec);

		/* keep the filter only if the condition is met */
		if (!uftrace_eval_cond(&(*pfilter)->trigger.cond, ctx.val.i))
			flags &= ~TRIGGER_FL_FILTER;
	}

	if (flags & TRIGGER_FL_FILTER) {
		if (tr->fmode == FILTER_MODE_IN)
			mtdp->filter.in_count++;
		else if (tr->fmode == FILTER_MODE_OUT)
			mtdp->filter.out_count++;

		/* apply default filter depth when match */
		mtdp->filter.depth = 0;
	}
	else {
		/* not matched by filter */
		if (mcount_get_filter_mode() == FILTER_MODE_IN && mtdp->filter.in_count == 0)
			return FILTER_OUT;
	}

	if (flags & TRIGGER_FL_LOC) {
		if (tr->lmode == FILTER_MODE_OUT)
			return FILTER_OUT;
	}
	else {
		if (mcount_get_loc_mode() == FILTER_MODE_IN)
			return FILTER_OUT;
	}

#define FLAGS_TO_CHECK                                                                             \
	(TRIGGER_FL_DEPTH | TRIGGER_FL_TRACE_ON | TRIGGER_FL_TRACE_OFF | TRIGGER_FL_TIME_FILTER |  \
	 TRIGGER_FL_SIZE_FILTER)
	if (flags & FLAGS_TO_CHECK) {
		if (flags & TRIGGER_FL_DEPTH) {
			mtdp->filter.depth = 0;
			mtdp->filter.max_depth = max_depth = tr->depth;
		}
		if (flags & TRIGGER_FL_TRACE_ON)
			mcount_enabled = true;
		if (flags & TRIGGER_FL_TRACE_OFF)
			mcount_enabled = false;

		if (flags & TRIGGER_FL_TIME_FILTER)
			mtdp->filter.time = tr->time;

		if (flags & TRIGGER_FL_SIZE_FILTER)
			mtdp->filter.size = tr->size;
	}

#undef FLAGS_TO_CHECK

	if (mtdp->filter.depth >= max_depth)
		return FILTER_OUT;

	mtdp->filter.depth++;
	return FILTER_IN;
}

static int script_save_context(struct script_context *sc_ctx, struct mcount_thread_data *mtdp,
			       struct mcount_ret_stack *rstack, char *symname, bool has_arg_retval,
			       struct list_head *pargs)
{
	if (!script_match_filter(symname))
		return -1;

	sc_ctx->tid = mcount_gettid(mtdp);
	sc_ctx->depth = rstack->depth;
	sc_ctx->address = rstack->child_ip;
	sc_ctx->name = symname;
	sc_ctx->timestamp = rstack->start_time;
	if (rstack->end_time)
		sc_ctx->duration = rstack->end_time - rstack->start_time;

	if (has_arg_retval) {
		unsigned *argbuf = get_argbuf(mtdp, rstack);

		sc_ctx->arglen = argbuf[0];
		sc_ctx->argbuf = &argbuf[1];
		sc_ctx->argspec = pargs;
	}
	else {
		/* prevent access to arguments */
		sc_ctx->arglen = 0;
	}

	return 0;
}

static void script_hook_entry(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack,
			      const struct uftrace_filter *filter)
{
	struct script_context sc_ctx;
	unsigned long entry_addr = rstack->child_ip;
	struct uftrace_symbol *sym = find_symtabs(&mcount_sym_info, entry_addr);
	char *symname = symbol_getname(sym, entry_addr);

	if (script_save_context(&sc_ctx, mtdp, rstack, symname,
				filter ? (filter->trigger.flags & TRIGGER_FL_ARGUMENT) : 0,
				filter ? filter->trigger.pargs : NULL) < 0)
		goto skip;

	/* accessing argument in script might change arch-context */
	mcount_save_arch_context(&mtdp->arch);
	script_uftrace_entry(&sc_ctx);
	mcount_restore_arch_context(&mtdp->arch);

skip:
	symbol_putname(sym, symname);
}

static void script_hook_exit(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack)
{
	struct script_context sc_ctx;
	unsigned long entry_addr = rstack->child_ip;
	struct uftrace_symbol *sym = find_symtabs(&mcount_sym_info, entry_addr);
	char *symname = symbol_getname(sym, entry_addr);

	if (script_save_context(&sc_ctx, mtdp, rstack, symname, rstack->flags & MCOUNT_FL_RETVAL,
				rstack->pargs) < 0)
		goto skip;

	/* accessing argument in script might change arch-context */
	mcount_save_arch_context(&mtdp->arch);
	script_uftrace_exit(&sc_ctx);
	mcount_restore_arch_context(&mtdp->arch);

skip:
	symbol_putname(sym, symname);
}

/**
 * filter_save_to_rstack - save current filter state to rstack
 * @mtdp - thread data
 *
 * The current values can be overwritten by triggers, and will be restored from
 * @rstack at function exit.
 */
static void filter_save_to_rstack(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack)
{
	rstack->filter_depth = mtdp->filter.saved_depth;
	rstack->filter_max_depth = mtdp->filter.saved_max_depth;
	rstack->filter_time = mtdp->filter.saved_time;
	rstack->filter_size = mtdp->filter.saved_size;
}

void mcount_entry_filter_record(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack,
				struct mcount_regs *regs, const struct uftrace_filter *filter)
{
	enum trigger_flag flags = filter ? filter->trigger.flags : 0;

	if (mtdp->filter.out_count > 0 ||
	    (mtdp->filter.in_count == 0 && mcount_get_filter_mode() == FILTER_MODE_IN) ||
	    (mtdp->filter.size > 0 &&
	     mcount_getsize(&mcount_sym_info, rstack->child_ip) < mtdp->filter.size))
		rstack->flags |= MCOUNT_FL_NORECORD;

	filter_save_to_rstack(mtdp, rstack);

#define FLAGS_TO_CHECK                                                                             \
	(TRIGGER_FL_FILTER | TRIGGER_FL_RETVAL | TRIGGER_FL_TRACE | TRIGGER_FL_FINISH |            \
	 TRIGGER_FL_CALLER)

	if (flags & FLAGS_TO_CHECK) {
		if (flags & TRIGGER_FL_FILTER) {
			if (filter->trigger.fmode == FILTER_MODE_IN)
				rstack->flags |= MCOUNT_FL_FILTERED;
			else
				rstack->flags |= MCOUNT_FL_NOTRACE;
		}

		/* check if it has to keep arg_spec for retval */
		if (flags & TRIGGER_FL_RETVAL) {
			rstack->pargs = filter->trigger.pargs;
			rstack->flags |= MCOUNT_FL_RETVAL;
		}

		if (flags & TRIGGER_FL_TRACE)
			rstack->flags |= MCOUNT_FL_TRACE;

		if (flags & TRIGGER_FL_CALLER)
			rstack->flags |= MCOUNT_FL_CALLER;

		if (flags & TRIGGER_FL_FINISH) {
			record_trace_data(mtdp, rstack, NULL);
			mcount_finish_trigger();
			return;
		}
	}

#undef FLAGS_TO_CHECK

	if (!(rstack->flags & MCOUNT_FL_NORECORD)) {
		mtdp->record_idx++;

		if (!mcount_enabled) {
			rstack->flags |= MCOUNT_FL_DISABLED;
			/*
			 * Flush existing rstack when mcount_enabled is off
			 * (i.e. disabled).  Note that changing to enabled is
			 * already handled in record_trace_data() on exit path
			 * using the MCOUNT_FL_DISABLED flag.
			 */
			if (unlikely(mtdp->enable_cached))
				record_trace_data(mtdp, rstack, NULL);
		}
		else {
			if (regs && (flags & TRIGGER_FL_ARGUMENT))
				save_argument(mtdp, rstack, filter->trigger.pargs, regs);
			if (flags & TRIGGER_FL_READ) {
				save_trigger_read(mtdp, rstack, filter->trigger.read, false);
				rstack->flags |= MCOUNT_FL_READ;
			}
			if (mcount_watchpoints)
				save_watchpoint(mtdp, rstack, mcount_watchpoints);

			if (mtdp->nr_events) {
				bool flush = false;
				int i;

				/*
				 * Flush rstacks if async event was recorded
				 * as it only has limited space for the events.
				 */
				for (i = 0; i < mtdp->nr_events; i++)
					if (mtdp->event[i].idx == ASYNC_IDX)
						flush = true;

				if (flush)
					record_trace_data(mtdp, rstack, NULL);
			}
		}

		/* script hooking for function entry */
		if (SCRIPT_ENABLED && script_str)
			script_hook_entry(mtdp, rstack, filter);

#define FLAGS_TO_CHECK (TRIGGER_FL_RECOVER | TRIGGER_FL_TRACE_ON | TRIGGER_FL_TRACE_OFF)

		if (flags & FLAGS_TO_CHECK) {
			if ((flags & TRIGGER_FL_RECOVER) && !mcount_estimate_return) {
				mcount_rstack_restore(mtdp);
				*rstack->parent_loc = mcount_return_fn;
				rstack->flags |= MCOUNT_FL_RECOVER;
			}
			if (flags & (TRIGGER_FL_TRACE_ON | TRIGGER_FL_TRACE_OFF))
				mtdp->enable_cached = mcount_enabled;
		}
	}

#undef FLAGS_TO_CHECK
}

/**
 * filter_restore_from_rstack - restore filters to their value at function entry
 * @mtdp - thread data
 */
static void filter_restore_from_rstack(struct mcount_thread_data *mtdp,
				       struct mcount_ret_stack *rstack)
{
	mtdp->filter.depth = rstack->filter_depth;
	mtdp->filter.max_depth = rstack->filter_max_depth;
	mtdp->filter.time = rstack->filter_time;
	mtdp->filter.size = rstack->filter_size;
}

void mcount_exit_filter_record(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack,
			       long *retval)
{
	uint64_t time_filter = mtdp->filter.time;

	if (time_filter == FILTER_NO_TIME)
		time_filter = mcount_threshold;

	pr_dbg3("<%d> exit  %lx\n", mtdp->idx, rstack->child_ip);

#define FLAGS_TO_CHECK (MCOUNT_FL_FILTERED | MCOUNT_FL_NOTRACE | MCOUNT_FL_RECOVER)

	if (rstack->flags & FLAGS_TO_CHECK) {
		if (rstack->flags & MCOUNT_FL_FILTERED)
			mtdp->filter.in_count--;
		else if (rstack->flags & MCOUNT_FL_NOTRACE)
			mtdp->filter.out_count--;

		if (rstack->flags & MCOUNT_FL_RECOVER)
			mcount_rstack_rehook(mtdp);
	}

#undef FLAGS_TO_CHECK

	filter_restore_from_rstack(mtdp, rstack);

	if (!(rstack->flags & MCOUNT_FL_NORECORD)) {
		if (mtdp->record_idx > 0)
			mtdp->record_idx--;

		if (!mcount_enabled)
			return;

		if (rstack->flags & MCOUNT_FL_RETVAL) {
			const struct uftrace_filter *filter;

			/* update args as trigger might be updated due to dlopen() */
			filter = uftrace_match_filter(mcount_triggers, rstack->child_ip);
			if (filter)
				rstack->pargs = filter->trigger.pargs;
		}
		else {
			retval = NULL;
		}

		if (rstack->flags & MCOUNT_FL_READ) {
			const struct uftrace_filter *filter;

			/* there's a possibility of overwriting by return value */
			filter = uftrace_match_filter(mcount_triggers, rstack->child_ip);
			if (filter)
				save_trigger_read(mtdp, rstack, filter->trigger.read, true);
		}

		if (mcount_watchpoints)
			save_watchpoint(mtdp, rstack, mcount_watchpoints);

		if (((rstack->end_time - rstack->start_time > time_filter) &&
		     (!mcount_triggers->caller_count || rstack->flags & MCOUNT_FL_CALLER)) ||
		    rstack->flags & (MCOUNT_FL_WRITTEN | MCOUNT_FL_TRACE)) {
			if (record_trace_data(mtdp, rstack, retval) < 0)
				pr_err("error during record");
		}
		else if (mtdp->nr_events) {
			bool flush = false;
			int i, k;

			/*
			 * Record rstacks if async event was recorded
			 * in the middle of the function.  Otherwise
			 * update event count to drop filtered ones.
			 */
			for (i = 0, k = 0; i < mtdp->nr_events; i++) {
				if (mtdp->event[i].idx == ASYNC_IDX)
					flush = true;
				if (mtdp->event[i].idx < mtdp->idx)
					k = i + 1;
			}

			if (flush)
				record_trace_data(mtdp, rstack, retval);
			else
				mtdp->nr_events = k; /* invalidate sync events */
		}

		/* script hooking for function exit */
		if (SCRIPT_ENABLED && script_str)
			script_hook_exit(mtdp, rstack);
	}
}

#else /* DISABLE_MCOUNT_FILTER */
/*
 * Here fast versions don't implement filters.
 */

enum filter_result mcount_entry_filter_check(struct mcount_thread_data *mtdp, unsigned long child,
					     struct mcount_regs *regs,
					     const struct uftrace_filter **pfilter)
{
	*pfilter = NULL;

	if (mcount_check_rstack(mtdp))
		return FILTER_RSTACK;

	if (mcount_min_size > 0 && mcount_getsize(&mcount_sym_info, child) < mcount_min_size)
		return FILTER_OUT;

	return FILTER_IN;
}

void mcount_entry_filter_record(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack,
				struct mcount_regs *regs, const struct uftrace_filter *filter)
{
	mtdp->record_idx++;
}

void mcount_exit_filter_record(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack,
			       long *retval)
{
	mtdp->record_idx--;

	if (rstack->end_time - rstack->start_time > mcount_threshold ||
	    rstack->flags & MCOUNT_FL_WRITTEN) {
		if (record_trace_data(mtdp, rstack, NULL) < 0)
			pr_err("error during record");
	}
}

static void mcount_save_filter(struct mcount_thread_data *mtdp)
{
}
#endif /* DISABLE_MCOUNT_FILTER */

#ifndef FIX_PARENT_LOC
static inline unsigned long *mcount_arch_parent_location(struct uftrace_sym_info *sinfo,
							 unsigned long *parent_loc,
							 unsigned long child_ip)
{
	return parent_loc;
}
#endif

bool within_same_module(unsigned long addr1, unsigned long addr2)
{
	return find_map(&mcount_sym_info, addr1) == find_map(&mcount_sym_info, addr2);
}

void mcount_rstack_inject_return(struct mcount_thread_data *mtdp, unsigned long *frame_pointer,
				 unsigned long addr)
{
	uint64_t estimated_ret_time = 0;

	if (mtdp->idx > 0) {
		int idx = mtdp->idx - 1;

		/*
		 * NOTE: we don't know the exact return time.
		 * estimate it as a half of delta from the previous start.
		 */
		estimated_ret_time = mcount_gettime();
		estimated_ret_time += mtdp->rstack[idx].start_time;
		estimated_ret_time /= 2;

		/*
		 * if previous symbol is a PLT function, and this one came
		 * from same module, we assume these two are siblings and
		 * use same depth even if it has a lower frame pointer.
		 */
		if (mtdp->rstack[idx].dyn_idx != MCOUNT_INVALID_DYNIDX &&
		    mtdp->rstack[idx].parent_loc > frame_pointer &&
		    within_same_module(mtdp->rstack[idx].child_ip, addr)) {
			/* add a fake exit record for the PLT func */
			mtdp->rstack[idx].end_time = estimated_ret_time;
			mcount_exit_filter_record(mtdp, &mtdp->rstack[idx], NULL);
			/* make it have a same depth */
			mtdp->idx--;
			mtdp->record_idx = mtdp->idx;
			mcount_save_filter(mtdp);
			return;
		}
	}

	while (mtdp->idx > 0) {
		int below = mtdp->idx - 1;

		if (mtdp->rstack[below].parent_loc == &mtdp->cygprof_dummy)
			break;

		if (mtdp->rstack[below].parent_loc > frame_pointer)
			break;

		/* add fake exit records */
		mtdp->rstack[below].end_time = estimated_ret_time;
		mcount_exit_filter_record(mtdp, &mtdp->rstack[below], NULL);
		mtdp->idx--;
		estimated_ret_time++;
	}
	mtdp->record_idx = mtdp->idx;
	mcount_save_filter(mtdp);
}

static int __mcount_entry(unsigned long *parent_loc, unsigned long child, struct mcount_regs *regs)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	const struct uftrace_filter *filter;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return -1;
	}
	else {
		if (!mcount_guard_recursion(mtdp))
			return -1;
	}

	filtered = mcount_entry_filter_check(mtdp, child, regs, &filter);
	if (filtered != FILTER_IN) {
		mcount_unguard_recursion(mtdp);
		return -1;
	}

	if (unlikely(mtdp->in_exception)) {
		unsigned long frame_addr;

		/* same as __builtin_frame_addr(2) but avoid warning */
		frame_addr = parent_loc[-1];

		/* basic sanity check */
		if (frame_addr < (unsigned long)parent_loc)
			frame_addr = (unsigned long)(parent_loc - 1);

		mcount_rstack_rehook_exception(mtdp, frame_addr);
		mtdp->in_exception = false;
	}

	/* fixup the parent_loc in an arch-dependant way (if needed) */
	parent_loc = mcount_arch_parent_location(&mcount_sym_info, parent_loc, child);

	if (mcount_estimate_return)
		mcount_rstack_inject_return(mtdp, parent_loc, child);

	rstack = &mtdp->rstack[mtdp->idx++];

	rstack->depth = mtdp->record_idx;
	rstack->dyn_idx = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = parent_loc;
	rstack->parent_ip = *parent_loc;
	rstack->child_ip = child;
	rstack->start_time = mcount_gettime();
	rstack->end_time = 0;
	rstack->flags = 0;
	rstack->nr_events = 0;
	rstack->event_idx = ARGBUF_SIZE;

	if (!mcount_estimate_return) {
		/* hijack the return address of child */
		*parent_loc = mcount_return_fn;

		/* restore return address of parent */
		if (mcount_auto_recover)
			mcount_auto_restore(mtdp);
	}

	mcount_entry_filter_record(mtdp, rstack, regs, filter);
	mcount_unguard_recursion(mtdp);
	return 0;
}

int mcount_entry(unsigned long *parent_loc, unsigned long child, struct mcount_regs *regs)
{
	int saved_errno = errno;
	int ret = __mcount_entry(parent_loc, child, regs);

	errno = saved_errno;
	return ret;
}

static unsigned long __mcount_exit(long *retval)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	unsigned long *ret_loc;
	unsigned long retaddr;

	mtdp = get_thread_data();
	ASSERT(mtdp != NULL);
	ASSERT(!mtdp->dead);

	/*
	 * it's only called when mcount_entry() was succeeded and
	 * no need to check recursion here.  But still needs to
	 * prevent recursion during this call.
	 */
	__mcount_guard_recursion(mtdp);

	rstack = &mtdp->rstack[mtdp->idx - 1];

	rstack->end_time = mcount_gettime();
	mcount_exit_filter_record(mtdp, rstack, retval);

	ret_loc = rstack->parent_loc;
	retaddr = rstack->parent_ip;

	/* re-hijack return address of parent */
	if (mcount_auto_recover)
		mcount_auto_rehook(mtdp);

	__mcount_unguard_recursion(mtdp);

	if (unlikely(mcount_should_stop())) {
		mtd_dtor(mtdp);
		/*
		 * mtd_dtor() will free rstack but current ret_addr
		 * might be plthook_return() when it was a tail call.
		 * Reload the return address after mtd_dtor() restored
		 * all the parent locations.
		 */
		retaddr = *ret_loc;
	}

	compiler_barrier();

	mtdp->idx--;
	return retaddr;
}

unsigned long mcount_exit(long *retval)
{
	int saved_errno = errno;
	unsigned long ret = __mcount_exit(retval);

	errno = saved_errno;
	return ret;
}

static int __cygprof_entry(unsigned long parent, unsigned long child)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	const struct uftrace_filter *filter;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return -1;
	}
	else {
		if (!mcount_guard_recursion(mtdp))
			return -1;
	}

	filtered = mcount_entry_filter_check(mtdp, child, NULL, &filter);

	if (unlikely(mtdp->in_exception)) {
		unsigned long *frame_ptr;
		unsigned long frame_addr;

		frame_ptr = __builtin_frame_address(0);
		frame_addr = *frame_ptr; /* XXX: probably dangerous */

		/* basic sanity check */
		if (frame_addr < (unsigned long)frame_ptr)
			frame_addr = (unsigned long)frame_ptr;

		mcount_rstack_rehook_exception(mtdp, frame_addr);
		mtdp->in_exception = false;
	}

	if (mcount_estimate_return)
		mcount_rstack_inject_return(mtdp, (void *)~0UL, child);

	rstack = &mtdp->rstack[mtdp->idx++];

	/*
	 * even if it already exceeds the rstack max, it needs to increase idx
	 * since the cygprof_exit() will be called anyway
	 */
	if (filtered == FILTER_RSTACK) {
		mcount_unguard_recursion(mtdp);
		return 0;
	}

	rstack->depth = mtdp->record_idx;
	rstack->dyn_idx = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = &mtdp->cygprof_dummy;
	rstack->parent_ip = parent;
	rstack->child_ip = child;
	rstack->end_time = 0;
	rstack->nr_events = 0;
	rstack->event_idx = ARGBUF_SIZE;

	if (filtered == FILTER_IN) {
		rstack->start_time = mcount_gettime();
		rstack->flags = MCOUNT_FL_CYGPROF;
	}
	else {
		rstack->start_time = 0;
		rstack->flags = MCOUNT_FL_CYGPROF | MCOUNT_FL_NORECORD;
	}

	mcount_entry_filter_record(mtdp, rstack, NULL, filter);
	mcount_unguard_recursion(mtdp);
	return 0;
}

static int cygprof_entry(unsigned long parent, unsigned long child)
{
	int saved_errno = errno;
	int ret = __cygprof_entry(parent, child);

	errno = saved_errno;
	return ret;
}

static void warn_unpaired_cygprof(void)
{
	pr_warn("unpaired cygprof exit: dropping...\n");
}

static void __cygprof_exit(unsigned long parent, unsigned long child)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	if (!mcount_guard_recursion(mtdp))
		return;

	/*
	 * cygprof_exit() can be called beyond rstack max.
	 * It cannot use mcount_check_rstack() here
	 * since we didn't decrease the idx yet.
	 */
	if (mtdp->idx > mcount_rstack_max)
		goto out;

	rstack = &mtdp->rstack[mtdp->idx - 1];

	/* discard unpaired cygprof exit (due to compiler bug?) */
	if (unlikely(!(rstack->flags & MCOUNT_FL_CYGPROF))) {
		static pthread_once_t warn_once = PTHREAD_ONCE_INIT;

		pthread_once(&warn_once, warn_unpaired_cygprof);
		mcount_unguard_recursion(mtdp);
		return;
	}

	if (!(rstack->flags & MCOUNT_FL_NORECORD))
		rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(mtdp, rstack, NULL);

out:
	mcount_unguard_recursion(mtdp);

	compiler_barrier();

	mtdp->idx--;
}

static void cygprof_exit(unsigned long parent, unsigned long child)
{
	int saved_errno = errno;

	__cygprof_exit(parent, child);
	errno = saved_errno;
}

static void _xray_entry(unsigned long parent, unsigned long child, struct mcount_regs *regs)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	const struct uftrace_filter *filter;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return;
	}
	else {
		if (!mcount_guard_recursion(mtdp))
			return;
	}

	filtered = mcount_entry_filter_check(mtdp, child, NULL, &filter);

	if (unlikely(mtdp->in_exception)) {
		unsigned long *frame_ptr;
		unsigned long frame_addr;

		frame_ptr = __builtin_frame_address(0);
		frame_addr = *frame_ptr; /* XXX: probably dangerous */

		/* basic sanity check */
		if (frame_addr < (unsigned long)frame_ptr)
			frame_addr = (unsigned long)frame_ptr;

		mcount_rstack_rehook_exception(mtdp, frame_addr);
		mtdp->in_exception = false;
	}

	if (mcount_estimate_return)
		mcount_rstack_inject_return(mtdp, (void *)~0UL, child);

	rstack = &mtdp->rstack[mtdp->idx++];

	rstack->depth = mtdp->record_idx;
	rstack->dyn_idx = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = &mtdp->cygprof_dummy;
	rstack->parent_ip = parent;
	rstack->child_ip = child;
	rstack->end_time = 0;
	rstack->nr_events = 0;
	rstack->event_idx = ARGBUF_SIZE;

	if (filtered == FILTER_IN) {
		rstack->start_time = mcount_gettime();
		rstack->flags = 0;
	}
	else {
		rstack->start_time = 0;
		rstack->flags = MCOUNT_FL_NORECORD;
	}

	mcount_entry_filter_record(mtdp, rstack, regs, filter);
	mcount_unguard_recursion(mtdp);
}

void xray_entry(unsigned long parent, unsigned long child, struct mcount_regs *regs)
{
	int saved_errno = errno;

	_xray_entry(parent, child, regs);
	errno = saved_errno;
}

static void _xray_exit(long *retval)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	if (!mcount_guard_recursion(mtdp))
		return;

	/*
	 * cygprof_exit() can be called beyond rstack max.
	 * It cannot use mcount_check_rstack() here
	 * since we didn't decrease the idx yet.
	 */
	if (mtdp->idx > mcount_rstack_max)
		goto out;

	rstack = &mtdp->rstack[mtdp->idx - 1];

	if (!(rstack->flags & MCOUNT_FL_NORECORD))
		rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(mtdp, rstack, retval);

out:
	mcount_unguard_recursion(mtdp);

	compiler_barrier();

	mtdp->idx--;
}

void xray_exit(long *retval)
{
	int saved_errno = errno;

	_xray_exit(retval);
	errno = saved_errno;
}

static void atfork_prepare_handler(void)
{
	struct uftrace_msg_task tmsg = {
		.time = mcount_gettime(),
		.pid = getpid(),
	};

	/* call script atfork preparation routine */
	if (SCRIPT_ENABLED && script_str)
		script_atfork_prepare();

	uftrace_send_message(UFTRACE_MSG_FORK_START, &tmsg, sizeof(tmsg));

	/* flush remaining contents in the stream */
	fflush(outfp);
	fflush(logfp);
}

static void atfork_child_handler(void)
{
	struct mcount_thread_data *mtdp;
	struct uftrace_msg_task tmsg = {
		.time = mcount_gettime(),
		.pid = getppid(),
		.tid = getpid(),
	};
	int i;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return;
	}
	else {
		if (!mcount_guard_recursion(mtdp))
			return;
	}

	/* update tid cache */
	mtdp->tid = tmsg.tid;
	/* flush event data */
	mtdp->nr_events = 0;

	clear_shmem_buffer(mtdp);
	prepare_shmem_buffer(mtdp);

	uftrace_send_message(UFTRACE_MSG_FORK_END, &tmsg, sizeof(tmsg));

	update_kernel_tid(tmsg.tid);

	/* do not record parent's functions */
	for (i = 0; i < mtdp->idx; i++)
		mtdp->rstack[i].flags |= MCOUNT_FL_WRITTEN;

	mcount_unguard_recursion(mtdp);
}

static void mcount_script_init(enum uftrace_pattern_type patt_type)
{
	struct script_info info = {
		.name = script_str,
		.version = UFTRACE_VERSION,
		.record = true,
	};
	char *cmds_str;

	cmds_str = getenv("UFTRACE_ARGS");
	if (cmds_str)
		strv_split(&info.cmds, cmds_str, "\n");

	if (script_init(&info, patt_type) < 0)
		script_str = NULL;

	strv_free(&info.cmds);
}

static __used void mcount_startup(void)
{
	char *channel = NULL;
	char *logfd_str;
	char *debug_str;
	char *bufsize_str;
	char *maxstack_str;
	char *threshold_str;
	char *minsize_str;
	char *color_str;
	char *demangle_str;
	char *plthook_str;
	char *patch_str;
	char *event_str;
	char *dirname;
	char *pattern_str;
	char *clock_str;
	char *symdir_str;
	struct stat statbuf;
	bool nest_libcall;

	if (!(mcount_global_flags & MCOUNT_GFL_SETUP))
		return;

	mtd.recursion_marker = true;

	outfp = stdout;
	logfp = stderr;

	if (pthread_key_create(&mtd_key, mtd_dtor))
		pr_err("cannot create mtd key");

	logfd_str = getenv("UFTRACE_LOGFD");
	debug_str = getenv("UFTRACE_DEBUG");
	bufsize_str = getenv("UFTRACE_BUFFER");
	maxstack_str = getenv("UFTRACE_MAX_STACK");
	color_str = getenv("UFTRACE_COLOR");
	threshold_str = getenv("UFTRACE_THRESHOLD");
	minsize_str = getenv("UFTRACE_MIN_SIZE");
	demangle_str = getenv("UFTRACE_DEMANGLE");
	plthook_str = getenv("UFTRACE_PLTHOOK");
	patch_str = getenv("UFTRACE_PATCH");
	event_str = getenv("UFTRACE_EVENT");
	script_str = getenv("UFTRACE_SCRIPT");
	nest_libcall = !!getenv("UFTRACE_NEST_LIBCALL");
	pattern_str = getenv("UFTRACE_PATTERN");
	clock_str = getenv("UFTRACE_CLOCK");
	symdir_str = getenv("UFTRACE_SYMBOL_DIR");

	page_size_in_kb = getpagesize() / KB;

	if (logfd_str) {
		int fd = strtol(logfd_str, NULL, 0);

		/* minimal sanity check */
		if (!fstat(fd, &statbuf)) {
			logfp = fdopen(fd, "a");
			if (logfp == NULL)
				pr_err("opening log file failed");

			setvbuf(logfp, NULL, _IOLBF, 1024);
		}
	}

	if (debug_str) {
		debug = strtol(debug_str, NULL, 0);
		build_debug_domain(getenv("UFTRACE_DEBUG_DOMAIN"));
	}

	if (demangle_str)
		demangler = strtol(demangle_str, NULL, 0);

	if (color_str)
		setup_color(strtol(color_str, NULL, 0), NULL);
	else
		setup_color(COLOR_AUTO, NULL);

	pr_dbg("initializing mcount library\n");

	dirname = getenv("UFTRACE_DIR");
	if (dirname == NULL)
		dirname = UFTRACE_DIR_NAME;

	xasprintf(&channel, "%s/%s", dirname, ".channel");
	mcount_pfd = open(channel, O_WRONLY);
	free(channel);

	if (getenv("UFTRACE_LIST_EVENT")) {
		mcount_list_events();
		exit(0);
	}

	if (bufsize_str)
		shmem_bufsize = strtol(bufsize_str, NULL, 0);

	mcount_exename = read_exename();
	mcount_sym_info.dirname = dirname;
	mcount_sym_info.symdir = symdir_str ?: dirname;
	mcount_sym_info.filename = mcount_exename;

	if (symdir_str)
		mcount_sym_info.flags |= SYMTAB_FL_USE_SYMFILE | SYMTAB_FL_SYMS_DIR;

	record_proc_maps(dirname, mcount_session_name(), &mcount_sym_info);

	if (pattern_str)
		mcount_filter_setting.ptype = parse_filter_pattern(pattern_str);

	if (patch_str)
		mcount_return_fn = mcount_arch_ops.exit[UFT_ARCH_OPS_DYNAMIC];
	else
		mcount_return_fn = mcount_arch_ops.exit[UFT_ARCH_OPS_MCOUNT];

	plthook_return_fn = mcount_arch_ops.exit[UFT_ARCH_OPS_PLTHOOK];

	mcount_filter_init(&mcount_filter_setting, !!patch_str);
	mcount_watch_init();

	if (maxstack_str)
		mcount_rstack_max = strtol(maxstack_str, NULL, 0);

	if (threshold_str)
		mcount_threshold = strtoull(threshold_str, NULL, 0);

	if (minsize_str)
		mcount_min_size = strtoul(minsize_str, NULL, 0);

	if (patch_str)
		mcount_dynamic_update(&mcount_sym_info, patch_str, mcount_filter_setting.ptype);

	if (event_str)
		mcount_setup_events(dirname, event_str, mcount_filter_setting.ptype);

	if (getenv("UFTRACE_KERNEL_PID_UPDATE"))
		kernel_pid_update = true;

	if (getenv("UFTRACE_ESTIMATE_RETURN"))
		mcount_estimate_return = true;

	if (plthook_str) {
		/* PLT hook depends on mcount_estimate_return */
		mcount_setup_plthook(mcount_exename, nest_libcall);
	}

	if (clock_str)
		setup_clock_id(clock_str);

	if (getenv("UFTRACE_AGENT"))
		agent_spawn();

	pthread_atfork(atfork_prepare_handler, NULL, atfork_child_handler);

	mcount_hook_functions();

	/* initialize script binding */
	if (SCRIPT_ENABLED && script_str)
		mcount_script_init(mcount_filter_setting.ptype);

	compiler_barrier();
	pr_dbg("mcount setup done\n");

	mcount_global_flags &= ~MCOUNT_GFL_SETUP;
	mtd.recursion_marker = false;
}

static void mcount_cleanup(void)
{
	agent_kill();
	mcount_finish();
	destroy_dynsym_indexes();
	mcount_dynamic_finish();

#if 0
	/*
	 * This mtd_key deletion sometimes makes other thread get crashed
	 * because they may try to get mtdp based on this mtd_key after being
	 * deleted.  Since this key deletion is not mandatory, it'd be better
	 * not to delete it until we find a better solution.
	 */
	pthread_key_delete(mtd_key);
	mtd_key = -1;
#endif

	mcount_filter_finish();
	mcount_watch_finish();

	if (SCRIPT_ENABLED && script_str)
		script_finish();
	script_str = NULL;

	unload_module_symtabs();

	pr_dbg("exit from libmcount\n");
}

/*
 * external interfaces
 */
#define UFTRACE_ALIAS(_func) void uftrace_##_func(void *, void *) __alias(_func)

/* This is the historic startup routine for mcount but not used here. */
void __visible_default __monstartup(unsigned long low, unsigned long high)
{
}

/* This is the historic cleanup routine for mcount but not used here. */
void __visible_default _mcleanup(void)
{
}

/*
 * This is a non-standard external function to work around some stack
 * corruption problems in the past.  I hope we don't need it anymore.
 */
void __visible_default mcount_restore(void)
{
	struct mcount_thread_data *mtdp;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	mcount_rstack_restore(mtdp);
}

/*
 * This is a non-standard external function to work around some stack
 * corruption problems in the past.  I hope we don't need it anymore.
 */
void __visible_default mcount_reset(void)
{
	struct mcount_thread_data *mtdp;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	mcount_rstack_rehook(mtdp);
}

/*
 * External entry points for -finstrument-functions.  The alias was added to
 * avoid calling them through PLT.
 */
void __visible_default __cyg_profile_func_enter(void *child, void *parent)
{
	cygprof_entry((unsigned long)parent, (unsigned long)child);
}
UFTRACE_ALIAS(__cyg_profile_func_enter);

void __visible_default __cyg_profile_func_exit(void *child, void *parent)
{
	cygprof_exit((unsigned long)parent, (unsigned long)child);
}
UFTRACE_ALIAS(__cyg_profile_func_exit);

bool mcount_is_main_executable(const char *filename, const char *exename)
{
	/* on Linux main executable has empty name
	   whereas on Android we need to compare with exename */
	char filename_canonized[PATH_MAX];
	char exename_canonized[PATH_MAX];

	if (!*filename)
		return true;
	if (realpath(filename, filename_canonized) && realpath(exename, exename_canonized)) {
		return strcmp(filename_canonized, exename_canonized) == 0;
	}
	return false;
}

#ifndef UNIT_TEST
/*
 * Initializer and Finalizer
 */
static void __attribute__((constructor)) mcount_init(void)
{
	mcount_startup();
}

static void __attribute__((destructor)) mcount_fini(void)
{
	mcount_cleanup();
}
#else /* UNIT_TEST */

#include <sys/mman.h>

static void setup_mcount_test(void)
{
	pr_dbg("init libmcount for testing\n");

	mcount_exename = read_exename();
	pthread_key_create(&mtd_key, mtd_dtor);
	mcount_global_flags = 0;

	mcount_triggers = xmalloc(sizeof(*mcount_triggers));
	memset(mcount_triggers, 0, sizeof(*mcount_triggers));
	mcount_triggers->root = RB_ROOT;
}

#define SHMEM_SESSION_FMT "/uftrace-%s-%d-%03d"

static void cleanup_thread_data(struct mcount_thread_data *mtdp)
{
	char shm_id[128];
	int tid = mcount_gettid(mtdp);
	int idx;

	shmem_finish(mtdp);

	for (idx = 0; idx < 2; idx++) {
		snprintf(shm_id, sizeof(shm_id), SHMEM_SESSION_FMT, mcount_session_name(), tid,
			 idx);
		shm_unlink(shm_id);
	}
}

TEST_CASE(mcount_thread_data)
{
	struct mcount_thread_data *mtdp;

	setup_mcount_test();

	pr_dbg("try to get thread data - should fail\n");
	mtdp = get_thread_data();
	TEST_EQ(check_thread_data(mtdp), true);

	pr_dbg("mcount_prepare() should setup the thread data\n");
	mtdp = mcount_prepare();
	TEST_EQ(check_thread_data(mtdp), false);

	TEST_EQ(get_thread_data(), mtdp);

	TEST_EQ(check_thread_data(mtdp), false);

	cleanup_thread_data(mtdp);
	mcount_cleanup();

	return TEST_OK;
}

TEST_CASE(mcount_signal_setup)
{
	struct signal_trigger_item *item;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_NONE,
	};

	/* it signal triggers are maintained in a stack (LIFO) */
	mcount_signal_init("SIGUSR1@traceon;USR2@traceoff;RTMIN+3@finish", &setting);

	item = list_first_entry(&siglist, typeof(*item), list);
	TEST_EQ(item->sig, SIGRTMIN + 3);
	TEST_EQ(item->tr.flags, TRIGGER_FL_FINISH);

	item = list_next_entry(item, list);
	TEST_EQ(item->sig, SIGUSR2);
	TEST_EQ(item->tr.flags, TRIGGER_FL_TRACE_OFF);

	item = list_next_entry(item, list);
	TEST_EQ(item->sig, SIGUSR1);
	TEST_EQ(item->tr.flags, TRIGGER_FL_TRACE_ON);

	mcount_signal_finish();

	TEST_EQ(list_empty(&siglist), true);

	return TEST_OK;
}

struct fake_rstack {
	unsigned long *frame_pointer;
	unsigned long func_addr;
};

TEST_CASE(mcount_estimate_return_depth)
{
	/* dummy frame pointer values - just to check relative values */
	unsigned long frame_pointers[8];
	/* increase idx/depth when frame pointer goes down */
	struct fake_rstack test_scenario[] = {
		{ &frame_pointers[7], 0x1234 }, { &frame_pointers[4], 0x1234 },
		{ &frame_pointers[0], 0x1234 }, { &frame_pointers[4], 0x1234 },
		{ &frame_pointers[5], 0x1234 },
	};
	/* mtdp->idx increased after mcount_entry() */
	int depth_check[] = { 0, 1, 2, 1, 1 };
	struct mcount_thread_data *mtdp;
	unsigned i;

	setup_mcount_test();
	mtdp = mcount_prepare();
	/* mcount_prepare calls mcount_guard_recursion() internally */
	mcount_unguard_recursion(mtdp);

	mcount_estimate_return = true;

	for (i = 0; i < ARRAY_SIZE(test_scenario); i++) {
		TEST_EQ(mcount_entry(test_scenario[i].frame_pointer, test_scenario[i].func_addr,
				     NULL),
			0);

		pr_dbg("[%d] mcount entry: idx = %d, depth = %d\n", i, mtdp->idx,
		       mtdp->rstack[mtdp->idx - 1].depth);
		TEST_EQ(mtdp->idx, depth_check[i] + 1);
		TEST_EQ(mtdp->rstack[mtdp->idx - 1].depth, depth_check[i]);
	}

	cleanup_thread_data(mtdp);
	mcount_cleanup();

	return TEST_OK;
}

#define TESTDIR_NAME "testdir"

TEST_CASE(mcount_setup)
{
	setenv("UFTRACE_DIR", TESTDIR_NAME, 1);
	setenv("UFTRACE_FILTER", "mcount.*_init", 1);
	setenv("UFTRACE_ESTIMATE_RETURN", "1", 1);

	create_directory(TESTDIR_NAME);

	TEST_EQ(mcount_global_flags, MCOUNT_GFL_SETUP);
	TEST_EQ(mcount_return_fn, 0);

	/* just to detect sanitizer failures */
	mcount_startup();

	TEST_EQ(mcount_global_flags, 0);
	TEST_EQ(mcount_estimate_return, true);
	TEST_NE(mcount_return_fn, 0);

	mcount_cleanup();

	TEST_EQ(mcount_global_flags, MCOUNT_GFL_FINISH);

	remove_directory(TESTDIR_NAME);

	return TEST_OK;
}

#endif /* UNIT_TEST */
