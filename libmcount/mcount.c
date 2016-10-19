/*
 * mcount() handling routines for ftrace
 *
 * Copyright (C) 2014-2016, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <gelf.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "mcount-arch.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/compiler.h"

uint64_t mcount_threshold;  /* nsec */
struct symtabs symtabs = {
	.flags = SYMTAB_FL_DEMANGLE | SYMTAB_FL_ADJ_OFFSET,
};
int shmem_bufsize = SHMEM_BUFFER_SIZE;
bool mcount_setup_done;
bool mcount_finished;

pthread_key_t mtd_key;
TLS struct mcount_thread_data mtd;

static int pfd = -1;
static int mcount_rstack_max = MCOUNT_RSTACK_MAX;
static char *mcount_exename;

#ifndef DISABLE_MCOUNT_FILTER
static int mcount_depth = MCOUNT_DEFAULT_DEPTH;
static bool mcount_enabled = true;
static enum filter_mode mcount_filter_mode = FILTER_MODE_NONE;

static struct rb_root mcount_triggers = RB_ROOT;
#endif /* DISABLE_MCOUNT_FILTER */

uint64_t mcount_gettime(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int gettid(struct mcount_thread_data *mtdp)
{
	if (!mtdp->tid)
		mtdp->tid = syscall(SYS_gettid);

	return mtdp->tid;
}

const char *session_name(void)
{
	static char session[16 + 1];
	static uint64_t session_id;
	int fd;

	if (!session_id) {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0)
			pr_err("cannot open urandom file");

		if (read(fd, &session_id, sizeof(session_id)) != 8)
			pr_err("reading from urandom");

		close(fd);

		snprintf(session, sizeof(session), "%016"PRIx64, session_id);
	}
	return session;
}

void ftrace_send_message(int type, void *data, size_t len)
{
	struct ftrace_msg msg = {
		.magic = FTRACE_MSG_MAGIC,
		.type = type,
		.len = len,
	};
	struct iovec iov[2] = {
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = data, .iov_len = len, },
	};

	if (pfd < 0)
		return;

	len += sizeof(msg);
	if (writev(pfd, iov, 2) != (ssize_t)len)
		pr_err("writing shmem name to pipe");
}

static void send_session_msg(struct mcount_thread_data *mtdp, const char *sess_id)
{
	struct ftrace_msg_sess sess = {
		.task = {
			.time = mcount_gettime(),
			.pid = getpid(),
			.tid = gettid(mtdp),
		},
		.namelen = strlen(mcount_exename),
	};
	struct ftrace_msg msg = {
		.magic = FTRACE_MSG_MAGIC,
		.type = FTRACE_MSG_SESSION,
		.len = sizeof(sess) + sess.namelen,
	};
	struct iovec iov[3] = {
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = &sess, .iov_len = sizeof(sess), },
		{ .iov_base = mcount_exename, .iov_len = sess.namelen, },
	};
	int len = sizeof(msg) + msg.len;

	if (pfd < 0)
		return;

	memcpy(sess.sid, sess_id, sizeof(sess.sid));

	if (writev(pfd, iov, 3) != len)
		pr_err("write tid info failed");
}

/* to be used by pthread_create_key() */
static void mtd_dtor(void *arg)
{
	struct mcount_thread_data *mtdp = arg;

	free(mtdp->rstack);
#ifndef DISABLE_MCOUNT_FILTER
	free(mtdp->argbuf);
#endif
	shmem_finish(mtdp);
}

static void mcount_init_file(void)
{
	/* This is for the case of library-only tracing */
	if (!mcount_setup_done)
		__monstartup(0, ~0);

	if (pthread_key_create(&mtd_key, mtd_dtor))
		pr_err("cannot create shmem key");

	send_session_msg(&mtd, session_name());
}

void mcount_prepare(void)
{
	static pthread_once_t once_control = PTHREAD_ONCE_INIT;
	struct ftrace_msg_task tmsg = {
		.pid = getpid(),
		.tid = gettid(&mtd),
	};

#ifndef DISABLE_MCOUNT_FILTER
	mtd.filter.depth  = mcount_depth;
	mtd.enable_cached = mcount_enabled;
	mtd.argbuf = xmalloc(mcount_rstack_max * ARGBUF_SIZE);
#endif
	mtd.rstack = xmalloc(mcount_rstack_max * sizeof(*mtd.rstack));

	pthread_once(&once_control, mcount_init_file);
	prepare_shmem_buffer(&mtd);

	pthread_setspecific(mtd_key, &mtd);

	/* time should be get after session message sent */
	tmsg.time = mcount_gettime();

	ftrace_send_message(FTRACE_MSG_TID, &tmsg, sizeof(tmsg));
}

bool mcount_check_rstack(struct mcount_thread_data *mtdp)
{
	if (mtdp->idx >= mcount_rstack_max) {
		static bool warned = false;

		if (!warned) {
			pr_log("too deeply nested calls: %d\n", mtdp->idx);
			warned = true;
		}
		return true;
	}
	return false;
}

#ifndef DISABLE_MCOUNT_FILTER
/* update filter state from trigger result */
enum filter_result mcount_entry_filter_check(struct mcount_thread_data *mtdp,
					     unsigned long child,
					     struct ftrace_trigger *tr)
{
	pr_dbg3("<%d> enter %lx\n", mtdp->idx, child);

	if (mcount_check_rstack(mtdp))
		return FILTER_RSTACK;

	/* save original depth to restore at exit time */
	mtdp->filter.saved_depth = mtdp->filter.depth;

	/* already filtered by notrace option */
	if (mtdp->filter.out_count > 0)
		return FILTER_OUT;

	ftrace_match_filter(&mcount_triggers, child, tr);

	pr_dbg3(" tr->flags: %lx, filter mode, count: [%d] %d/%d\n",
		tr->flags, mcount_filter_mode, mtdp->filter.in_count,
		mtdp->filter.out_count);

	if (tr->flags & TRIGGER_FL_FILTER) {
		if (tr->fmode == FILTER_MODE_IN)
			mtdp->filter.in_count++;
		else if (tr->fmode == FILTER_MODE_OUT)
			mtdp->filter.out_count++;

		/* apply default filter depth when match */
		mtdp->filter.depth = mcount_depth;
	}
	else {
		/* not matched by filter */
		if (mcount_filter_mode == FILTER_MODE_IN &&
		    mtdp->filter.in_count == 0)
			return FILTER_OUT;
	}

#define FLAGS_TO_CHECK  (TRIGGER_FL_DEPTH | TRIGGER_FL_TRACE_ON | TRIGGER_FL_TRACE_OFF)

	if (tr->flags & FLAGS_TO_CHECK) {
		if (tr->flags & TRIGGER_FL_DEPTH)
			mtdp->filter.depth = tr->depth;

		if (tr->flags & TRIGGER_FL_TRACE_ON)
			mcount_enabled = true;

		if (tr->flags & TRIGGER_FL_TRACE_OFF)
			mcount_enabled = false;
	}

#undef FLAGS_TO_CHECK

	if (!mcount_enabled)
		return FILTER_IN;

	if (mtdp->filter.depth <= 0)
		return FILTER_OUT;

	mtdp->filter.depth--;
	return FILTER_IN;
}

/* save current filter state to rstack */
void mcount_entry_filter_record(struct mcount_thread_data *mtdp,
				struct mcount_ret_stack *rstack,
				struct ftrace_trigger *tr,
				struct mcount_regs *regs)
{
	if (mtdp->filter.out_count > 0 ||
	    (mtdp->filter.in_count == 0 && mcount_filter_mode == FILTER_MODE_IN))
		rstack->flags |= MCOUNT_FL_NORECORD;

	rstack->filter_depth = mtdp->filter.saved_depth;

#define FLAGS_TO_CHECK  (TRIGGER_FL_FILTER | TRIGGER_FL_RETVAL | TRIGGER_FL_TRACE)

	if (tr->flags & FLAGS_TO_CHECK) {
		if (tr->flags & TRIGGER_FL_FILTER) {
			if (tr->fmode == FILTER_MODE_IN)
				rstack->flags |= MCOUNT_FL_FILTERED;
			else
				rstack->flags |= MCOUNT_FL_NOTRACE;
		}

		/* check if it has to keep arg_spec for retval */
		if (tr->flags & TRIGGER_FL_RETVAL) {
			rstack->pargs = tr->pargs;
			rstack->flags |= MCOUNT_FL_RETVAL;
		}

		if (tr->flags & TRIGGER_FL_TRACE)
			rstack->flags |= MCOUNT_FL_TRACE;
	}

#undef FLAGS_TO_CHECK

	if (!(rstack->flags & MCOUNT_FL_NORECORD)) {
		mtdp->record_idx++;

		if (!mcount_enabled) {
			rstack->flags |= MCOUNT_FL_DISABLED;
		}
		else if (tr->flags & TRIGGER_FL_ARGUMENT) {
			save_argument(mtdp, rstack, tr->pargs, regs);
		}

		if (mtdp->enable_cached != mcount_enabled) {
			/*
			 * Flush existing rstack when mcount_enabled is off
			 * (i.e. disabled).  Note that changing to enabled is
			 * already handled in record_trace_data() on exit path
			 * using the MCOUNT_FL_DISALBED flag.
			 */
			if (!mcount_enabled)
				record_trace_data(mtdp, rstack, NULL);

			mtdp->enable_cached = mcount_enabled;
		}

		if (tr->flags & TRIGGER_FL_RECOVER) {
			mcount_restore();
			*rstack->parent_loc = (unsigned long) mcount_return;
			rstack->flags |= MCOUNT_FL_RECOVER;
		}
	}
}

/* restore filter state from rstack */
void mcount_exit_filter_record(struct mcount_thread_data *mtdp,
			       struct mcount_ret_stack *rstack,
			       long *retval)
{
	pr_dbg3("<%d> exit  %lx\n", mtdp->idx, rstack->child_ip);

#define FLAGS_TO_CHECK  (MCOUNT_FL_FILTERED | MCOUNT_FL_NOTRACE | MCOUNT_FL_RECOVER)

	if (rstack->flags & FLAGS_TO_CHECK) {
		if (rstack->flags & MCOUNT_FL_FILTERED)
			mtdp->filter.in_count--;
		else if (rstack->flags & MCOUNT_FL_NOTRACE)
			mtdp->filter.out_count--;

		if (rstack->flags & MCOUNT_FL_RECOVER)
			mcount_reset();
	}

#undef FLAGS_TO_CHECK

	mtdp->filter.depth = rstack->filter_depth;

	if (!(rstack->flags & MCOUNT_FL_NORECORD)) {
		if (mtdp->record_idx > 0)
			mtdp->record_idx--;

		if (!(rstack->flags & MCOUNT_FL_RETVAL))
			retval = NULL;

		if (rstack->end_time - rstack->start_time > mcount_threshold ||
		    rstack->flags & (MCOUNT_FL_WRITTEN | MCOUNT_FL_TRACE)) {
			if (!mcount_enabled)
				return;

			if (record_trace_data(mtdp, rstack, retval) < 0)
				pr_err("error during record");
		}
	}
}

#else /* DISABLE_MCOUNT_FILTER */
enum filter_result mcount_entry_filter_check(struct mcount_thread_data *mtdp,
					     unsigned long child,
					     struct ftrace_trigger *tr)
{
	if (mcount_check_rstack(mtdp))
		return FILTER_RSTACK;

	return FILTER_IN;
}

void mcount_entry_filter_record(struct mcount_thread_data *mtdp,
				struct mcount_ret_stack *rstack,
				struct ftrace_trigger *tr,
				struct mcount_regs *regs)
{
	mtdp->record_idx++;
}

void mcount_exit_filter_record(struct mcount_thread_data *mtdp,
			       struct mcount_ret_stack *rstack,
			       long *retval)
{
	mtdp->record_idx--;

	if (rstack->end_time - rstack->start_time > mcount_threshold ||
	    rstack->flags & MCOUNT_FL_WRITTEN) {
		if (record_trace_data(mtdp, rstack, NULL) < 0)
			pr_err("error during record");
	}
}

#endif /* DISABLE_MCOUNT_FILTER */

__weak unsigned long *mcount_arch_parent_location(struct symtabs *symtabs,
						  unsigned long *parent_loc,
						  unsigned long child_ip)
{
	return parent_loc;
}

int mcount_entry(unsigned long *parent_loc, unsigned long child,
		 struct mcount_regs *regs)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	struct ftrace_trigger tr = {
		.flags = 0,
	};

	/*
	 * If an executable has its own malloc(), following recursion could occur
	 *
	 * mcount_entry -> mcount_prepare -> xmalloc -> mcount_entry -> ...
	 */
	if (unlikely(mcount_should_stop()))
		return -1;

	mtd.recursion_guard = true;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mcount_prepare();

		mtdp = get_thread_data();
		assert(mtdp);
	}

	filtered = mcount_entry_filter_check(mtdp, child, &tr);
	if (filtered != FILTER_IN) {
		mtdp->recursion_guard = false;
		return -1;
	}

	/* fixup the parent_loc in an arch-dependant way (if needed) */
	parent_loc = mcount_arch_parent_location(&symtabs, parent_loc, child);

	rstack = &mtdp->rstack[mtdp->idx++];

	rstack->depth      = mtdp->record_idx;
	rstack->dyn_idx    = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = parent_loc;
	rstack->parent_ip  = *parent_loc;
	rstack->child_ip   = child;
	rstack->start_time = mcount_gettime();
	rstack->end_time   = 0;
	rstack->flags      = 0;

	/* hijack the return address */
	*parent_loc = (unsigned long)mcount_return;

	mcount_entry_filter_record(mtdp, rstack, &tr, regs);
	mtdp->recursion_guard = false;
	return 0;
}

unsigned long mcount_exit(long *retval)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	unsigned long retaddr;

	mtdp = get_thread_data();
	assert(mtdp);

	mtdp->recursion_guard = true;

	rstack = &mtdp->rstack[mtdp->idx - 1];

	rstack->end_time = mcount_gettime();
	mcount_exit_filter_record(mtdp, rstack, retval);

	retaddr = rstack->parent_ip;

	compiler_barrier();

	mtdp->idx--;
	mtdp->recursion_guard = false;

	return retaddr;
}

static void mcount_finish(void)
{
	if (mcount_finished)
		return;

	mtd_dtor(&mtd);
	pthread_key_delete(mtd_key);

	if (pfd != -1) {
		close(pfd);
		pfd = -1;
	}

	mcount_finished = true;
}

static int cygprof_entry(unsigned long parent, unsigned long child)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	struct ftrace_trigger tr = {
		.flags = 0,
	};

	if (unlikely(mcount_should_stop()))
		return -1;

	mtd.recursion_guard = true;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mcount_prepare();

		mtdp = get_thread_data();
		assert(mtdp);
	}

	filtered = mcount_entry_filter_check(mtdp, child, &tr);

	/* 'recover' trigger is only for -pg entry */
	tr.flags &= ~TRIGGER_FL_RECOVER;

	rstack = &mtdp->rstack[mtdp->idx++];

	/*
	 * even if it already exceeds the rstack max, it needs to increase idx
	 * since the cygprof_exit() will be called anyway
	 */
	if (filtered == FILTER_RSTACK) {
		mtdp->recursion_guard = false;
		return 0;
	}

	rstack->depth      = mtdp->record_idx;
	rstack->dyn_idx    = MCOUNT_INVALID_DYNIDX;
	rstack->parent_ip  = parent;
	rstack->child_ip   = child;
	rstack->end_time   = 0;

	if (filtered == FILTER_IN) {
		rstack->start_time = mcount_gettime();
		rstack->flags      = 0;
	}
	else {
		rstack->start_time = 0;
		rstack->flags      = MCOUNT_FL_NORECORD;
	}

	mcount_entry_filter_record(mtdp, rstack, &tr, NULL);
	mtdp->recursion_guard = false;
	return 0;
}

static void cygprof_exit(unsigned long parent, unsigned long child)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;

	if (unlikely(mcount_should_stop()))
		return;

	mtd.recursion_guard = true;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mcount_prepare();

		mtdp = get_thread_data();
		assert(mtdp);
	}

	/*
	 * cygprof_exit() can be called beyond rstack max.
	 * it cannot use mcount_check_rstack() here
	 * since we didn't decrease the idx yet.
	 */
	if (mtdp->idx > mcount_rstack_max)
		goto out;

	rstack = &mtdp->rstack[mtdp->idx - 1];

	if (!(rstack->flags & MCOUNT_FL_NORECORD))
		rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(mtdp, rstack, NULL);

	compiler_barrier();

out:
	mtdp->idx--;
	mtdp->recursion_guard = false;
}

static void atfork_prepare_handler(void)
{
	struct ftrace_msg_task tmsg = {
		.time = mcount_gettime(),
		.pid = getpid(),
	};

	ftrace_send_message(FTRACE_MSG_FORK_START, &tmsg, sizeof(tmsg));
}

static void atfork_child_handler(void)
{
	struct mcount_thread_data *mtdp;
	struct ftrace_msg_task tmsg = {
		.time = mcount_gettime(),
		.pid = getppid(),
		.tid = getpid(),
	};

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mcount_prepare();

		mtdp = get_thread_data();
		assert(mtdp);
	}

	mtd.tid = 0;

	clear_shmem_buffer(&mtd);
	prepare_shmem_buffer(&mtd);

	ftrace_send_message(FTRACE_MSG_FORK_END, &tmsg, sizeof(tmsg));
}

static void build_debug_domain(char *dbg_domain_str)
{
	int i, len;

	if (dbg_domain_str == NULL)
		return;

	len = strlen(dbg_domain_str);
	for (i = 0; i < len; i += 2) {
		const char *pos;
		char domain = dbg_domain_str[i];
		int level = dbg_domain_str[i+1] - '0';
		int d;

		pos = strchr(DBG_DOMAIN_STR, domain);
		if (pos == NULL)
			continue;

		d = pos - DBG_DOMAIN_STR;
		dbg_domain[d] = level;
	}
}

/*
 * external interfaces
 */
void __visible_default __monstartup(unsigned long low, unsigned long high)
{
	char *pipefd_str;
	char *logfd_str;
	char *debug_str;
	char *bufsize_str;
	char *maxstack_str;
	char *threshold_str;
	char *color_str;
	char *demangle_str;
	char *dirname;
	struct stat statbuf;
	LIST_HEAD(modules);

	if (mcount_setup_done || mtd.recursion_guard)
		return;

	mtd.recursion_guard = true;

	outfp = stdout;
	logfp = stderr;

	pipefd_str = getenv("UFTRACE_PIPE");
	logfd_str = getenv("UFTRACE_LOGFD");
	debug_str = getenv("UFTRACE_DEBUG");
	bufsize_str = getenv("UFTRACE_BUFFER");
	maxstack_str = getenv("UFTRACE_MAX_STACK");
	color_str = getenv("UFTRACE_COLOR");
	threshold_str = getenv("UFTRACE_THRESHOLD");
	demangle_str = getenv("UFTRACE_DEMANGLE");

	if (logfd_str) {
		int fd = strtol(logfd_str, NULL, 0);

		/* minimal sanity check */
		if (!fstat(fd, &statbuf)) {
			logfp = fdopen(fd, "a");
			setvbuf(logfp, NULL, _IOLBF, 1024);
		}
	}

	if (debug_str) {
		debug = strtol(debug_str, NULL, 0);
		build_debug_domain(getenv("UFTRACE_DEBUG_DOMAIN"));
	}

	if (demangle_str)
		demangler = strtol(demangle_str, NULL, 0);

	pr_dbg("initializing mcount library\n");

	if (color_str)
		setup_color(strtol(color_str, NULL, 0));

	if (pipefd_str) {
		pfd = strtol(pipefd_str, NULL, 0);

		/* minimal sanity check */
		if (fstat(pfd, &statbuf) < 0 || !S_ISFIFO(statbuf.st_mode)) {
			pr_dbg("ignore invalid pipe fd: %d\n", pfd);
			pfd = -1;
		}
	}

	if (bufsize_str)
		shmem_bufsize = strtol(bufsize_str, NULL, 0);

	dirname = getenv("UFTRACE_DIR");
	if (dirname == NULL)
		dirname = UFTRACE_DIR_NAME;

	mcount_exename = read_exename();
	record_proc_maps(dirname, session_name(), &symtabs);
	load_symtabs(&symtabs, NULL, mcount_exename);

#ifndef DISABLE_MCOUNT_FILTER
	ftrace_setup_filter_module(getenv("UFTRACE_FILTER"), &modules);
	ftrace_setup_filter_module(getenv("UFTRACE_TRIGGER"), &modules);
	ftrace_setup_filter_module(getenv("UFTRACE_ARGUMENT"), &modules);
	ftrace_setup_filter_module(getenv("UFTRACE_RETVAL"), &modules);

	load_module_symtabs(&symtabs, &modules);

	ftrace_setup_filter(getenv("UFTRACE_FILTER"), &symtabs, NULL,
			    &mcount_triggers, &mcount_filter_mode);

	ftrace_setup_trigger(getenv("UFTRACE_TRIGGER"), &symtabs, NULL,
			     &mcount_triggers);

	ftrace_setup_argument(getenv("UFTRACE_ARGUMENT"), &symtabs, NULL,
			      &mcount_triggers);

	ftrace_setup_retval(getenv("UFTRACE_RETVAL"), &symtabs, NULL,
			      &mcount_triggers);

	if (getenv("UFTRACE_DEPTH"))
		mcount_depth = strtol(getenv("UFTRACE_DEPTH"), NULL, 0);

	if (getenv("UFTRACE_DISABLED"))
		mcount_enabled = false;
#endif /* DISABLE_MCOUNT_FILTER */

	if (maxstack_str)
		mcount_rstack_max = strtol(maxstack_str, NULL, 0);

	if (threshold_str)
		mcount_threshold = strtoull(threshold_str, NULL, 0);

	if (getenv("UFTRACE_PLTHOOK")) {
		if (symtabs.loaded && symtabs.dsymtab.nr_sym == 0) {
			pr_dbg("skip PLT hooking due to no dynamic symbols\n");
			goto out;
		}

		setup_dynsym_indexes(&symtabs);

#ifndef DISABLE_MCOUNT_FILTER
		ftrace_setup_filter(getenv("UFTRACE_FILTER"), &symtabs, "PLT",
				    &mcount_triggers, &mcount_filter_mode);

		ftrace_setup_trigger(getenv("UFTRACE_TRIGGER"), &symtabs, "PLT",
				    &mcount_triggers);

		ftrace_setup_argument(getenv("UFTRACE_ARGUMENT"), &symtabs, "PLT",
				      &mcount_triggers);

		ftrace_setup_retval(getenv("UFTRACE_RETVAL"), &symtabs, "PLT",
				      &mcount_triggers);
#endif /* DISABLE_MCOUNT_FILTER */

		if (hook_pltgot(mcount_exename, symtabs.maps->start) < 0)
			pr_dbg("error when hooking plt: skipping...\n");
		else
			plthook_setup(&symtabs);
	}

out:
	pthread_atfork(atfork_prepare_handler, NULL, atfork_child_handler);

#ifndef DISABLE_MCOUNT_FILTER
	ftrace_cleanup_filter_module(&modules);
#endif /* DISABLE_MCOUNT_FILTER */

	compiler_barrier();

	mcount_setup_done = true;
	mtd.recursion_guard = false;
}

void __visible_default _mcleanup(void)
{
	mcount_finish();
	destroy_dynsym_indexes();

#ifndef DISABLE_MCOUNT_FILTER
	ftrace_cleanup_filter(&mcount_triggers);
#endif
}

void __visible_default mcount_restore(void)
{
	int idx;
	struct mcount_thread_data *mtdp;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	for (idx = mtdp->idx - 1; idx >= 0; idx--)
		*mtdp->rstack[idx].parent_loc = mtdp->rstack[idx].parent_ip;
}

void __visible_default mcount_reset(void)
{
	int idx;
	struct mcount_thread_data *mtdp;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	for (idx = mtdp->idx - 1; idx >= 0; idx--)
		*mtdp->rstack[idx].parent_loc = (unsigned long)mcount_return;
}

void __visible_default __cyg_profile_func_enter(void *child, void *parent)
{
	cygprof_entry((unsigned long)parent, (unsigned long)child);
}

void __visible_default __cyg_profile_func_exit(void *child, void *parent)
{
	cygprof_exit((unsigned long)parent, (unsigned long)child);
}

/*
 * Initializer and Finalizer
 */
static void __attribute__((constructor))
mcount_init(void)
{
	if (!mcount_setup_done)
		__monstartup(0UL, ~0UL);
}

static void __attribute__((destructor))
mcount_fini(void)
{
	_mcleanup();
}
