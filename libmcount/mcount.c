/*
 * mcount() handling routines for uftrace
 *
 * Copyright (C) 2014-2017, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/uio.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "mcount-arch.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/script.h"

/* time filter in nsec */
uint64_t mcount_threshold;

/* symbol table of main executable */
struct symtabs symtabs = {
	.flags = SYMTAB_FL_DEMANGLE | SYMTAB_FL_ADJ_OFFSET,
};

/* size of shmem buffer to save uftrace_record */
int shmem_bufsize = SHMEM_BUFFER_SIZE;

/* global flag to control mcount behavior */
unsigned long mcount_global_flags = MCOUNT_GFL_SETUP;

/* TSD key to save mtd below */
pthread_key_t mtd_key = (pthread_key_t)-1;

/* thread local data to trace function execution */
TLS struct mcount_thread_data mtd;

/* pipe file descriptor to communite to uftrace */
int pfd = -1;

/* maximum depth of mcount rstack */
static int mcount_rstack_max = MCOUNT_RSTACK_MAX;

/* name of main executable */
char *mcount_exename;

/* whether it should update pid filter manually */
bool kernel_pid_update;

/* system page size */
int page_size_in_kb;

/* call depth to filter */
static int __maybe_unused mcount_depth = MCOUNT_DEFAULT_DEPTH;

/* boolean flag to turn on/off recording */
static bool __maybe_unused mcount_enabled = true;

/* function filtering mode - inclusive or exclusive */
static enum filter_mode __maybe_unused mcount_filter_mode = FILTER_MODE_NONE;

/* tree of trigger actions */
static struct rb_root __maybe_unused mcount_triggers = RB_ROOT;

#ifndef DISABLE_MCOUNT_FILTER
static void prepare_pmu_trigger(struct rb_root *root)
{
	struct rb_node *node = rb_first(root);
	struct uftrace_filter *entry;

	while (node) {
		entry = rb_entry(node, typeof(*entry), node);

		if (entry->trigger.flags & TRIGGER_FL_READ) {
			if (entry->trigger.read & TRIGGER_READ_PMU_CYCLE)
				if (prepare_pmu_event(EVENT_ID_READ_PMU_CYCLE) < 0)
					break;
			if (entry->trigger.read & TRIGGER_READ_PMU_CACHE)
				if (prepare_pmu_event(EVENT_ID_READ_PMU_CACHE) < 0)
					break;
			if (entry->trigger.read & TRIGGER_READ_PMU_BRANCH)
				if (prepare_pmu_event(EVENT_ID_READ_PMU_BRANCH) < 0)
					break;
		}

		node = rb_next(node);
	}
}

static void mcount_filter_init(enum uftrace_pattern_type ptype)
{
	char *filter_str    = getenv("UFTRACE_FILTER");
	char *trigger_str   = getenv("UFTRACE_TRIGGER");
	char *argument_str  = getenv("UFTRACE_ARGUMENT");
	char *retval_str    = getenv("UFTRACE_RETVAL");
	char *autoargs_str  = getenv("UFTRACE_AUTO_ARGS");

	load_module_symtabs(&symtabs);

	/* setup auto-args only if argument/return value is used */
	if (argument_str || retval_str || autoargs_str ||
	    (trigger_str && (strstr(trigger_str, "arg") ||
			     strstr(trigger_str, "retval"))))
		setup_auto_args();

	uftrace_setup_filter(filter_str, &symtabs, &mcount_triggers,
			     &mcount_filter_mode, false, ptype);
	uftrace_setup_trigger(trigger_str, &symtabs, &mcount_triggers,
			      &mcount_filter_mode, false, ptype);
	uftrace_setup_argument(argument_str, &symtabs, &mcount_triggers,
			       false, ptype);
	uftrace_setup_retval(retval_str, &symtabs, &mcount_triggers,
			     false, ptype);

	if (autoargs_str) {
		uftrace_setup_argument(get_auto_argspec_str(), &symtabs,
				       &mcount_triggers, true, ptype);
		uftrace_setup_retval(get_auto_retspec_str(), &symtabs,
				     &mcount_triggers, true, ptype);
	}

	if (getenv("UFTRACE_DEPTH"))
		mcount_depth = strtol(getenv("UFTRACE_DEPTH"), NULL, 0);

	if (getenv("UFTRACE_DISABLED"))
		mcount_enabled = false;

	prepare_pmu_trigger(&mcount_triggers);
}

static void mcount_filter_setup(struct mcount_thread_data *mtdp)
{
	mtdp->filter.depth  = mcount_depth;
	mtdp->filter.time   = mcount_threshold;
	mtdp->enable_cached = mcount_enabled;
	mtdp->argbuf        = xmalloc(mcount_rstack_max * ARGBUF_SIZE);
}

static void mcount_filter_release(struct mcount_thread_data *mtdp)
{
	free(mtdp->argbuf);
	mtdp->argbuf = NULL;
}
#endif /* DISABLE_MCOUNT_FILTER */

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
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = &sess, .iov_len = sizeof(sess), },
		{ .iov_base = mcount_exename, .iov_len = sess.namelen, },
	};
	int len = sizeof(msg) + msg.len;

	if (pfd < 0)
		return;

	mcount_memcpy4(sess.sid, sess_id, sizeof(sess.sid));

	if (writev(pfd, iov, 3) != len) {
		if (!mcount_should_stop())
			pr_err("write tid info failed");
	}
}

/* to be used by pthread_create_key() */
static void mtd_dtor(void *arg)
{
	struct mcount_thread_data *mtdp = arg;
	struct uftrace_msg_task tmsg;

	/* this thread is done, do not enter anymore */
	mtdp->recursion_guard = true;

	free(mtdp->rstack);
	mtdp->rstack = NULL;

	mcount_filter_release(mtdp);
	shmem_finish(mtdp);

	tmsg.pid = getpid(),
	tmsg.tid = mcount_gettid(mtdp),
	tmsg.time = mcount_gettime();

	/* dtor for script support */
	if (SCRIPT_ENABLED && script_str)
		script_uftrace_end();

	uftrace_send_message(UFTRACE_MSG_TASK_END, &tmsg, sizeof(tmsg));
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

	/* set line buffer mode not to discard crash message */
	setlinebuf(outfp);

	for (idx = 0; idx < (int)ARRAY_SIZE(sigsegv_codes); idx++) {
		if (sig != SIGSEGV)
			break;

		if (si->si_code == sigsegv_codes[idx].code) {
			pr_red("Segmentation fault: %s (addr: %p)\n",
			       sigsegv_codes[idx].msg, si->si_addr);
			break;
		}
	}
	if (sig != SIGSEGV || idx == (int)ARRAY_SIZE(sigsegv_codes)) {
		pr_red("process crashed by signal %d: %s (si_code: %d)\n",
		       sig, strsignal(sig), si->si_code);
	}

	mtdp = get_thread_data();
	if (check_thread_data(mtdp))
		goto out;

	mcount_rstack_restore(mtdp);

	idx = mtdp->idx - 1;
	/* flush current rstack on crash */
	rstack = &mtdp->rstack[idx];
	record_trace_data(mtdp, rstack, NULL);

	if (dbg_domain[PR_DOMAIN]) {
		pr_red("Backtrace from uftrace:\n");
		pr_red("=====================================\n");

		while (rstack >= mtdp->rstack) {
			struct sym *parent, *child;
			char *pname, *cname;

			parent = find_symtabs(&symtabs, rstack->parent_ip);
			pname = symbol_getname(parent, rstack->parent_ip);
			child  = find_symtabs(&symtabs, rstack->child_ip);
			cname = symbol_getname(child, rstack->child_ip);

			pr_red("[%d] (%s[%lx] <= %s[%lx])\n", idx--,
			       cname, rstack->child_ip, pname, rstack->parent_ip);

			symbol_putname(parent, pname);
			symbol_putname(child, cname);

			rstack--;
		}
	}

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
	pr_dbg("new session started: %.*s: %s\n",
	       SESSION_ID_LEN, mcount_session_name(), basename(mcount_exename));

	sigemptyset(&sa.sa_mask);
	sigaction(SIGABRT, &sa, &old_sigact[0]);
	sigaction(SIGSEGV, &sa, &old_sigact[1]);
}

struct mcount_thread_data * mcount_prepare(void)
{
	static pthread_once_t once_control = PTHREAD_ONCE_INIT;
	struct mcount_thread_data *mtdp = &mtd;
	struct uftrace_msg_task tmsg;

	/*
	 * If an executable implements its own malloc(),
	 * following recursion could occur
	 *
	 * mcount_entry -> mcount_prepare -> xmalloc -> mcount_entry -> ...
	 */
	if (mtdp->recursion_guard)
		return NULL;

	mtdp->recursion_guard = true;
	compiler_barrier();

	mcount_filter_setup(mtdp);
	mtdp->rstack = xmalloc(mcount_rstack_max * sizeof(*mtd.rstack));

	pthread_once(&once_control, mcount_init_file);
	prepare_shmem_buffer(mtdp);

	pthread_setspecific(mtd_key, mtdp);

	/* time should be get after session message sent */
	tmsg.pid = getpid(),
	tmsg.tid = mcount_gettid(mtdp),
	tmsg.time = mcount_gettime();

	uftrace_send_message(UFTRACE_MSG_TASK_START, &tmsg, sizeof(tmsg));

	update_kernel_tid(tmsg.tid);

	return mtdp;
}

static void mcount_finish(void)
{
	if (mcount_global_flags & MCOUNT_GFL_FINISH)
		return;

	mcount_global_flags |= MCOUNT_GFL_FINISH;
	mtd_dtor(&mtd);

	__sync_synchronize();

	pthread_key_delete(mtd_key);
	if (pfd != -1) {
		close(pfd);
		pfd = -1;
	}

	finish_auto_args();
}

static bool mcount_check_rstack(struct mcount_thread_data *mtdp)
{
	if (mtdp->idx >= mcount_rstack_max) {
		static bool warned = false;

		if (!warned) {
			pr_warn("too deeply nested calls: %d\n", mtdp->idx);
			warned = true;
		}
		return true;
	}
	return false;
}

#ifndef DISABLE_MCOUNT_FILTER
extern void * get_argbuf(struct mcount_thread_data *, struct mcount_ret_stack *);

/* update filter state from trigger result */
enum filter_result mcount_entry_filter_check(struct mcount_thread_data *mtdp,
					     unsigned long child,
					     struct uftrace_trigger *tr)
{
	pr_dbg3("<%d> enter %lx\n", mtdp->idx, child);

	if (mcount_check_rstack(mtdp))
		return FILTER_RSTACK;

	/* save original depth and time to restore at exit time */
	mtdp->filter.saved_depth = mtdp->filter.depth;
	mtdp->filter.saved_time  = mtdp->filter.time;

	/* already filtered by notrace option */
	if (mtdp->filter.out_count > 0)
		return FILTER_OUT;

	uftrace_match_filter(child, &mcount_triggers, tr);

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

#define FLAGS_TO_CHECK  (TRIGGER_FL_DEPTH | TRIGGER_FL_TRACE_ON |	\
			 TRIGGER_FL_TRACE_OFF | TRIGGER_FL_TIME_FILTER)

	if (tr->flags & FLAGS_TO_CHECK) {
		if (tr->flags & TRIGGER_FL_DEPTH)
			mtdp->filter.depth = tr->depth;

		if (tr->flags & TRIGGER_FL_TRACE_ON)
			mcount_enabled = true;

		if (tr->flags & TRIGGER_FL_TRACE_OFF)
			mcount_enabled = false;

		if (tr->flags & TRIGGER_FL_TIME_FILTER)
			mtdp->filter.time = tr->time;
	}

#undef FLAGS_TO_CHECK

	if (mtdp->filter.depth <= 0)
		return FILTER_OUT;

	mtdp->filter.depth--;
	return FILTER_IN;
}

static int script_save_context(struct script_context *sc_ctx,
			       struct mcount_thread_data *mtdp,
			       struct mcount_ret_stack *rstack,
			       char *symname, bool has_arg_retval,
			       struct list_head *pargs)
{
	if (!script_match_filter(symname))
		return -1;

	sc_ctx->tid       = mcount_gettid(mtdp);
	sc_ctx->depth     = rstack->depth;
	sc_ctx->address   = rstack->child_ip;
	sc_ctx->name      = symname;
	sc_ctx->timestamp = rstack->start_time;
	if (rstack->end_time)
		sc_ctx->duration = rstack->end_time - rstack->start_time;

	if (has_arg_retval) {
		unsigned *argbuf = get_argbuf(mtdp, rstack);

		sc_ctx->arglen  = argbuf[0];
		sc_ctx->argbuf  = &argbuf[1];
		sc_ctx->argspec = pargs;
	}
	else {
		/* prevent access to arguments */
		sc_ctx->arglen  = 0;
	}

	return 0;
}

static void script_hook_entry(struct mcount_thread_data *mtdp,
			      struct mcount_ret_stack *rstack,
			      struct uftrace_trigger *tr)
{
	struct script_context sc_ctx;
	unsigned long entry_addr = rstack->child_ip;
	struct sym *sym = find_symtabs(&symtabs, entry_addr);
	char *symname = symbol_getname(sym, entry_addr);

	if (script_save_context(&sc_ctx, mtdp, rstack, symname,
				tr->flags & TRIGGER_FL_ARGUMENT,
				tr->pargs) < 0)
		goto skip;

	/* accessing argument in script might change arch-context */
	mcount_save_arch_context(&mtdp->arch);
	script_uftrace_entry(&sc_ctx);
	mcount_restore_arch_context(&mtdp->arch);

skip:
	symbol_putname(sym, symname);
}

static void script_hook_exit(struct mcount_thread_data *mtdp,
			     struct mcount_ret_stack *rstack)
{
	struct script_context sc_ctx;
	unsigned long entry_addr = rstack->child_ip;
	struct sym *sym = find_symtabs(&symtabs, entry_addr);
	char *symname = symbol_getname(sym, entry_addr);

	if (script_save_context(&sc_ctx, mtdp, rstack, symname,
				rstack->flags & MCOUNT_FL_RETVAL,
				rstack->pargs) < 0)
		goto skip;

	/* accessing argument in script might change arch-context */
	mcount_save_arch_context(&mtdp->arch);
	script_uftrace_exit(&sc_ctx);
	mcount_restore_arch_context(&mtdp->arch);

skip:
	symbol_putname(sym, symname);
}

/* save current filter state to rstack */
void mcount_entry_filter_record(struct mcount_thread_data *mtdp,
				struct mcount_ret_stack *rstack,
				struct uftrace_trigger *tr,
				struct mcount_regs *regs)
{
	if (mtdp->filter.out_count > 0 ||
	    (mtdp->filter.in_count == 0 && mcount_filter_mode == FILTER_MODE_IN))
		rstack->flags |= MCOUNT_FL_NORECORD;

	rstack->filter_depth = mtdp->filter.saved_depth;
	rstack->filter_time  = mtdp->filter.saved_time;

#define FLAGS_TO_CHECK  (TRIGGER_FL_FILTER | TRIGGER_FL_RETVAL |	\
			 TRIGGER_FL_TRACE | TRIGGER_FL_FINISH)

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

		if (tr->flags & TRIGGER_FL_FINISH) {
			record_trace_data(mtdp, rstack, NULL);
			uftrace_send_message(UFTRACE_MSG_FINISH, NULL, 0);
			mcount_finish();
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
			 * using the MCOUNT_FL_DISALBED flag.
			 */
			if (unlikely(mtdp->enable_cached))
				record_trace_data(mtdp, rstack, NULL);
		}
		else {
			if (tr->flags & TRIGGER_FL_ARGUMENT)
				save_argument(mtdp, rstack, tr->pargs, regs);
			if (tr->flags & TRIGGER_FL_READ) {
				save_trigger_read(mtdp, rstack, tr->read, false);
				rstack->flags |= MCOUNT_FL_READ;
			}

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
			script_hook_entry(mtdp, rstack, tr);

#define FLAGS_TO_CHECK  (TRIGGER_FL_RECOVER | TRIGGER_FL_TRACE_ON | TRIGGER_FL_TRACE_OFF)

		if (tr->flags & FLAGS_TO_CHECK) {
			if (tr->flags & TRIGGER_FL_RECOVER) {
				mcount_rstack_restore(mtdp);
				*rstack->parent_loc = (unsigned long) mcount_return;
				rstack->flags |= MCOUNT_FL_RECOVER;
			}
			if (tr->flags & (TRIGGER_FL_TRACE_ON | TRIGGER_FL_TRACE_OFF))
				mtdp->enable_cached = mcount_enabled;
		}
	}

#undef FLAGS_TO_CHECK

}

/* restore filter state from rstack */
void mcount_exit_filter_record(struct mcount_thread_data *mtdp,
			       struct mcount_ret_stack *rstack,
			       long *retval)
{
	uint64_t time_filter = mtdp->filter.time;

	pr_dbg3("<%d> exit  %lx\n", mtdp->idx, rstack->child_ip);

#define FLAGS_TO_CHECK  (MCOUNT_FL_FILTERED | MCOUNT_FL_NOTRACE | MCOUNT_FL_RECOVER)

	if (rstack->flags & FLAGS_TO_CHECK) {
		if (rstack->flags & MCOUNT_FL_FILTERED)
			mtdp->filter.in_count--;
		else if (rstack->flags & MCOUNT_FL_NOTRACE)
			mtdp->filter.out_count--;

		if (rstack->flags & MCOUNT_FL_RECOVER)
			mcount_rstack_reset(mtdp);
	}

#undef FLAGS_TO_CHECK

	mtdp->filter.depth = rstack->filter_depth;
	mtdp->filter.time  = rstack->filter_time;

	if (!(rstack->flags & MCOUNT_FL_NORECORD)) {
		if (mtdp->record_idx > 0)
			mtdp->record_idx--;

		if (!mcount_enabled)
			return;

		if (!(rstack->flags & MCOUNT_FL_RETVAL))
			retval = NULL;

		if (rstack->flags & MCOUNT_FL_READ) {
			struct uftrace_trigger tr;

			/* there's a possibility of overwriting by return value */
			uftrace_match_filter(rstack->child_ip, &mcount_triggers, &tr);
			save_trigger_read(mtdp, rstack, tr.read, true);
		}

		if (rstack->end_time - rstack->start_time > time_filter ||
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
				mtdp->nr_events = k;  /* invalidate sync events */
		}

		/* script hooking for function exit */
		if (SCRIPT_ENABLED && script_str)
			script_hook_exit(mtdp, rstack);
	}
}

#else /* DISABLE_MCOUNT_FILTER */
enum filter_result mcount_entry_filter_check(struct mcount_thread_data *mtdp,
					     unsigned long child,
					     struct uftrace_trigger *tr)
{
	if (mcount_check_rstack(mtdp))
		return FILTER_RSTACK;

	return FILTER_IN;
}

void mcount_entry_filter_record(struct mcount_thread_data *mtdp,
				struct mcount_ret_stack *rstack,
				struct uftrace_trigger *tr,
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

#ifndef FIX_PARENT_LOC
static inline unsigned long *
mcount_arch_parent_location(struct symtabs *symtabs, unsigned long *parent_loc,
			    unsigned long child_ip)
{
	return parent_loc;
}
#endif

int mcount_entry(unsigned long *parent_loc, unsigned long child,
		 struct mcount_regs *regs)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	struct uftrace_trigger tr;

	if (unlikely(mcount_should_stop()))
		return -1;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return -1;
	}
	else {
		if (unlikely(mtdp->recursion_guard))
			return -1;

		mtdp->recursion_guard = true;
	}

	tr.flags = 0;
	filtered = mcount_entry_filter_check(mtdp, child, &tr);
	if (filtered != FILTER_IN) {
		mtdp->recursion_guard = false;
		return -1;
	}

	if (unlikely(mtdp->in_exception)) {
		unsigned long frame_addr;

		/* same as __builtin_frame_addr(2) but avoid warning */
		frame_addr = parent_loc[-1];

		/* basic sanity check */
		if (frame_addr < (unsigned long)parent_loc)
			frame_addr = (unsigned long)(parent_loc - 1);

		mcount_rstack_reset_exception(mtdp, frame_addr);
		mtdp->in_exception = false;
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
	rstack->nr_events  = 0;
	rstack->event_idx  = ARGBUF_SIZE;

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
	if (unlikely(check_thread_data(mtdp))) {
		/* mcount_finish() called in the middle */
		if (mcount_should_stop())
			return mtd.rstack[--mtd.idx].parent_ip;

		assert(mtdp);
	}

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

static int cygprof_entry(unsigned long parent, unsigned long child)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	struct uftrace_trigger tr = {
		.flags = 0,
	};

	if (unlikely(mcount_should_stop()))
		return -1;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return -1;
	}
	else {
		if (unlikely(mtdp->recursion_guard))
			return -1;

		mtdp->recursion_guard = true;
	}

	filtered = mcount_entry_filter_check(mtdp, child, &tr);

	if (unlikely(mtdp->in_exception)) {
		unsigned long *frame_ptr;
		unsigned long frame_addr;

		frame_ptr = __builtin_frame_address(0);
		frame_addr = *frame_ptr;  /* XXX: probably dangerous */

		/* basic sanity check */
		if (frame_addr < (unsigned long)frame_ptr)
			frame_addr = (unsigned long)frame_ptr;

		mcount_rstack_reset_exception(mtdp, frame_addr);
		mtdp->in_exception = false;
	}

	/* 
	 * recording arguments and return value is not supported.
	 * also 'recover' trigger is only work for -pg entry.
	 */
	tr.flags &= ~(TRIGGER_FL_ARGUMENT | TRIGGER_FL_RETVAL | TRIGGER_FL_RECOVER);

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
	rstack->parent_loc = &mtdp->cygprof_dummy;
	rstack->parent_ip  = parent;
	rstack->child_ip   = child;
	rstack->end_time   = 0;
	rstack->nr_events  = 0;
	rstack->event_idx  = ARGBUF_SIZE;

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

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp) || mtdp->recursion_guard))
		return;

	mtdp->recursion_guard = true;

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

void xray_entry(unsigned long parent, unsigned long child,
		struct mcount_regs *regs)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	struct uftrace_trigger tr = {
		.flags = 0,
	};

	if (unlikely(mcount_should_stop()))
		return;

	/* Access the mtd through TSD pointer to reduce TLS overhead */
	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mcount_prepare();

		mtdp = get_thread_data();
		assert(mtdp);
	}
	else {
		if (unlikely(mtdp->recursion_guard))
			return;

		mtdp->recursion_guard = true;
	}

	filtered = mcount_entry_filter_check(mtdp, child, &tr);

	if (unlikely(mtdp->in_exception)) {
		unsigned long *frame_ptr;
		unsigned long frame_addr;

		frame_ptr = __builtin_frame_address(0);
		frame_addr = *frame_ptr;  /* XXX: probably dangerous */

		/* basic sanity check */
		if (frame_addr < (unsigned long)frame_ptr)
			frame_addr = (unsigned long)frame_ptr;

		mcount_rstack_reset_exception(mtdp, frame_addr);
		mtdp->in_exception = false;
	}

	/* 'recover' trigger is only for -pg entry */
	tr.flags &= ~TRIGGER_FL_RECOVER;

	rstack = &mtdp->rstack[mtdp->idx++];

	rstack->depth      = mtdp->record_idx;
	rstack->dyn_idx    = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = &mtdp->cygprof_dummy;
	rstack->parent_ip  = parent;
	rstack->child_ip   = child;
	rstack->end_time   = 0;
	rstack->nr_events  = 0;
	rstack->event_idx  = ARGBUF_SIZE;

	if (filtered == FILTER_IN) {
		rstack->start_time = mcount_gettime();
		rstack->flags      = 0;
	}
	else {
		rstack->start_time = 0;
		rstack->flags      = MCOUNT_FL_NORECORD;
	}

	mcount_entry_filter_record(mtdp, rstack, &tr, regs);
	mtdp->recursion_guard = false;
}

void xray_exit(long *retval)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;

	if (unlikely(mcount_should_stop()))
		return;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp) || mtdp->recursion_guard))
		return;

	mtdp->recursion_guard = true;

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

	mcount_exit_filter_record(mtdp, rstack, retval);

	compiler_barrier();

out:
	mtdp->idx--;
	mtdp->recursion_guard = false;
}

/* save an asynchronous event */
int mcount_save_event(struct mcount_event_info *mei)
{
	struct mcount_thread_data *mtdp;

	if (unlikely(mcount_should_stop()))
		return -1;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return -1;

	if (mtdp->nr_events < MAX_EVENT) {
		int i = mtdp->nr_events++;

		mtdp->event[i].id   = mei->id;
		mtdp->event[i].time = mcount_gettime();
		mtdp->event[i].dsize = 0;
		mtdp->event[i].idx   = ASYNC_IDX;
	}

	return 0;
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
}

static void atfork_child_handler(void)
{
	struct mcount_thread_data *mtdp;
	struct uftrace_msg_task tmsg = {
		.time = mcount_gettime(),
		.pid = getppid(),
		.tid = getpid(),
	};

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		/* we need it even if in a recursion */
		mtd.recursion_guard = false;

		mtdp = mcount_prepare();
	}

	/* update tid cache */
	mtdp->tid = tmsg.tid;
	/* flush event data */
	mtdp->nr_events = 0;

	mtdp->recursion_guard = true;

	clear_shmem_buffer(mtdp);
	prepare_shmem_buffer(mtdp);

	uftrace_send_message(UFTRACE_MSG_FORK_END, &tmsg, sizeof(tmsg));

	update_kernel_tid(tmsg.tid);

	mtdp->recursion_guard = false;
}

static void mcount_startup(void)
{
	char *pipefd_str;
	char *logfd_str;
	char *debug_str;
	char *bufsize_str;
	char *maxstack_str;
	char *threshold_str;
	char *color_str;
	char *demangle_str;
	char *plthook_str;
	char *patch_str;
	char *event_str;
	char *dirname;
	char *pattern_str;
	struct stat statbuf;
	bool nest_libcall;
	enum uftrace_pattern_type patt_type = PATT_REGEX;

	if (!(mcount_global_flags & MCOUNT_GFL_SETUP) || mtd.recursion_guard)
		return;

	mtd.recursion_guard = true;

	outfp = stdout;
	logfp = stderr;

	if (pthread_key_create(&mtd_key, mtd_dtor))
		pr_err("cannot create mtd key");

	pipefd_str = getenv("UFTRACE_PIPE");
	logfd_str = getenv("UFTRACE_LOGFD");
	debug_str = getenv("UFTRACE_DEBUG");
	bufsize_str = getenv("UFTRACE_BUFFER");
	maxstack_str = getenv("UFTRACE_MAX_STACK");
	color_str = getenv("UFTRACE_COLOR");
	threshold_str = getenv("UFTRACE_THRESHOLD");
	demangle_str = getenv("UFTRACE_DEMANGLE");
	plthook_str = getenv("UFTRACE_PLTHOOK");
	patch_str = getenv("UFTRACE_PATCH");
	event_str = getenv("UFTRACE_EVENT");
	script_str = getenv("UFTRACE_SCRIPT");
	nest_libcall = !!getenv("UFTRACE_NEST_LIBCALL");
	pattern_str = getenv("UFTRACE_PATTERN");

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
		setup_color(strtol(color_str, NULL, 0));
	else
		setup_color(COLOR_AUTO);

	pr_dbg("initializing mcount library\n");

	if (pipefd_str) {
		pfd = strtol(pipefd_str, NULL, 0);

		/* minimal sanity check */
		if (fstat(pfd, &statbuf) < 0 || !S_ISFIFO(statbuf.st_mode)) {
			pr_dbg("ignore invalid pipe fd: %d\n", pfd);
			pfd = -1;
		}
	}

	if (getenv("UFTRACE_LIST_EVENT")) {
		mcount_list_events();
		exit(0);
	}

	if (bufsize_str)
		shmem_bufsize = strtol(bufsize_str, NULL, 0);

	dirname = getenv("UFTRACE_DIR");
	if (dirname == NULL)
		dirname = UFTRACE_DIR_NAME;

	symtabs.dirname = dirname;

	mcount_exename = read_exename();
	record_proc_maps(dirname, mcount_session_name(), &symtabs);
	set_kernel_base(&symtabs, mcount_session_name());
	load_symtabs(&symtabs, NULL, mcount_exename);

	if (pattern_str)
		patt_type = parse_filter_pattern(pattern_str);

	mcount_filter_init(patt_type);

	if (maxstack_str)
		mcount_rstack_max = strtol(maxstack_str, NULL, 0);

	if (threshold_str)
		mcount_threshold = strtoull(threshold_str, NULL, 0);

	if (patch_str)
		mcount_dynamic_update(&symtabs, patch_str, patt_type);

	if (event_str)
		mcount_setup_events(dirname, event_str, patt_type);

	if (plthook_str)
		mcount_setup_plthook(mcount_exename, nest_libcall);

	if (getenv("UFTRACE_KERNEL_PID_UPDATE"))
		kernel_pid_update = true;

	pthread_atfork(atfork_prepare_handler, NULL, atfork_child_handler);

	mcount_hook_functions();

	/* initialize script binding */
	if (SCRIPT_ENABLED && script_str)
		if (script_init(script_str, patt_type) < 0)
			script_str = NULL;

	compiler_barrier();
	pr_dbg("mcount setup done\n");

	mcount_global_flags &= ~MCOUNT_GFL_SETUP;
	mtd.recursion_guard = false;
}

static void mcount_cleanup(void)
{
	mcount_finish();
	destroy_dynsym_indexes();

#ifndef DISABLE_MCOUNT_FILTER
	uftrace_cleanup_filter(&mcount_triggers);
#endif
	if (SCRIPT_ENABLED && script_str)
		script_finish();

	unload_symtabs(&symtabs);
	finish_pmu_event();

	pr_dbg("exit from libmcount\n");
}

/*
 * external interfaces
 */
#define UFTRACE_ALIAS(_func) void uftrace_##_func(void) __alias(_func)

void __visible_default __monstartup(unsigned long low, unsigned long high)
{
}

void __visible_default _mcleanup(void)
{
}

void __visible_default mcount_restore(void)
{
	struct mcount_thread_data *mtdp;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	mcount_rstack_restore(mtdp);
}

void __visible_default mcount_reset(void)
{
	struct mcount_thread_data *mtdp;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	mcount_rstack_reset(mtdp);
}

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

#ifndef UNIT_TEST
/*
 * Initializer and Finalizer
 */
static void __attribute__((constructor))
mcount_init(void)
{
	mcount_startup();
}

static void __attribute__((destructor))
mcount_fini(void)
{
	mcount_cleanup();
}
#else  /* UNIT_TEST */

static void setup_mcount_test(void)
{
	mcount_exename = read_exename();

	pthread_key_create(&mtd_key, mtd_dtor);
}

static void finish_mcount_test(void)
{
	pthread_key_delete(mtd_key);
}

TEST_CASE(mcount_thread_data)
{
	struct mcount_thread_data *mtdp;

	setup_mcount_test();

	mtdp = get_thread_data();
	TEST_EQ(check_thread_data(mtdp), true);

	mtdp = mcount_prepare();
	TEST_EQ(check_thread_data(mtdp), false);

	TEST_EQ(get_thread_data(), mtdp);

	TEST_EQ(check_thread_data(mtdp), false);

	return TEST_OK;
}

#endif /* UNIT_TEST */
