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
#include <dlfcn.h>
#include <link.h>

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
	.flags = SYMTAB_FL_DEMANGLE | SYMTAB_FL_ADJ_OFFSET |
		 SYMTAB_FL_SKIP_NORMAL | SYMTAB_FL_SKIP_DYNAMIC,
};
int shmem_bufsize = SHMEM_BUFFER_SIZE;
bool mcount_setup_done;
bool mcount_finished;

pthread_key_t mtd_key = (pthread_key_t)-1;
TLS struct mcount_thread_data mtd;

static int pfd = -1;
static int mcount_rstack_max = MCOUNT_RSTACK_MAX;
static char *mcount_exename;
static bool kernel_pid_update;

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
	return (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

int gettid(struct mcount_thread_data *mtdp)
{
	if (!mtdp->tid)
		mtdp->tid = syscall(SYS_gettid);

	return mtdp->tid;
}

/* kernel never updates pid filter for a forked child */
static void update_kernel_tid(int tid)
{
	static const char *TRACING_DIR = "/sys/kernel/debug/tracing";
	char *filename = NULL;
	char buf[8];
	int fd;
	ssize_t len;

	xasprintf(&filename, "%s/set_ftrace_pid", TRACING_DIR);
	fd = open(filename, O_WRONLY | O_APPEND);
	if (fd < 0)
		return;

	snprintf(buf, sizeof(buf), "%d", tid);
	len = strlen(buf);
	if (write(fd, buf, len) != len)
		pr_dbg("update kernel ftrace tid filter failed\n");

	close(fd);

	free(filename);
}

const char *session_name(void)
{
	static char session[SESSION_ID_LEN + 1];
	static uint64_t session_id;
	int fd;

	if (!session_id) {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0)
			pr_err("cannot open urandom file");

		if (read(fd, &session_id, sizeof(session_id)) != 8)
			pr_err("reading from urandom");

		close(fd);

		snprintf(session, sizeof(session), "%0*"PRIx64,
			 SESSION_ID_LEN, session_id);
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

static void send_dlopen_msg(struct mcount_thread_data *mtdp, const char *sess_id,
			    uint64_t timestamp,  uint64_t base_addr,
			    const char *libname)
{
	struct ftrace_msg_dlopen dlop = {
		.task = {
			.time = timestamp,
			.pid = getpid(),
			.tid = gettid(mtdp),
		},
		.base_addr = base_addr,
		.namelen = strlen(libname),
	};
	struct ftrace_msg msg = {
		.magic = FTRACE_MSG_MAGIC,
		.type = FTRACE_MSG_DLOPEN,
		.len = sizeof(dlop) + dlop.namelen,
	};
	struct iovec iov[3] = {
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = &dlop, .iov_len = sizeof(dlop), },
		{ .iov_base = (void *)libname, .iov_len = dlop.namelen, },
	};
	int len = sizeof(msg) + msg.len;

	if (pfd < 0)
		return;

	memcpy(dlop.sid, sess_id, sizeof(dlop.sid));

	if (writev(pfd, iov, 3) != len)
		pr_err("write tid info failed");
}

/* to be used by pthread_create_key() */
static void mtd_dtor(void *arg)
{
	struct mcount_thread_data *mtdp = arg;

	/* this thread is done, do not enter anymore */
	mtdp->recursion_guard = true;

	free(mtdp->rstack);
	mtdp->rstack = NULL;

#ifndef DISABLE_MCOUNT_FILTER
	free(mtdp->argbuf);
	mtdp->argbuf = NULL;
#endif
	shmem_finish(mtdp);
}

static void mcount_init_file(void)
{
	send_session_msg(&mtd, session_name());
}

struct mcount_thread_data * mcount_prepare(void)
{
	static pthread_once_t once_control = PTHREAD_ONCE_INIT;
	struct mcount_thread_data *mtdp = &mtd;
	struct ftrace_msg_task tmsg;

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

#ifndef DISABLE_MCOUNT_FILTER
	mtdp->filter.depth  = mcount_depth;
	mtdp->filter.time   = mcount_threshold;
	mtdp->enable_cached = mcount_enabled;
	mtdp->argbuf = xmalloc(mcount_rstack_max * ARGBUF_SIZE);
#endif
	mtdp->rstack = xmalloc(mcount_rstack_max * sizeof(*mtd.rstack));

	pthread_once(&once_control, mcount_init_file);
	prepare_shmem_buffer(mtdp);

	pthread_setspecific(mtd_key, mtdp);

	/* time should be get after session message sent */
	tmsg.pid = getpid(),
	tmsg.tid = gettid(mtdp),
	tmsg.time = mcount_gettime();

	ftrace_send_message(FTRACE_MSG_TID, &tmsg, sizeof(tmsg));

	if (kernel_pid_update)
		update_kernel_tid(gettid(mtdp));

	return mtdp;
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
	rstack->filter_time  = mtdp->filter.saved_time;

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
			mcount_rstack_restore();
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
	uint64_t time_filter = mtdp->filter.time;

	pr_dbg3("<%d> exit  %lx\n", mtdp->idx, rstack->child_ip);

#define FLAGS_TO_CHECK  (MCOUNT_FL_FILTERED | MCOUNT_FL_NOTRACE | MCOUNT_FL_RECOVER)

	if (rstack->flags & FLAGS_TO_CHECK) {
		if (rstack->flags & MCOUNT_FL_FILTERED)
			mtdp->filter.in_count--;
		else if (rstack->flags & MCOUNT_FL_NOTRACE)
			mtdp->filter.out_count--;

		if (rstack->flags & MCOUNT_FL_RECOVER)
			mcount_rstack_reset();
	}

#undef FLAGS_TO_CHECK

	mtdp->filter.depth = rstack->filter_depth;
	mtdp->filter.time  = rstack->filter_time;

	if (!(rstack->flags & MCOUNT_FL_NORECORD)) {
		if (mtdp->record_idx > 0)
			mtdp->record_idx--;

		if (!(rstack->flags & MCOUNT_FL_RETVAL))
			retval = NULL;

		if (rstack->end_time - rstack->start_time > time_filter ||
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
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return;
	}
	else {
		if (unlikely(mtdp->recursion_guard))
			return;

		mtdp->recursion_guard = true;
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

void xray_entry(unsigned long parent, unsigned long child,
		struct mcount_regs *regs)
{
	enum filter_result filtered;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	struct ftrace_trigger tr = {
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

	/* 'recover' trigger is only for -pg entry */
	tr.flags &= ~TRIGGER_FL_RECOVER;

	rstack = &mtdp->rstack[mtdp->idx++];

	rstack->depth      = mtdp->record_idx;
	rstack->dyn_idx    = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = &mtdp->cygprof_dummy;
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

	mcount_entry_filter_record(mtdp, rstack, &tr, regs);
	mtdp->recursion_guard = false;
}

void xray_exit(long *retval)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;

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
		/* we need it even if in a recursion */
		mtd.recursion_guard = false;

		mtdp = mcount_prepare();
	}

	/* flush tid cache */
	mtdp->tid = 0;

	mtdp->recursion_guard = true;

	clear_shmem_buffer(mtdp);
	prepare_shmem_buffer(mtdp);

	ftrace_send_message(FTRACE_MSG_FORK_END, &tmsg, sizeof(tmsg));

	mtdp->recursion_guard = false;
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

struct dlopen_base_data {
	const char *libname;
	unsigned long base_addr;
};

static const char *simple_basename(const char *pathname)
{
	const char *p = strrchr(pathname, '/');

	return p ? p + 1 : pathname;
}

static int dlopen_base_callback(struct dl_phdr_info *info,
				size_t size, void *arg)
{
	struct dlopen_base_data *data = arg;

	if (!strstr(simple_basename(info->dlpi_name), data->libname))
		return 0;

	data->base_addr = info->dlpi_addr;
	data->libname = info->dlpi_name; /* update to use full path */
	return 0;
}

static void (*old_segfault_handler)(int);

static void segfault_handler(int sig)
{
	mcount_rstack_restore();

	signal(sig, old_segfault_handler);
	raise(sig);
}

void mcount_rstack_restore(void)
{
	int idx;
	struct mcount_thread_data *mtdp;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	for (idx = mtdp->idx - 1; idx >= 0; idx--)
		*mtdp->rstack[idx].parent_loc = mtdp->rstack[idx].parent_ip;
}

void mcount_rstack_reset(void)
{
	int idx;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp)))
		return;

	for (idx = mtdp->idx - 1; idx >= 0; idx--) {
		rstack = &mtdp->rstack[idx];

		if (rstack->dyn_idx == MCOUNT_INVALID_DYNIDX)
			*rstack->parent_loc = (unsigned long)mcount_return;
		else
			*rstack->parent_loc = (unsigned long)plthook_return;
	}
}

static void mcount_hook_functions(void);

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
	char *filter_str;
	char *trigger_str;
	char *argument_str;
	char *retval_str;
	char *plthook_str;
	char *patch_str;
	char *dirname;
	struct stat statbuf;
	LIST_HEAD(modules);

	if (mcount_setup_done || mtd.recursion_guard)
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
	filter_str = getenv("UFTRACE_FILTER");
	trigger_str = getenv("UFTRACE_TRIGGER");
	argument_str = getenv("UFTRACE_ARGUMENT");
	retval_str = getenv("UFTRACE_RETVAL");
	plthook_str = getenv("UFTRACE_PLTHOOK");
	patch_str = getenv("UFTRACE_PATCH");

	if (logfd_str) {
		int fd = strtol(logfd_str, NULL, 0);

		/* minimal sanity check */
		if (!fstat(fd, &statbuf)) {
			logfp = fdopen(fd, "a");
			setvbuf(logfp, NULL, _IOLBF, 1024);
		}
	}

	old_segfault_handler = signal(SIGSEGV, segfault_handler);

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

	symtabs.dirname = dirname;

	if (filter_str || trigger_str || argument_str || retval_str || patch_str)
		symtabs.flags &= ~SYMTAB_FL_SKIP_NORMAL;
	if (plthook_str)
		symtabs.flags &= ~SYMTAB_FL_SKIP_DYNAMIC;

	mcount_exename = read_exename();
	record_proc_maps(dirname, session_name(), &symtabs);
	set_kernel_base(&symtabs, session_name());
	load_symtabs(&symtabs, NULL, mcount_exename);

#ifndef DISABLE_MCOUNT_FILTER
	ftrace_setup_filter_module(filter_str, &modules, mcount_exename);
	ftrace_setup_filter_module(trigger_str, &modules, mcount_exename);
	ftrace_setup_filter_module(argument_str, &modules, mcount_exename);
	ftrace_setup_filter_module(retval_str, &modules, mcount_exename);

	load_module_symtabs(&symtabs, &modules);

	ftrace_setup_filter(filter_str, &symtabs, &mcount_triggers,
			    &mcount_filter_mode);
	ftrace_setup_trigger(trigger_str, &symtabs, &mcount_triggers);
	ftrace_setup_argument(argument_str, &symtabs, &mcount_triggers);
	ftrace_setup_retval(retval_str, &symtabs, &mcount_triggers);

	if (getenv("UFTRACE_DEPTH"))
		mcount_depth = strtol(getenv("UFTRACE_DEPTH"), NULL, 0);

	if (getenv("UFTRACE_DISABLED"))
		mcount_enabled = false;
#endif /* DISABLE_MCOUNT_FILTER */

	if (maxstack_str)
		mcount_rstack_max = strtol(maxstack_str, NULL, 0);

	if (threshold_str)
		mcount_threshold = strtoull(threshold_str, NULL, 0);

	if (patch_str)
		mcount_dynamic_update(&symtabs, patch_str);

	if (plthook_str) {
		if (symtabs.dsymtab.nr_sym == 0) {
			pr_dbg("skip PLT hooking due to no dynamic symbols\n");
			goto out;
		}

		setup_dynsym_indexes(&symtabs);

		if (hook_pltgot(mcount_exename, symtabs.maps->start) < 0)
			pr_dbg("error when hooking plt: skipping...\n");
		else
			plthook_setup(&symtabs);
	}

out:
	if (getenv("UFTRACE_KERNEL_PID_UPDATE"))
		kernel_pid_update = true;

	pthread_atfork(atfork_prepare_handler, NULL, atfork_child_handler);

	mcount_hook_functions();

#ifndef DISABLE_MCOUNT_FILTER
	ftrace_cleanup_filter_module(&modules);
#endif /* DISABLE_MCOUNT_FILTER */

	compiler_barrier();
	pr_dbg("mcount setup done\n");

	mcount_setup_done = true;
	mtd.recursion_guard = false;
}

static void mcount_cleanup(void)
{
	mcount_finish();
	destroy_dynsym_indexes();

#ifndef DISABLE_MCOUNT_FILTER
	ftrace_cleanup_filter(&mcount_triggers);
#endif
}

/*
 * hooking functions
 */
static int (*real_backtrace)(void **buffer, int sz);
static void (*real_cxa_throw)(void *exc, void *type, void *dest);
static void (*real_cxa_end_catch)(void);
static void * (*real_dlopen)(const char *filename, int flags);

static void mcount_hook_functions(void)
{
	real_backtrace		= dlsym(RTLD_NEXT, "backtrace");
	real_cxa_throw		= dlsym(RTLD_NEXT, "__cxa_throw");
	real_cxa_end_catch	= dlsym(RTLD_NEXT, "__cxa_end_catch");
	real_dlopen		= dlsym(RTLD_NEXT, "dlopen");
}

__visible_default int backtrace(void **buffer, int sz)
{
	int ret;

	if (real_backtrace == NULL)
		return 0;

	mcount_rstack_restore();
	ret = real_backtrace(buffer, sz);
	mcount_rstack_reset();

	return ret;
}

__visible_default void __cxa_throw(void *exception, void *type, void *dest)
{
	struct mcount_thread_data *mtdp;

	/*
	 * restore return addresses so that it can unwind stack frames
	 * safely during the exception handling.
	 * It pairs to __cxa_end_catch().
	 */
	mcount_rstack_restore();

	mtdp = get_thread_data();
	if (!check_thread_data(mtdp))
		pr_dbg("exception thrown from [%d]\n", mtdp->idx);

	real_cxa_throw(exception, type, dest);
}

__visible_default void __cxa_end_catch(void)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	unsigned long retaddr;

	/* get frame address where exception handler returns */
	retaddr = (unsigned long)__builtin_frame_address(0);

	real_cxa_end_catch();

	pr_dbg("exception returned at frame: %#lx\n", retaddr);

	mcount_rstack_restore();

	mtdp = get_thread_data();
	if (!check_thread_data(mtdp)) {
		int idx;

		/* it needs to find how much stack frame was unwinded */
		for (idx = mtdp->idx - 1; idx >= 0; idx--) {
			rstack = &mtdp->rstack[idx];

			pr_dbg2("[%d] parent at %p\n", idx, rstack->parent_loc);
			if (rstack->parent_loc == &mtdp->cygprof_dummy)
				break;

			if ((unsigned long)rstack->parent_loc > retaddr)
				break;

			/* record unwinded functions */
			if (!(rstack->flags & MCOUNT_FL_NORECORD))
				rstack->end_time = mcount_gettime();

			mcount_exit_filter_record(mtdp, rstack, NULL);
		}

		/* we're in ENTER state, so add 1 to the index */
		mtdp->idx = idx + 1;
		pr_dbg("[%d] exception returned\n", mtdp->idx);

		mcount_rstack_reset();
	}
}

__visible_default void * dlopen(const char *filename, int flags)
{
	struct mcount_thread_data *mtdp;
	uint64_t timestamp = mcount_gettime();
	void *ret = real_dlopen(filename, flags);
	struct dlopen_base_data data = {
		.libname = simple_basename(filename),
	};

	if (unlikely(mcount_should_stop()))
		return ret;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return ret;
	}
	else {
		if (unlikely(mtdp->recursion_guard))
			return ret;

		mtdp->recursion_guard = true;
	}

	dl_iterate_phdr(dlopen_base_callback, &data);

	/*
	 * get timestamp before calling dlopen() so that
	 * it can have symbols in static initializers which
	 * called during the dlopen.
	 */
	send_dlopen_msg(mtdp, session_name(), timestamp,
			data.base_addr, data.libname);

	mtdp->recursion_guard = false;
	return ret;
}

/*
 * external interfaces
 */
void __visible_default __monstartup(unsigned long low, unsigned long high)
{
	mcount_startup();
}

void __visible_default _mcleanup(void)
{
	mcount_cleanup();
}

void __visible_default mcount_restore(void)
{
	mcount_rstack_restore();
}

void __visible_default mcount_reset(void)
{
	mcount_rstack_reset();
}

void __visible_default __cyg_profile_func_enter(void *child, void *parent)
{
	cygprof_entry((unsigned long)parent, (unsigned long)child);
}

void __visible_default __cyg_profile_func_exit(void *child, void *parent)
{
	cygprof_exit((unsigned long)parent, (unsigned long)child);
}

#ifndef UNIT_TEST
/*
 * Initializer and Finalizer
 */
static void __attribute__((constructor))
mcount_init(void)
{
	if (!mcount_setup_done)
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
