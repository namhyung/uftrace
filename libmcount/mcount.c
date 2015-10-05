/*
 * mcount() handling routines for ftrace
 *
 * Copyright (C) 2014-2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <gelf.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT  "mcount"

#include "mcount.h"
#include "../utils/utils.h"
#include "../utils/symbol.h"

#ifdef SINGLE_THREAD
# define TLS
#else
# define TLS  __thread
#endif

/*
 * The mcount_rstack_idx and mcount_record_idx are to save current
 * index of mcount_rstack.  In general, both will have same value but
 * in case of cygprof functions, it may differ if filters applied.
 *
 * This is because how cygprof handles filters - cygprof_exit() should
 * be called for filtered functions while mcount_exit() is not.  The
 * mcount_record_idx is only increased/decreased when the function is
 * not filtered out so that we can keep proper depth in the output.
 */
static TLS int mcount_rstack_idx;
static TLS int mcount_record_idx;
static TLS struct mcount_ret_stack *mcount_rstack;
static int mcount_rstack_max = MCOUNT_RSTACK_MAX;

static int pfd = -1;
static bool mcount_setup_done;

#ifndef DISABLE_MCOUNT_FILTER
static int mcount_depth = MCOUNT_DEFAULT_DEPTH;
static TLS int mcount_rstack_depth;

static struct rb_root filter_trace = RB_ROOT;
static struct rb_root filter_notrace = RB_ROOT;
static struct rb_root filter_plt_trace = RB_ROOT;
static struct rb_root filter_plt_notrace = RB_ROOT;
static bool has_filter, has_notrace;
static bool has_plt_filter, has_plt_notrace;
#endif /* DISABLE_MCOUNT_FILTER */

static TLS bool plthook_recursion_guard;
static unsigned long *plthook_got_ptr;
static unsigned long *plthook_dynsym_addr;
static bool *plthook_dynsym_resolved;
unsigned long plthook_resolver_addr;

static struct symtabs symtabs;
static char mcount_exename[1024];

static uint64_t mcount_gettime(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static TLS int tid;
static int gettid(void)
{
	if (!tid)
		tid = syscall(SYS_gettid);

	return tid;
}

static void read_exename(void)
{
	int len;
	static bool exename_read;

	if (!exename_read) {
		len = readlink("/proc/self/exe", mcount_exename,
			       sizeof(mcount_exename)-1);
		if (len < 0)
			exit(1);
		mcount_exename[len] = '\0';

		exename_read = true;
	}
}

static const char *session_name(void)
{
	static char session[16 + 1];
	static uint64_t session_id;
	int fd;

	if (!session_id) {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0)
			pr_err("open open urandom file");

		if (read(fd, &session_id, sizeof(session_id)) != 8)
			pr_err("reading from urandom");

		close(fd);

		snprintf(session, sizeof(session), "%016"PRIx64, session_id);
	}
	return session;
}

static void ftrace_send_message(int type, void *data, size_t len)
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


#define SHMEM_SESSION_FMT  "/ftrace-%s-%d-%03d" /* session-id, tid, seq */

static pthread_key_t shmem_key;
static TLS int shmem_seqnum;
static TLS struct mcount_shmem_buffer *shmem_buffer[2];
static TLS struct mcount_shmem_buffer *shmem_curr;
static TLS int shmem_losts;
static int shmem_bufsize = SHMEM_BUFFER_SIZE;

static void get_new_shmem_buffer(void)
{
	char buf[128];
	int idx = shmem_seqnum % 2;
	int fd;

	snprintf(buf, sizeof(buf), SHMEM_SESSION_FMT,
		 session_name(), gettid(), idx);

	if (shmem_buffer[idx] == NULL) {
		pr_dbg("opening shmem buffer: %s\n", buf);

		fd = shm_open(buf, O_RDWR | O_CREAT | O_TRUNC, 0600);
		if (fd < 0)
			pr_err("open shmem buffer");

		if (ftruncate(fd, shmem_bufsize) < 0)
			pr_err("resizing shmem buffer");

		shmem_buffer[idx] = mmap(NULL, shmem_bufsize,
					 PROT_READ | PROT_WRITE,
					 MAP_SHARED, fd, 0);
		if (shmem_buffer[idx] == MAP_FAILED)
			pr_err("mmap shmem buffer");

		/* mark it's a new buffer */
		shmem_buffer[idx]->flag |= SHMEM_FL_NEW;

		close(fd);
	} else {
		/*
		 * It's not a new buffer, check ftrace record already
		 * consumed it.
		 */
		if (!(shmem_buffer[idx]->flag & SHMEM_FL_WRITTEN)) {
			shmem_losts++;
			return;
		}

		/*
		 * Start a new buffer and clear the flags.
		 * See record_mmap_file().
		 */
		__sync_fetch_and_and(&shmem_buffer[idx]->flag,
				     ~(SHMEM_FL_NEW | SHMEM_FL_WRITTEN));
	}
	shmem_curr = shmem_buffer[idx];
	shmem_curr->size = 0;

	ftrace_send_message(FTRACE_MSG_REC_START, buf, strlen(buf));
}

static void finish_shmem_buffer(void)
{
	char buf[64];
	int idx = shmem_seqnum % 2;

	if (shmem_curr == NULL)
		return;

	snprintf(buf, sizeof(buf), SHMEM_SESSION_FMT,
		 session_name(), gettid(), idx);

	ftrace_send_message(FTRACE_MSG_REC_END, buf, strlen(buf));

	shmem_curr = NULL;
	shmem_seqnum++;
}

static void clear_shmem_buffer(void)
{
	if (shmem_buffer[0])
		munmap(shmem_buffer[0], shmem_bufsize);
	if (shmem_buffer[1])
		munmap(shmem_buffer[1], shmem_bufsize);

	shmem_buffer[0] = shmem_buffer[1] = NULL;
	shmem_seqnum = 0;
}

/* to be used by pthread_create_key() */
static void shmem_dtor(void *unused)
{
	int seq = shmem_seqnum;

	finish_shmem_buffer();
	/* force update seqnum to call finish on both buffer */
	if (seq == shmem_seqnum)
		shmem_seqnum++;
	finish_shmem_buffer();

	clear_shmem_buffer();
}

static int record_trace_data(struct mcount_ret_stack *mrstack)
{
	struct ftrace_ret_stack *frstack;
	uint64_t timestamp = mrstack->end_time ?: mrstack->start_time;
	size_t size = sizeof(*frstack);

	assert(size < (size_t)shmem_bufsize);

	if (shmem_curr == NULL ||
	    shmem_curr->size + size > shmem_bufsize - sizeof(*shmem_buffer)) {
		finish_shmem_buffer();
		get_new_shmem_buffer();

		if (shmem_curr == NULL)
			return 0;

		if (shmem_losts) {
			frstack = (void *)shmem_curr->data;

			frstack->time = timestamp;
			frstack->type = FTRACE_LOST;
			frstack->unused = FTRACE_UNUSED;
			frstack->addr = shmem_losts;

			ftrace_send_message(FTRACE_MSG_LOST, &shmem_losts,
					    sizeof(shmem_losts));

			size += sizeof(*frstack);
			shmem_curr->size += sizeof(*frstack);
			shmem_losts = 0;
		}
	}

	pr_dbg2("%d recording %zd bytes\n", gettid(), size);

	frstack = (void *)(shmem_curr->data + shmem_curr->size);

	frstack->time = timestamp;
	frstack->type = mrstack->end_time ? FTRACE_EXIT : FTRACE_ENTRY;
	frstack->unused = FTRACE_UNUSED;
	frstack->depth = mrstack->depth;
	frstack->addr = mrstack->child_ip;

	shmem_curr->size += sizeof(*frstack);
	return 0;
}

static void record_proc_maps(char *dirname, const char *sess_id)
{
	int ifd, ofd, len;
	char buf[4096];

	ifd = open("/proc/self/maps", O_RDONLY);
	if (ifd < 0)
		pr_err("cannot open proc maps file");

	snprintf(buf, sizeof(buf), "%s/sid-%s.map", dirname, sess_id);

	ofd = open(buf, O_WRONLY | O_CREAT, 0644);
	if (ofd < 0)
		pr_err("cannot open for writing maps file");

	while ((len = read(ifd, buf, sizeof(buf))) > 0) {
		if (write(ofd, buf, len) != len)
			pr_err("write proc maps failed");
	}

	close(ifd);
	close(ofd);
}

extern void __monstartup(unsigned long low, unsigned long high);

static void send_session_msg(const char *sess_id)
{
	struct ftrace_msg_sess sess = {
		.task = {
			.time = mcount_gettime(),
			.pid = getpid(),
			.tid = gettid(),
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

static void mcount_init_file(void)
{
	char *dirname = getenv("FTRACE_DIR");

	/* This is for the case of library-only tracing */
	if (!mcount_setup_done)
		__monstartup(0, ~0);

	if (pthread_key_create(&shmem_key, shmem_dtor))
		pr_err("cannot create shmem key");

	if (dirname == NULL)
		dirname = FTRACE_DIR_NAME;

	send_session_msg(session_name());
	record_proc_maps(dirname, session_name());
}

static void mcount_prepare(void)
{
	static pthread_once_t once_control = PTHREAD_ONCE_INIT;
	struct ftrace_msg_task tmsg = {
		.pid = getpid(),
		.tid = gettid(),
	};

#ifndef DISABLE_MCOUNT_FILTER
	mcount_rstack_depth = mcount_depth;
#endif
	mcount_rstack = xmalloc(mcount_rstack_max * sizeof(*mcount_rstack));

	pthread_once(&once_control, mcount_init_file);

	/* time should be get after session message sent */
	tmsg.time = mcount_gettime();

	ftrace_send_message(FTRACE_MSG_TID, &tmsg, sizeof(tmsg));
}

enum filter_result {
	FILTER_NOTRACE = -1,
	FILTER_OUT,
	FILTER_IN,
	FILTER_MATCH,
};

#ifndef DISABLE_MCOUNT_FILTER
static enum filter_result mcount_filter(unsigned long ip)
{
	enum filter_result ret = FILTER_IN;

	/*
	 * mcount_rstack_idx > 0 means it's now traced (not filtered)
	 */
	if (mcount_rstack_idx < 0)
		return FILTER_OUT;

	if (has_filter) {
		if (ftrace_match_filter(&filter_trace, ip))
			return FILTER_MATCH;

		if (mcount_record_idx == 0)
			ret = FILTER_OUT;
	}

	if (has_notrace && ret) {
		if (ftrace_match_filter(&filter_notrace, ip))
			return FILTER_NOTRACE;
	}
	return ret;
}

static __inline__
enum filter_result mcount_entry_filter_check(unsigned long child)
{
	enum filter_result ret;

	if (mcount_rstack_idx >= mcount_rstack_max)
		pr_err_ns("too deeply nested calls: %d\n", mcount_rstack_idx);

	pr_dbg2("<%d> N %lx\n", mcount_rstack_idx, child);
	ret = mcount_filter(child);

	if (ret == FILTER_MATCH)
		mcount_rstack_depth = mcount_depth;
	else if (ret == FILTER_OUT)
		return ret;

	/*
	 * it can be < 0 in case it is called from plthook_entry()
	 * which in turn is called libcygprof.so.
	 */
	if (mcount_rstack_depth <= 0)
		return FILTER_OUT;

	mcount_rstack_depth--;
	return ret;
}

static __inline__
void mcount_entry_filter_record(enum filter_result res,
				struct mcount_ret_stack *rstack)
{
	if (res != FILTER_NOTRACE) {
		if (record_trace_data(rstack) < 0)
			pr_err("error during record");
	} else {
		rstack->flags |= MCOUNT_FL_NOTRACE;
		mcount_rstack_idx -= MCOUNT_NOTRACE_IDX; /* see below */
	}

}

static __inline__
enum filter_result mcount_exit_filter_check(void)
{
	int idx = mcount_rstack_idx;
	enum filter_result ret = FILTER_IN;

	/*
	 * We subtracted big number for notrace filtered functions
	 * so that it can be identified when entering the exit handler.
	 */
	if (idx < 0) {
		struct mcount_ret_stack *rstack;

		idx += MCOUNT_NOTRACE_IDX;
		rstack = &mcount_rstack[idx - 1];

		if ((rstack->flags & MCOUNT_FL_NOTRACE) == 0)
			pr_err_ns("invalid notrace index: %d\n", idx);

		rstack->flags &= ~MCOUNT_FL_NOTRACE;
		mcount_rstack_idx = idx;

		ret = FILTER_OUT;
	}

	if (mcount_rstack_idx <= 0)
		pr_err_ns("broken ret stack (%d)\n", mcount_rstack_idx);

	mcount_rstack_depth++;
	return ret;
}

static __inline__
void mcount_exit_filter_record(enum filter_result res,
			       struct mcount_ret_stack *rstack)
{
	if (res < FILTER_IN)
		return;

	if (record_trace_data(rstack) < 0)
		pr_err("error during record");
}

static __inline__
void mcount_exit_check_rstack(struct mcount_ret_stack *rstack)
{
	pr_dbg2("<%d> X %lx\n", mcount_rstack_idx, rstack->parent_ip);

	if (rstack->depth != mcount_record_idx || rstack->end_time != 0)
		pr_err_ns("corrupted mcount ret stack found!\n");

}

#else /* DISABLE_MCOUNT_FILTER */
static __inline__
enum filter_result mcount_entry_filter_check(unsigned long child)
{
	if (mcount_rstack_idx >= mcount_rstack_max)
		pr_err_ns("too deeply nested calls: %d\n", mcount_rstack_idx);

	return FILTER_IN;
}

static __inline__
void mcount_entry_filter_record(enum filter_result res,
				struct mcount_ret_stack *rstack)
{
	if (record_trace_data(rstack) < 0)
		pr_err("error during record");
}

static __inline__
enum filter_result mcount_exit_filter_check(void)
{
	if (mcount_rstack_idx <= 0)
		pr_err_ns("broken ret stack (%d)\n", mcount_rstack_idx);

	return FILTER_IN;
}

static __inline__
void mcount_exit_filter_record(enum filter_result res,
			       struct mcount_ret_stack *rstack)
{
	if (record_trace_data(rstack) < 0)
		pr_err("error during record");
}

static __inline__
void mcount_exit_check_rstack(struct mcount_ret_stack *rstack)
{
}
#endif /* DISABLE_MCOUNT_FILTER */

int mcount_entry(unsigned long *parent_loc, unsigned long child)
{
	enum filter_result filtered;
	struct mcount_ret_stack *rstack;

	if (unlikely(mcount_rstack == NULL))
		mcount_prepare();

	filtered = mcount_entry_filter_check(child);
	if (filtered == FILTER_OUT)
		return -1;

	rstack = &mcount_rstack[mcount_rstack_idx++];

	rstack->depth = mcount_record_idx++;
	rstack->dyn_idx = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = parent_loc;
	rstack->parent_ip = *parent_loc;
	rstack->child_ip = child;
	rstack->start_time = mcount_gettime();
	rstack->end_time = 0;
	rstack->flags = 0;

	mcount_entry_filter_record(filtered, rstack);
	return 0;
}

unsigned long mcount_exit(void)
{
	enum filter_result was_filtered;
	struct mcount_ret_stack *rstack;

	was_filtered = mcount_exit_filter_check();

	mcount_record_idx--;
	rstack = &mcount_rstack[--mcount_rstack_idx];

	mcount_exit_check_rstack(rstack);

	rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(was_filtered, rstack);

	return rstack->parent_ip;
}

static void mcount_finish(void)
{
	finish_shmem_buffer();
	pthread_key_delete(shmem_key);

	if (pfd != -1) {
		close(pfd);
		pfd = -1;
	}
}

#ifndef DISABLE_MCOUNT_FILTER
static __inline__
enum filter_result cygprof_entry_filter_check(unsigned long child)
{
	enum filter_result ret;

	if (mcount_rstack_idx >= mcount_rstack_max)
		pr_err_ns("too deeply nested calls: %d\n", mcount_rstack_idx);

	pr_dbg2("<%d> N %lx\n", mcount_rstack_idx, child);
	ret = mcount_filter(child);

	if (ret == FILTER_MATCH)
		mcount_rstack_depth = mcount_depth;

	if (mcount_rstack_depth-- <= 0 && ret == FILTER_IN)
		ret = FILTER_OUT;

	return ret;
}

static __inline__
void cygprof_entry_filter_record(enum filter_result res,
				 struct mcount_ret_stack *rstack)
{
	if (res == FILTER_NOTRACE) {
		rstack->flags |= MCOUNT_FL_NORECORD | MCOUNT_FL_NOTRACE;
		mcount_rstack_idx -= MCOUNT_NOTRACE_IDX; /* see below */
		return;
	}

	if (res == FILTER_OUT) {
		rstack->flags |= MCOUNT_FL_NORECORD;
		return;
	}

	mcount_record_idx++;

	if (record_trace_data(rstack) < 0)
		pr_err("error during record");
}

static __inline__
enum filter_result cygprof_exit_filter_check(unsigned long parent,
					     unsigned long child)
{
	enum filter_result ret = FILTER_IN;
	struct mcount_ret_stack *rstack;
	int idx = mcount_rstack_idx;

	/*
	 * We subtracted big number for notrace filtered functions
	 * so that it can be identified when entering the exit handler.
	 */
	if (idx < 0) {
		idx += MCOUNT_NOTRACE_IDX;
		ret = FILTER_OUT;
	}

	rstack = &mcount_rstack[idx - 1];

	if (rstack->flags & MCOUNT_FL_NORECORD) {
		rstack->flags &= ~MCOUNT_FL_NORECORD;
		ret = FILTER_OUT;
	}

	if (rstack->flags & MCOUNT_FL_NOTRACE) {
		rstack->flags &= ~MCOUNT_FL_NOTRACE;
		mcount_rstack_idx = idx;
	}

	if (ret >= FILTER_IN)
		mcount_record_idx--;
	mcount_rstack_depth++;

	if (idx <= 0)
		pr_err_ns("broken ret stack (%d)\n", idx);

	return ret;
}

static __inline__
void cygprof_exit_filter_record(enum filter_result res,
				struct mcount_ret_stack *rstack)
{
	if (res != FILTER_IN)
		return;

	if (record_trace_data(rstack) < 0)
		pr_err("error during record");
}
#else /* DISABLE_MCOUNT_FILTER */
static __inline__
enum filter_result cygprof_entry_filter_check(unsigned long child)
{
	if (mcount_rstack_idx >= mcount_rstack_max)
		pr_err_ns("too deeply nested calls: %d\n", mcount_rstack_idx);

	return FILTER_IN;
}

static __inline__
void cygprof_entry_filter_record(enum filter_result res,
				 struct mcount_ret_stack *rstack)
{
	mcount_record_idx++;

	if (record_trace_data(rstack) < 0)
		pr_err("error during record");
}

static __inline__
enum filter_result cygprof_exit_filter_check(unsigned long parent,
					     unsigned long child)
{
	if (mcount_rstack_idx <= 0)
		pr_err_ns("broken ret stack (%d)\n", mcount_rstack_idx);

	mcount_record_idx--;
	return FILTER_IN;
}

static __inline__
void cygprof_exit_filter_record(enum filter_result res,
				struct mcount_ret_stack *rstack)
{
	if (record_trace_data(rstack) < 0)
		pr_err("error during record");
}
#endif /* DISABLE_MCOUNT_FILTER */

static int cygprof_entry(unsigned long parent, unsigned long child)
{
	enum filter_result filtered;
	struct mcount_ret_stack *rstack;
	int idx = mcount_rstack_idx;

	if (unlikely(mcount_rstack == NULL))
		mcount_prepare();

	filtered = cygprof_entry_filter_check(child);

	if (idx < 0)
		idx += MCOUNT_NOTRACE_IDX;

	rstack = &mcount_rstack[idx];

	rstack->depth = mcount_record_idx;
	rstack->dyn_idx = MCOUNT_INVALID_DYNIDX;
	rstack->parent_ip = parent;
	rstack->child_ip = child;
	rstack->start_time = filtered >= FILTER_IN ? mcount_gettime() : 0;
	rstack->end_time = 0;
	rstack->flags = 0;

	mcount_rstack_idx++;
	cygprof_entry_filter_record(filtered, rstack);
	return 0;
}

static void cygprof_exit(unsigned long parent, unsigned long child)
{
	enum filter_result was_filtered;
	struct mcount_ret_stack *rstack;
	int idx = mcount_rstack_idx - 1;

	was_filtered = cygprof_exit_filter_check(parent, child);

	if (idx < 0)
		idx += MCOUNT_NOTRACE_IDX;

	rstack = &mcount_rstack[idx];

	mcount_exit_check_rstack(rstack);

	rstack->end_time = was_filtered >= FILTER_IN ? mcount_gettime() : 0;

	mcount_rstack_idx--;
	cygprof_exit_filter_record(was_filtered, rstack);
}

static unsigned long got_addr;
static bool segv_handled;

void segv_handler(int sig, siginfo_t *si, void *ctx)
{
	if (si->si_code == SEGV_ACCERR) {
		mprotect((void *)(got_addr & ~0xFFF), sizeof(long)*3,
			 PROT_WRITE);
		segv_handled = true;
	} else {
		pr_err_ns("mcount: invalid memory access.. exiting.\n");
	}
}

extern void __attribute__((weak)) plt_hooker(void);

static int find_got(Elf_Data *dyn_data, size_t nr_dyn)
{
	size_t i;
	struct sigaction sa, old_sa;

	for (i = 0; i < nr_dyn; i++) {
		GElf_Dyn dyn;

		if (gelf_getdyn(dyn_data, i, &dyn) == NULL)
			return -1;

		if (dyn.d_tag != DT_PLTGOT)
			continue;

		got_addr = (unsigned long)dyn.d_un.d_val;
		plthook_got_ptr = (void *)got_addr;
		plthook_resolver_addr = plthook_got_ptr[2];

		/*
		 * The GOT region is write-protected on some systems.
		 * In that case, we need to use mprotect() to overwrite
		 * the address of resolver function.  So install signal
		 * handler to catch such cases.
		 */
		sa.sa_sigaction = segv_handler;
		sa.sa_flags = SA_SIGINFO;
		sigfillset(&sa.sa_mask);
		if (sigaction(SIGSEGV, &sa, &old_sa) < 0) {
			pr_log("error during install sig handler\n");
			return -1;
		}

		plthook_got_ptr[2] = (unsigned long)plt_hooker;

		if (sigaction(SIGSEGV, &old_sa, NULL) < 0) {
			pr_log("error during recover sig handler\n");
			return -1;
		}

		if (segv_handled) {
			mprotect((void *)(got_addr & ~0xFFF), sizeof(long)*3,
				 PROT_READ);
			segv_handled = false;
		}

		pr_dbg("found GOT at %p (resolver: %#lx)\n",
		       plthook_got_ptr, plthook_resolver_addr);

		break;
	}
	return 0;
}

static int hook_pltgot(void)
{
	int fd;
	int ret = -1;
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Scn *sec;
	GElf_Shdr shdr;
	Elf_Data *data;
	size_t shstr_idx;
	size_t i;

	pr_dbg("opening executable image: %s\n", mcount_exename);

	fd = open(mcount_exename, O_RDONLY);
	if (fd < 0)
		return -1;

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);

	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto elf_error;

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto elf_error;

	for (i = 0; i < ehdr.e_phnum; i++) {
		GElf_Phdr phdr;

		if (gelf_getphdr(elf, i, &phdr) == NULL)
			goto elf_error;

		if (phdr.p_type != PT_DYNAMIC)
			continue;

		sec = gelf_offscn(elf, phdr.p_offset);

		if (!sec || gelf_getshdr(sec, &shdr) == NULL)
			continue;

		data = elf_getdata(sec, NULL);
		if (data == NULL)
			goto elf_error;

		if (find_got(data, shdr.sh_size / shdr.sh_entsize) < 0)
			goto elf_error;
	}
	ret = 0;

out:
	elf_end(elf);
	close(fd);

	return ret;

elf_error:
	pr_log("%s\n", elf_errmsg(elf_errno()));

	goto out;
}

/* functions should skip PLT hooking */
static const char *skip_syms[] = {
	"mcount",
	"__fentry__",
	"__gnu_mcount_nc",
	"__cyg_profile_func_enter",
	"__cyg_profile_func_exit",
	"_mcleanup",
	"mcount_restore",
	"mcount_reset",
	"__libc_start_main",
};

static struct dynsym_idxlist skip_idxlist;

static const char *setjmp_syms[] = {
	"setjmp",
	"_setjmp",
	"sigsetjmp",
	"__sigsetjmp",
};

static struct dynsym_idxlist setjmp_idxlist;

static const char *longjmp_syms[] = {
	"longjmp",
	"siglongjmp",
	"__longjmp_chk",
};

static struct dynsym_idxlist longjmp_idxlist;

static void setup_dynsym_indexes(struct symtabs *symtabs)
{
	build_dynsym_idxlist(symtabs, &skip_idxlist,
			     skip_syms, ARRAY_SIZE(skip_syms));
	build_dynsym_idxlist(symtabs, &setjmp_idxlist,
			     setjmp_syms, ARRAY_SIZE(setjmp_syms));
	build_dynsym_idxlist(symtabs, &longjmp_idxlist,
			     longjmp_syms, ARRAY_SIZE(longjmp_syms));
}

static void destroy_dynsym_indexes(void)
{
	destroy_dynsym_idxlist(&skip_idxlist);
	destroy_dynsym_idxlist(&setjmp_idxlist);
	destroy_dynsym_idxlist(&longjmp_idxlist);
}

struct mcount_jmpbuf_rstack {
	int count;
	int record_idx;
	unsigned long parent[MCOUNT_RSTACK_MAX];
	unsigned long child[MCOUNT_RSTACK_MAX];
};

static struct mcount_jmpbuf_rstack setjmp_rstack;

static void setup_jmpbuf_rstack(struct mcount_ret_stack *rstack, int idx)
{
	int i;
	struct mcount_jmpbuf_rstack *jbstack = &setjmp_rstack;

	pr_dbg("setup jmpbuf rstack: %d\n", idx);

	/* currently, only saves a single jmpbuf */
	jbstack->count = idx;
	jbstack->record_idx = mcount_record_idx;
	for (i = 0; i <= idx; i++) {
		jbstack->parent[i] = rstack[i].parent_ip;
		jbstack->child[i]  = rstack[i].child_ip;
	}

	rstack[idx].flags |= MCOUNT_FL_SETJMP;
}

static void restore_jmpbuf_rstack(struct mcount_ret_stack *rstack, int idx)
{
	int i, dyn_idx;
	struct mcount_jmpbuf_rstack *jbstack = &setjmp_rstack;

	dyn_idx = rstack[idx].dyn_idx;

	pr_dbg("restore jmpbuf: %d\n", jbstack->count);

	mcount_rstack_idx = jbstack->count + 1;
	mcount_record_idx = jbstack->record_idx;

	for (i = 0; i < jbstack->count + 1; i++) {
		mcount_rstack[i].parent_ip = jbstack->parent[i];
		mcount_rstack[i].child_ip  = jbstack->child[i];
	}

	rstack[idx].flags &= ~MCOUNT_FL_LONGJMP;

	/* to avoid check in plthook_exit() */
	rstack[jbstack->count].dyn_idx = dyn_idx;
}

#ifndef DISABLE_MCOUNT_FILTER
static enum filter_result plthook_filter(unsigned long ip)
{
	enum filter_result ret = FILTER_IN;

	/*
	 * mcount_rstack_idx > 0 means it's now traced (not filtered)
	 */
	if (mcount_rstack_idx < 0)
		return FILTER_OUT;

	if (has_plt_filter) {
		if (ftrace_match_filter(&filter_plt_trace, ip))
			return FILTER_IN;
		ret = FILTER_OUT;
	}

	if (has_plt_notrace && ret) {
		if (ftrace_match_filter(&filter_plt_notrace, ip))
			return FILTER_OUT;
	}
	return ret;
}
#else
static enum filter_result plthook_filter(unsigned long ip)
{
	return FILTER_IN;
}
#endif

extern unsigned long plthook_return(void);

unsigned long plthook_entry(unsigned long *ret_addr, unsigned long child_idx,
			    unsigned long module_id)
{
	struct sym *sym;
	unsigned long child_ip;

	/*
	 * There was a recursion like below:
	 *
	 * plthook_entry -> mcount_entry -> mcount_prepare -> xmalloc
	 *   -> plthook_entry
	 */
	if (plthook_recursion_guard)
		goto out;

	if (check_dynsym_idxlist(&skip_idxlist, child_idx))
		goto out;

	sym = find_dynsym(&symtabs, child_idx);
	pr_dbg2("[%d] n %s\n", child_idx, sym->name);

	child_ip = sym ? sym->addr : 0;
	if (child_ip == 0) {
		pr_err_ns("invalid function idx found! (idx: %d, %#lx)\n",
			  (int) child_idx, child_idx);
	}

	if (plthook_filter(sym->addr) == FILTER_OUT)
		goto out;

	plthook_recursion_guard = true;

	if (mcount_entry(ret_addr, child_ip) == 0) {
		int idx = mcount_rstack_idx - 1;

		*ret_addr = (unsigned long)plthook_return;

		if (idx < 0)
			idx += MCOUNT_NOTRACE_IDX;

		if (idx >= mcount_rstack_max)
			pr_err_ns("invalid rstack idx: %d\n", idx);

		mcount_rstack[idx].dyn_idx = child_idx;

		if (check_dynsym_idxlist(&setjmp_idxlist, child_idx))
			setup_jmpbuf_rstack(mcount_rstack, idx);
		if (check_dynsym_idxlist(&longjmp_idxlist, child_idx))
			mcount_rstack[idx].flags |= MCOUNT_FL_LONGJMP;
	} else {
		plthook_recursion_guard = false;
	}

out:
	if (plthook_dynsym_resolved[child_idx])
		return plthook_dynsym_addr[child_idx];

	plthook_dynsym_addr[child_idx] = plthook_got_ptr[3 + child_idx];
	return 0;
}

unsigned long plthook_exit(void)
{
	unsigned long orig_ip;
	int idx = mcount_rstack_idx - 1;
	int dyn_idx;
	unsigned long new_addr;

	if (idx >= 0 && (mcount_rstack[idx].flags & MCOUNT_FL_LONGJMP))
		restore_jmpbuf_rstack(mcount_rstack, idx);

	orig_ip = mcount_exit();
	idx = mcount_rstack_idx;

	dyn_idx = mcount_rstack[idx].dyn_idx;

	if (dyn_idx == MCOUNT_INVALID_DYNIDX)
		pr_err_ns("invalid dynsym idx: %d\n", idx);

	if (!plthook_dynsym_resolved[dyn_idx]) {
		struct sym *sym = find_dynsym(&symtabs, dyn_idx);
		char *name = symbol_getname(sym, 0);

		new_addr = plthook_got_ptr[3 + dyn_idx];
		/* restore GOT so plt_hooker keep called */
		plthook_got_ptr[3 + dyn_idx] = plthook_dynsym_addr[dyn_idx];

		plthook_dynsym_resolved[dyn_idx] = true;
		plthook_dynsym_addr[dyn_idx] = new_addr;

		pr_dbg2("[%d] x %s: %lx\n", dyn_idx, name, new_addr);
		symbol_putname(sym, name);
	}

	plthook_recursion_guard = false;

	return orig_ip;
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
	struct ftrace_msg_task tmsg = {
		.time = mcount_gettime(),
		.pid = getppid(),
		.tid = getpid(),
	};

	tid = 0;

	clear_shmem_buffer();
	get_new_shmem_buffer();

	ftrace_send_message(FTRACE_MSG_FORK_END, &tmsg, sizeof(tmsg));
}

/*
 * external interfaces
 */
void __attribute__((visibility("default")))
__monstartup(unsigned long low, unsigned long high)
{
	char *pipefd_str = getenv("FTRACE_PIPE");
	char *logfd_str = getenv("FTRACE_LOGFD");
	char *debug_str = getenv("FTRACE_DEBUG");
	char *bufsize_str = getenv("FTRACE_BUFFER");
	char *maxstack_str = getenv("FTRACE_MAX_STACK");
	struct stat statbuf;

	if (mcount_setup_done)
		return;

	if (logfd_str) {
		logfd = strtol(logfd_str, NULL, 0);

		/* minimal sanity check */
		if (fstat(logfd, &statbuf) < 0)
			logfd = STDERR_FILENO;
	}

	if (pipefd_str) {
		pfd = strtol(pipefd_str, NULL, 0);

		/* minimal sanity check */
		if (fstat(pfd, &statbuf) < 0 || !S_ISFIFO(statbuf.st_mode)) {
			pr_log("ignore invalid pipe fd: %d\n", pfd);
			pfd = -1;
		}
	}

	if (debug_str)
		debug = strtol(debug_str, NULL, 0);

	if (bufsize_str)
		shmem_bufsize = strtol(bufsize_str, NULL, 0);

	read_exename();
	load_symtabs(&symtabs, NULL, mcount_exename);

#ifndef DISABLE_MCOUNT_FILTER
	ftrace_setup_filter(getenv("FTRACE_FILTER"), &symtabs, NULL,
			    &filter_trace, &has_filter);
	ftrace_setup_filter(getenv("FTRACE_NOTRACE"), &symtabs, NULL,
			    &filter_notrace, &has_notrace);
	ftrace_setup_filter_regex(getenv("FTRACE_FILTER_REGEX"), &symtabs, NULL,
				  &filter_trace, &has_filter);
	ftrace_setup_filter_regex(getenv("FTRACE_NOTRACE_REGEX"), &symtabs, NULL,
				  &filter_notrace, &has_notrace);

	if (getenv("FTRACE_DEPTH"))
		mcount_depth = strtol(getenv("FTRACE_DEPTH"), NULL, 0);
#endif /* DISABLE_MCOUNT_FILTER */

	if (maxstack_str)
		mcount_rstack_max = strtol(maxstack_str, NULL, 0);

	if (getenv("FTRACE_PLTHOOK")) {
		setup_dynsym_indexes(&symtabs);

#ifndef DISABLE_MCOUNT_FILTER
		ftrace_setup_filter(getenv("FTRACE_FILTER"), &symtabs, "plt",
				    &filter_plt_trace, &has_plt_filter);
		ftrace_setup_filter(getenv("FTRACE_NOTRACE"), &symtabs, "plt",
				    &filter_plt_notrace, &has_plt_notrace);
		ftrace_setup_filter_regex(getenv("FTRACE_FILTER_REGEX"), &symtabs, "plt",
					  &filter_plt_trace, &has_plt_filter);
		ftrace_setup_filter_regex(getenv("FTRACE_NOTRACE_REGEX"), &symtabs, "plt",
					  &filter_plt_notrace, &has_plt_notrace);
#endif
		if (hook_pltgot() < 0)
			pr_dbg("error when hooking plt: skipping...\n");
		else {
			plthook_dynsym_resolved = xcalloc(sizeof(bool),
							  count_dynsym(&symtabs));
			plthook_dynsym_addr = xcalloc(sizeof(unsigned long),
						      count_dynsym(&symtabs));
		}
	}

	pthread_atfork(atfork_prepare_handler, NULL, atfork_child_handler);

	mcount_setup_done = true;
}

void __attribute__((visibility("default")))
_mcleanup(void)
{
	mcount_finish();
	destroy_dynsym_indexes();

#ifndef DISABLE_MCOUNT_FILTER
	ftrace_cleanup_filter(&filter_trace);
	ftrace_cleanup_filter(&filter_notrace);
#endif
}

void __attribute__((visibility("default")))
mcount_restore(void)
{
	int idx;

	if (unlikely(mcount_rstack == NULL))
		return;

	for (idx = mcount_rstack_idx - 1; idx >= 0; idx--)
		*mcount_rstack[idx].parent_loc = mcount_rstack[idx].parent_ip;
}

extern __attribute__((weak)) void mcount_return(void);

void __attribute__((visibility("default")))
mcount_reset(void)
{
	int idx;

	if (unlikely(mcount_rstack == NULL))
		return;

	for (idx = mcount_rstack_idx - 1; idx >= 0; idx--)
		*mcount_rstack[idx].parent_loc = (unsigned long)mcount_return;
}

void __attribute__((visibility("default")))
__cyg_profile_func_enter(void *child, void *parent)
{
	cygprof_entry((unsigned long)parent, (unsigned long)child);
}

void __attribute__((visibility("default")))
__cyg_profile_func_exit(void *child, void *parent)
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
