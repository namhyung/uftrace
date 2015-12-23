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
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"

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
static bool mcount_enabled = true;

struct filter_control {
	int in_count;
	int out_count;
	int depth;
	int saved_depth;
};

static TLS struct filter_control mcount_filter;
static enum filter_mode mcount_filter_mode = FILTER_MODE_NONE;

static struct rb_root mcount_triggers = RB_ROOT;
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
			pr_err("cannot open urandom file");

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
		pr_dbg2("opening shmem buffer: %s\n", buf);

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

	pr_dbg3("task %d recorded %zd bytes\n", gettid(), size);

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
	mcount_filter.depth = mcount_depth;
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
/* update filter state from trigger result */
static __inline__
enum filter_result mcount_entry_filter_check(unsigned long child,
					     struct ftrace_trigger *tr)
{
	if (mcount_rstack_idx >= mcount_rstack_max)
		pr_err_ns("too deeply nested calls: %d\n", mcount_rstack_idx);

	pr_dbg3("<%d> enter %lx\n", mcount_rstack_idx, child);

	/* save original depth to restore at exit time */
	mcount_filter.saved_depth = mcount_filter.depth;

	/* already filtered by notrace option */
	if (mcount_filter.out_count > 0)
		return FILTER_OUT;

	ftrace_match_filter(&mcount_triggers, child, tr);

	pr_dbg3(" tr->flags: %lx, filter mode, count: [%d] %d/%d\n",
		tr->flags, mcount_filter_mode, mcount_filter.in_count, mcount_filter.out_count);

	if (tr->flags & TRIGGER_FL_FILTER) {
		if (tr->fmode == FILTER_MODE_IN)
			mcount_filter.in_count++;
		else if (tr->fmode == FILTER_MODE_OUT)
			mcount_filter.out_count++;

		/* apply default filter depth when match */
		mcount_filter.depth = mcount_depth;
	}
	else {
		/* not matched by filter */
		if (mcount_filter_mode == FILTER_MODE_IN &&
		    mcount_filter.in_count == 0)
			return FILTER_OUT;
	}

	if (tr->flags & TRIGGER_FL_DEPTH)
		mcount_filter.depth = tr->depth;

	if (tr->flags & TRIGGER_FL_TRACE_ON)
		mcount_enabled = true;

	if (tr->flags & TRIGGER_FL_TRACE_OFF)
		mcount_enabled = false;

	if (!mcount_enabled)
		return FILTER_IN;

	/*
	 * it can be < 0 in case it is called from plthook_entry()
	 * which in turn is called libcygprof.so.
	 */
	if (mcount_filter.depth <= 0)
		return FILTER_OUT;

	mcount_filter.depth--;
	return FILTER_IN;
}

/* save current filter state to rstack */
static __inline__
void mcount_entry_filter_record(struct mcount_ret_stack *rstack,
				struct ftrace_trigger *tr)
{
	if (tr->flags & TRIGGER_FL_FILTER) {
		if (tr->fmode == FILTER_MODE_IN)
			rstack->flags |= MCOUNT_FL_FILTERED;
		else
			rstack->flags |= MCOUNT_FL_NOTRACE;
	}

	if (mcount_filter.out_count > 0 ||
	    (mcount_filter.in_count == 0 && mcount_filter_mode == FILTER_MODE_IN))
		rstack->flags |= MCOUNT_FL_NORECORD;

	rstack->filter_depth = mcount_filter.saved_depth;

	if (!(rstack->flags & MCOUNT_FL_NORECORD)) {
		mcount_record_idx++;

		if (mcount_enabled && (record_trace_data(rstack) < 0))
			pr_err("error during record");
	}

}

/* restore filter state from rstack */
static __inline__
void mcount_exit_filter_record(struct mcount_ret_stack *rstack)
{
	pr_dbg3("<%d> exit  %lx\n", mcount_rstack_idx, rstack->child_ip);

	if (rstack->flags & MCOUNT_FL_FILTERED)
		mcount_filter.in_count--;
	else if (rstack->flags & MCOUNT_FL_NOTRACE)
		mcount_filter.out_count--;

	mcount_filter.depth = rstack->filter_depth;

	if (!(rstack->flags & MCOUNT_FL_NORECORD)) {
		if (mcount_record_idx > 0)
			mcount_record_idx--;

		if (mcount_enabled && (record_trace_data(rstack) < 0))
			pr_err("error during record");
	}
}

#else /* DISABLE_MCOUNT_FILTER */
static __inline__
enum filter_result mcount_entry_filter_check(unsigned long child,
					     struct ftrace_trigger *tr)
{
	if (mcount_rstack_idx >= mcount_rstack_max)
		pr_err_ns("too deeply nested calls: %d\n", mcount_rstack_idx);

	return FILTER_IN;
}

static __inline__
void mcount_entry_filter_record(struct mcount_ret_stack *rstack,
				struct ftrace_trigger *tr)
{
	mcount_record_idx++;

	if (record_trace_data(rstack) < 0)
		pr_err("error during record");
}

static __inline__
void mcount_exit_filter_record(struct mcount_ret_stack *rstack)
{
	mcount_record_idx--;

	if (record_trace_data(rstack) < 0)
		pr_err("error during record");
}

#endif /* DISABLE_MCOUNT_FILTER */

int mcount_entry(unsigned long *parent_loc, unsigned long child)
{
	enum filter_result filtered;
	struct mcount_ret_stack *rstack;
	struct ftrace_trigger tr = {
		.flags = 0,
	};

	if (unlikely(mcount_rstack == NULL))
		mcount_prepare();

	filtered = mcount_entry_filter_check(child, &tr);
	if (filtered == FILTER_OUT)
		return -1;

	rstack = &mcount_rstack[mcount_rstack_idx++];

	rstack->depth      = mcount_record_idx;
	rstack->dyn_idx    = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = parent_loc;
	rstack->parent_ip  = *parent_loc;
	rstack->child_ip   = child;
	rstack->start_time = mcount_gettime();
	rstack->end_time   = 0;
	rstack->flags      = 0;

	mcount_entry_filter_record(rstack, &tr);
	return 0;
}

unsigned long mcount_exit(void)
{
	struct mcount_ret_stack *rstack;

	rstack = &mcount_rstack[--mcount_rstack_idx];

	rstack->end_time = mcount_gettime();
	mcount_exit_filter_record(rstack);

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

static int cygprof_entry(unsigned long parent, unsigned long child)
{
	enum filter_result filtered;
	struct mcount_ret_stack *rstack;
	struct ftrace_trigger tr = {
		.flags = 0,
	};

	if (unlikely(mcount_rstack == NULL))
		mcount_prepare();

	filtered = mcount_entry_filter_check(child, &tr);

	rstack = &mcount_rstack[mcount_rstack_idx++];

	rstack->depth      = mcount_record_idx;
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

	mcount_entry_filter_record(rstack, &tr);
	return 0;
}

static void cygprof_exit(unsigned long parent, unsigned long child)
{
	struct mcount_ret_stack *rstack;

	rstack = &mcount_rstack[--mcount_rstack_idx];

	if (!(rstack->flags & MCOUNT_FL_NORECORD))
		rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(rstack);
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
			pr_dbg("error during install sig handler\n");
			return -1;
		}

		plthook_got_ptr[2] = (unsigned long)plt_hooker;

		if (sigaction(SIGSEGV, &old_sa, NULL) < 0) {
			pr_dbg("error during recover sig handler\n");
			return -1;
		}

		if (segv_handled) {
			mprotect((void *)(got_addr & ~0xFFF), sizeof(long)*3,
				 PROT_READ);
			segv_handled = false;
		}

		pr_dbg2("found GOT at %p (PLT resolver: %#lx)\n",
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

	pr_dbg2("opening executable image: %s\n", mcount_exename);

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
	pr_dbg("%s\n", elf_errmsg(elf_errno()));

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

static const char *vfork_syms[] = {
	"vfork",
};

static struct dynsym_idxlist vfork_idxlist;

static void setup_dynsym_indexes(struct symtabs *symtabs)
{
	build_dynsym_idxlist(symtabs, &skip_idxlist,
			     skip_syms, ARRAY_SIZE(skip_syms));
	build_dynsym_idxlist(symtabs, &setjmp_idxlist,
			     setjmp_syms, ARRAY_SIZE(setjmp_syms));
	build_dynsym_idxlist(symtabs, &longjmp_idxlist,
			     longjmp_syms, ARRAY_SIZE(longjmp_syms));
	build_dynsym_idxlist(symtabs, &vfork_idxlist,
			     vfork_syms, ARRAY_SIZE(vfork_syms));
}

static void destroy_dynsym_indexes(void)
{
	destroy_dynsym_idxlist(&skip_idxlist);
	destroy_dynsym_idxlist(&setjmp_idxlist);
	destroy_dynsym_idxlist(&longjmp_idxlist);
	destroy_dynsym_idxlist(&vfork_idxlist);
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

	pr_dbg2("setup jmpbuf rstack: %d\n", idx);

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

	pr_dbg2("restore jmpbuf: %d\n", jbstack->count);

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

/* it's crazy to call vfork() concurrently */
static int vfork_parent;
static TLS int vfork_shmem_seqnum;
static TLS struct mcount_shmem_buffer *vfork_shmem_buffer[2];
static TLS struct mcount_shmem_buffer *vfork_shmem_curr;

static void prepare_vfork(void)
{
	/* save original parent pid */
	vfork_parent = getpid();
}

/* this function will be called in child */
static void setup_vfork(void)
{
	struct ftrace_msg_task tmsg = {
		.pid = getppid(),
		.tid = getpid(),
		.time = mcount_gettime(),
	};

	vfork_shmem_seqnum = shmem_seqnum;
	vfork_shmem_buffer[0] = shmem_buffer[0];
	vfork_shmem_buffer[1] = shmem_buffer[1];
	vfork_shmem_curr = shmem_curr;

	/* setup new shmem buffer for child */
	tid = 0;
	shmem_seqnum = 0;
	shmem_buffer[0] = NULL;
	shmem_buffer[1] = NULL;
	shmem_curr = NULL;

	ftrace_send_message(FTRACE_MSG_TID, &tmsg, sizeof(tmsg));
}

/* this function detects whether child finished */
static void restore_vfork(struct mcount_ret_stack *rstack)
{
	/*
	 * On vfork, parent sleeps until child exec'ed or exited.
	 * So if it sees parent pid, that means child was done.
	 */
	if (getpid() == vfork_parent) {
		struct sym *sym;

		shmem_seqnum = vfork_shmem_seqnum;
		shmem_buffer[0] = vfork_shmem_buffer[0];
		shmem_buffer[1] = vfork_shmem_buffer[1];
		shmem_curr = vfork_shmem_curr;

		tid = 0;
		vfork_parent = 0;

		/* make parent returning from vfork() */
		sym = find_dynsym(&symtabs, vfork_idxlist.idx[0]);
		if (sym)
			rstack->child_ip = sym->addr;
	}
}

extern unsigned long plthook_return(void);

unsigned long plthook_entry(unsigned long *ret_addr, unsigned long child_idx,
			    unsigned long module_id)
{
	struct sym *sym;
	unsigned long child_ip;
	struct mcount_ret_stack *rstack;
	struct ftrace_trigger tr = {
		.flags = 0,
	};
	bool skip = false;

	if (unlikely(mcount_rstack == NULL))
		mcount_prepare();

	/*
	 * There was a recursion like below:
	 *
	 * plthook_entry -> mcount_entry -> mcount_prepare -> xmalloc
	 *   -> plthook_entry
	 */
	if (plthook_recursion_guard)
		return 0;

	if (check_dynsym_idxlist(&skip_idxlist, child_idx))
		return 0;

	sym = find_dynsym(&symtabs, child_idx);
	pr_dbg3("[%d] enter %"PRIx64": %s\n", child_idx, sym->addr, sym->name);

	child_ip = sym ? sym->addr : 0;
	if (child_ip == 0) {
		pr_err_ns("invalid function idx found! (idx: %d, %#lx)\n",
			  (int) child_idx, child_idx);
	}

	if (mcount_entry_filter_check(sym->addr, &tr) == FILTER_OUT) {
		/*
		 * Skip recording but still hook the return address,
		 * otherwise it cannot trace further invocations due to
		 * the overwritten PLT entry by the resolver function.
		 */
		skip = true;
		goto out;
	}

	plthook_recursion_guard = true;

out:
	rstack = &mcount_rstack[mcount_rstack_idx++];

	rstack->depth      = mcount_record_idx;
	rstack->dyn_idx    = child_idx;
	rstack->parent_loc = ret_addr;
	rstack->parent_ip  = *ret_addr;
	rstack->child_ip   = child_ip;
	rstack->start_time = skip ? 0 : mcount_gettime();
	rstack->end_time   = 0;
	rstack->flags      = skip ? MCOUNT_FL_NORECORD : 0;

	mcount_entry_filter_record(rstack, &tr);

	*ret_addr = (unsigned long)plthook_return;

	if (check_dynsym_idxlist(&setjmp_idxlist, child_idx))
		setup_jmpbuf_rstack(mcount_rstack, mcount_rstack_idx-1);
	if (check_dynsym_idxlist(&longjmp_idxlist, child_idx))
		rstack->flags |= MCOUNT_FL_LONGJMP;
	if (check_dynsym_idxlist(&vfork_idxlist, child_idx)) {
		rstack->flags |= MCOUNT_FL_VFORK;
		prepare_vfork();
	}

	if (plthook_dynsym_resolved[child_idx])
		return plthook_dynsym_addr[child_idx];

	plthook_dynsym_addr[child_idx] = plthook_got_ptr[3 + child_idx];
	return 0;
}

unsigned long plthook_exit(void)
{
	int dyn_idx;
	unsigned long new_addr;
	struct mcount_ret_stack *rstack;

again:
	rstack = &mcount_rstack[--mcount_rstack_idx];

	if (unlikely(rstack->flags & (MCOUNT_FL_LONGJMP | MCOUNT_FL_VFORK))) {
		if (rstack->flags & MCOUNT_FL_LONGJMP) {
			restore_jmpbuf_rstack(mcount_rstack, mcount_rstack_idx+1);
			goto again;
		}

		if (rstack->flags & MCOUNT_FL_VFORK)
			setup_vfork();
	}

	if (unlikely(vfork_parent))
		restore_vfork(rstack);

	dyn_idx = rstack->dyn_idx;
	if (dyn_idx == MCOUNT_INVALID_DYNIDX) {
		pr_err_ns("<%d> invalid dynsym idx: %d\n",
			  mcount_rstack_idx, dyn_idx);
	}

	pr_dbg3("[%d] exit  %"PRIx64": %s\n", dyn_idx,
		plthook_dynsym_addr[dyn_idx],
		find_dynsym(&symtabs, dyn_idx)->name);

	if (!(rstack->flags & MCOUNT_FL_NORECORD))
		rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(rstack);

	plthook_recursion_guard = false;

	if (!plthook_dynsym_resolved[dyn_idx]) {
		new_addr = plthook_got_ptr[3 + dyn_idx];
		/* restore GOT so plt_hooker keep called */
		plthook_got_ptr[3 + dyn_idx] = plthook_dynsym_addr[dyn_idx];

		plthook_dynsym_resolved[dyn_idx] = true;
		plthook_dynsym_addr[dyn_idx] = new_addr;
	}
	return rstack->parent_ip;
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
void __attribute__((visibility("default")))
__monstartup(unsigned long low, unsigned long high)
{
	char *pipefd_str = getenv("FTRACE_PIPE");
	char *logfd_str = getenv("FTRACE_LOGFD");
	char *debug_str = getenv("FTRACE_DEBUG");
	char *bufsize_str = getenv("FTRACE_BUFFER");
	char *maxstack_str = getenv("FTRACE_MAX_STACK");
	char *color_str = getenv("FTRACE_COLOR");
	struct stat statbuf;

	if (mcount_setup_done)
		return;

	outfp = stdout;
	logfp = stderr;

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
		build_debug_domain(getenv("FTRACE_DEBUG_DOMAIN"));
	}

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

	read_exename();
	load_symtabs(&symtabs, NULL, mcount_exename);

#ifndef DISABLE_MCOUNT_FILTER
	ftrace_setup_filter(getenv("FTRACE_FILTER"), &symtabs, NULL,
			    &mcount_triggers, &mcount_filter_mode);

	ftrace_setup_trigger(getenv("FTRACE_TRIGGER"), &symtabs, NULL,
			     &mcount_triggers);

	if (getenv("FTRACE_DEPTH"))
		mcount_depth = strtol(getenv("FTRACE_DEPTH"), NULL, 0);

	if (getenv("FTRACE_DISABLED"))
		mcount_enabled = false;
#endif /* DISABLE_MCOUNT_FILTER */

	if (maxstack_str)
		mcount_rstack_max = strtol(maxstack_str, NULL, 0);

	if (getenv("FTRACE_PLTHOOK")) {
		setup_dynsym_indexes(&symtabs);

#ifndef DISABLE_MCOUNT_FILTER
		ftrace_setup_filter(getenv("FTRACE_FILTER"), &symtabs, "PLT",
				    &mcount_triggers, &mcount_filter_mode);

		ftrace_setup_trigger(getenv("FTRACE_TRIGGER"), &symtabs, "PLT",
				    &mcount_triggers);
#endif /* DISABLE_MCOUNT_FILTER */

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
	ftrace_cleanup_filter(&mcount_triggers);
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
