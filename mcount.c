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
#include "symbol.h"
#include "utils.h"

__thread int mcount_rstack_idx;
__thread struct mcount_ret_stack *mcount_rstack;

static int mcount_depth = MCOUNT_DEFAULT_DEPTH;
static __thread int mcount_rstack_depth;

static int pfd = -1;
static bool mcount_setup_done;

static struct rb_root filter_trace = RB_ROOT;
static struct rb_root filter_notrace = RB_ROOT;
static bool has_filter, has_notrace;

static __thread bool plthook_recursion_guard;
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

static __thread int tid;
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
static __thread int shmem_seqnum;
static __thread struct mcount_shmem_buffer *shmem_buffer[2];
static __thread struct mcount_shmem_buffer *shmem_curr;
static __thread int shmem_losts;
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

	pr_dbg2("%d recording %zd bytes\n", mrstack->tid, size);

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

	mcount_rstack_depth = mcount_depth;
	mcount_rstack = xmalloc(MCOUNT_RSTACK_MAX * sizeof(*mcount_rstack));

	pthread_once(&once_control, mcount_init_file);

	/* time should be get after session message sent */
	tmsg.time = mcount_gettime();

	ftrace_send_message(FTRACE_MSG_TID, &tmsg, sizeof(tmsg));
}

/*
 * return 2 if it matches one of the filters.
 * return 1 if it's inside of a filter function (or there's no filters),
 * return 0 if it's outside of filter functions.
 * return -1 if it's filtered at notrace - needs special treatment.
 */
static int mcount_filter(unsigned long ip)
{
	/*
	 * mcount_rstack_idx > 0 means it's now traced (not filtered)
	 */
	int ret = mcount_rstack_idx >= 0;

	if (mcount_rstack_idx < 0)
		return 0;

	if (has_filter && (mcount_rstack_idx == 0 || mcount_rstack_depth == 0)) {
		if (ftrace_match_filter(&filter_trace, ip))
			return 2;
		ret = 0;
	}

	if (has_notrace && ret) {
		if (ftrace_match_filter(&filter_notrace, ip))
			return -1;
	}
	return ret;
}

int mcount_entry(unsigned long *parent_loc, unsigned long child)
{
	int filtered;
	struct mcount_ret_stack *rstack;

	if (unlikely(mcount_rstack == NULL))
		mcount_prepare();

	if (mcount_rstack_idx >= MCOUNT_RSTACK_MAX) {
		pr_log("too deeply nested calls\n");
		return -1;
	}

	pr_dbg2("<%d> N %lx\n", mcount_rstack_idx, child);
	filtered = mcount_filter(child);

	if (filtered == 2)
		mcount_rstack_depth = mcount_depth;
	else if (filtered == 0)
		return -1;

	/*
	 * it can be < 0 in case it is called from plthook_entry()
	 * which in turn is called libcygprof.so.
	 */
	if (mcount_rstack_depth <= 0)
		return -1;

	mcount_rstack_depth--;

	rstack = &mcount_rstack[mcount_rstack_idx++];

	rstack->tid = gettid();
	rstack->depth = mcount_rstack_idx - 1;
	rstack->dyn_idx = MCOUNT_INVALID_DYNIDX;
	rstack->parent_loc = parent_loc;
	rstack->parent_ip = *parent_loc;
	rstack->child_ip = child;
	rstack->start_time = mcount_gettime();
	rstack->end_time = 0;

	if (filtered > 0) {
		if (record_trace_data(rstack) < 0)
			pr_err("error during record");
	} else
		mcount_rstack_idx -= MCOUNT_NOTRACE_IDX; /* see below */

	return 0;
}

unsigned long mcount_exit(void)
{
	bool was_filtered = false;
	struct mcount_ret_stack *rstack;

	/*
	 * We subtracted big number for notrace filtered functions
	 * so that it can be identified when entering the exit handler.
	 */
	if (mcount_rstack_idx < 0) {
		mcount_rstack_idx += MCOUNT_NOTRACE_IDX;
		was_filtered = true;
	}

	if (mcount_rstack_idx <= 0)
		pr_err_ns("broken ret stack (%d)\n", mcount_rstack_idx);

	mcount_rstack_depth++;
	rstack = &mcount_rstack[--mcount_rstack_idx];

	pr_dbg2("<%d> X %lx\n", mcount_rstack_idx, rstack->parent_ip);

	if (rstack->depth != mcount_rstack_idx || rstack->end_time != 0)
		pr_err_ns("corrupted mcount ret stack found!\n");

	rstack->end_time = mcount_gettime();
	rstack->tid = gettid();

	if (!was_filtered) {
		if (record_trace_data(rstack) < 0)
			pr_err("error during record");
	}

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

int cygprof_entry(unsigned long parent, unsigned long child)
{
	int filtered;
	struct mcount_ret_stack *rstack;

	if (unlikely(mcount_rstack == NULL))
		mcount_prepare();

	if (mcount_rstack_idx >= MCOUNT_RSTACK_MAX) {
		pr_log("too deeply nested calls\n");
		return -1;
	}

	pr_dbg2("<%d> N %lx\n", mcount_rstack_idx, child);
	filtered = mcount_filter(child);

	if (filtered == 2)
		mcount_rstack_depth = mcount_depth;
	else if (filtered == 0)
		return -1;

	mcount_rstack_depth--;

	rstack = &mcount_rstack[mcount_rstack_idx++];

	rstack->tid = gettid();
	rstack->depth = mcount_rstack_idx - 1;
	rstack->dyn_idx = MCOUNT_INVALID_DYNIDX;
	rstack->parent_ip = parent;
	rstack->child_ip = child;
	rstack->start_time = mcount_gettime();
	rstack->end_time = 0;

	if (filtered > 0) {
		if (mcount_rstack_depth >= 0) {
			if (record_trace_data(rstack) < 0)
				pr_err("error during record");
		}
	} else
		mcount_rstack_idx -= MCOUNT_NOTRACE_IDX; /* see below */

	return 0;
}

unsigned long cygprof_exit(void)
{
	bool was_filtered = false;
	struct mcount_ret_stack *rstack;

	/*
	 * We subtracted big number for notrace filtered functions
	 * so that it can be identified when entering the exit handler.
	 */
	if (mcount_rstack_idx < 0) {
		mcount_rstack_idx += MCOUNT_NOTRACE_IDX;
		was_filtered = true;
	}

	if (mcount_rstack_depth++ < 0)
		was_filtered = true;

	if (mcount_rstack_idx <= 0)
		pr_err_ns("broken ret stack (%d)\n", mcount_rstack_idx);

	rstack = &mcount_rstack[--mcount_rstack_idx];

	pr_dbg2("<%d> X %lx\n", mcount_rstack_idx, rstack->parent_ip);

	if (rstack->depth != mcount_rstack_idx || rstack->end_time != 0)
		pr_err_ns("corrupted mcount ret stack found!\n");

	rstack->end_time = mcount_gettime();
	rstack->tid = gettid();

	if (!was_filtered) {
		if (record_trace_data(rstack) < 0)
			pr_err("error during record");
	}

	return rstack->parent_ip;
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

	if (should_skip_idx(child_idx))
		goto out;

	plthook_recursion_guard = true;

	sym = find_dynsym(&symtabs, child_idx);
	pr_dbg2("[%d] n %s\n", child_idx, sym->name);

	child_ip = sym ? sym->addr : 0;
	if (child_ip == 0) {
		pr_err_ns("invalid function idx found! (idx: %d, %#lx)\n",
			  (int) child_idx, child_idx);
	}

	if (mcount_entry(ret_addr, child_ip) == 0) {
		int idx = mcount_rstack_idx - 1;

		*ret_addr = (unsigned long)plthook_return;

		if (idx < 0)
			idx += MCOUNT_NOTRACE_IDX;

		if (idx >= MCOUNT_RSTACK_MAX)
			pr_err_ns("invalid rstack idx: %d\n", idx);

		mcount_rstack[idx].dyn_idx = child_idx;
	}

out:
	if (plthook_dynsym_resolved[child_idx])
		return plthook_dynsym_addr[child_idx];

	plthook_dynsym_addr[child_idx] = plthook_got_ptr[3 + child_idx];
	return 0;
}

unsigned long plthook_exit(void)
{
	unsigned long orig_ip = mcount_exit();
	int idx = mcount_rstack_idx;
	int dyn_idx;
	unsigned long new_addr;

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
	char *depth_str = getenv("FTRACE_DEPTH");
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
	load_symtabs(&symtabs, mcount_exename);

	ftrace_setup_filter(getenv("FTRACE_FILTER"), &symtabs,
			    &filter_trace, &has_filter);
	ftrace_setup_filter(getenv("FTRACE_NOTRACE"), &symtabs,
			    &filter_notrace, &has_notrace);
	ftrace_setup_filter_regex(getenv("FTRACE_FILTER_REGEX"), &symtabs,
				  &filter_trace, &has_filter);
	ftrace_setup_filter_regex(getenv("FTRACE_NOTRACE_REGEX"), &symtabs,
				  &filter_notrace, &has_notrace);

	if (depth_str)
		mcount_depth = strtol(depth_str, NULL, 0);

	if (getenv("FTRACE_PLTHOOK")) {
		setup_skip_idx(&symtabs);

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
	destroy_skip_idx();

	ftrace_cleanup_filter(&filter_trace);
	ftrace_cleanup_filter(&filter_notrace);
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
