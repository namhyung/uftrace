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
#include <gelf.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT  "mcount"

#include "mcount.h"
#include "symbol.h"
#include "utils.h"

__thread int mcount_rstack_idx;
__thread struct mcount_ret_stack *mcount_rstack;

static int pfd = -1;
static bool mcount_setup_done;

static unsigned long *filter_trace;
static unsigned nr_filter;
static unsigned long *filter_notrace;
static unsigned nr_notrace;

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

static int gettid(void)
{
	return syscall(SYS_gettid);
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


#define SHMEM_BUFFER_SIZE  (128 * 1024)
#define SHMEM_SESSION_FMT  "/ftrace-%s-%d-%03d" /* session-id, tid, seq */

struct mcount_shmem_buffer {
	unsigned size;
	char data[];
};

static pthread_key_t shmem_key;
static __thread int shmem_seqnum;
static __thread struct mcount_shmem_buffer *shmem_buffer;

static void get_new_shmem_buffer(void)
{
	char buf[128];
	int fd;

	snprintf(buf, sizeof(buf), SHMEM_SESSION_FMT,
		 session_name(), gettid(), shmem_seqnum++);

	pr_dbg("opening shmem buffer: %s\n", buf);

	fd = shm_open(buf, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		pr_err("open shmem buffer");

	if (ftruncate(fd, SHMEM_BUFFER_SIZE) < 0)
		pr_err("resizing shmem buffer");

	shmem_buffer = mmap(NULL, SHMEM_BUFFER_SIZE, PROT_READ | PROT_WRITE,
			    MAP_SHARED, fd, 0);
	if (shmem_buffer == MAP_FAILED)
		pr_err("mmap shmem buffer");

	close(fd);

	shmem_buffer->size = 0;

	if (pfd >= 0) {
		ssize_t len = strlen(buf);
		const struct ftrace_msg msg = {
			.magic = FTRACE_MSG_MAGIC,
			.type = FTRACE_MSG_REC_START,
			.len = len,
		};

		/* combine msg header and data for atomicity */
		memmove(buf+sizeof(msg), buf, len + 1);
		memcpy(buf, &msg, sizeof(msg));

		len += sizeof(msg);
		if (write(pfd, buf, len) != len)
			pr_err("writing shmem name to pipe");
	}
}

static void finish_shmem_buffer(void)
{
	char buf[64];

	if (shmem_buffer == NULL)
		return;

	snprintf(buf, sizeof(buf), SHMEM_SESSION_FMT,
		 session_name(), gettid(), shmem_seqnum - 1);

	munmap(shmem_buffer, SHMEM_BUFFER_SIZE);
	shmem_buffer = NULL;

	if (pfd >= 0) {
		ssize_t len = strlen(buf);
		const struct ftrace_msg msg = {
			.magic = FTRACE_MSG_MAGIC,
			.type = FTRACE_MSG_REC_END,
			.len = len,
		};

		/* combine msg header and data for atomicity */
		memmove(buf+sizeof(msg), buf, len + 1);
		memcpy(buf, &msg, sizeof(msg));

		len += sizeof(msg);
		if (write(pfd, buf, len) != len)
			pr_err("writing shmem name to pipe");
	}
}

/* to be used by pthread_create_key() */
static void shmem_dtor(void *unused)
{
	finish_shmem_buffer();
}

static int record_mmap_data(void *buf, size_t size)
{
	assert(size < SHMEM_BUFFER_SIZE);

	if (shmem_buffer == NULL ||
	    shmem_buffer->size + size > SHMEM_BUFFER_SIZE - sizeof(*shmem_buffer)) {
		finish_shmem_buffer();
		get_new_shmem_buffer();
	}

	memcpy(shmem_buffer->data + shmem_buffer->size, buf, size);
	shmem_buffer->size += size;
	return 0;
}

static int record_trace_data(void *buf, size_t size)
{
	pr_dbg2("%d recording %zd bytes\n", gettid(), size);

	return record_mmap_data(buf, size);
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
	const struct ftrace_msg msg = {
		.magic = FTRACE_MSG_MAGIC,
		.type = FTRACE_MSG_SESSION,
		.len = sizeof(sess) + sess.namelen,
	};
	int len = sizeof(msg) + msg.len;
	char buf[len];
	char *ptr = buf;

	if (pfd < 0)
		return;

	memcpy(sess.sid, sess_id, sizeof(sess.sid));

	memcpy(ptr, &msg, sizeof(msg));
	ptr += sizeof(msg);
	memcpy(ptr, &sess, sizeof(sess));
	ptr += sizeof(sess);
	memcpy(ptr, mcount_exename, sess.namelen);

	if (write(pfd, buf, len) != len)
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
	const struct ftrace_msg msg = {
		.magic = FTRACE_MSG_MAGIC,
		.type = FTRACE_MSG_TID,
		.len = sizeof(tmsg),
	};
	char buf[128];
	int len = sizeof(msg) + sizeof(tmsg);

	mcount_rstack = xmalloc(MCOUNT_RSTACK_MAX * sizeof(*mcount_rstack));

	pthread_once(&once_control, mcount_init_file);

	/* time should be get after session message sent */
	tmsg.time = mcount_gettime();

	memcpy(buf, &msg, sizeof(msg));
	memcpy(buf + sizeof(msg), &tmsg, sizeof(tmsg));

	if (write(pfd, buf, len) != len)
		pr_err("write tid info failed");
}

static bool mcount_match(unsigned long ip1, unsigned long ip2)
{
	return ip1 == ip2;
}

/*
 * return 1 if it should be traced, 0 otherwise.
 * return -1 if it's filtered at notrace - needs special treatment.
 */
static int mcount_filter(unsigned long ip)
{
	/*
	 * mcount_rstack_idx > 0 means it's now traced (not filtered)
	 */
	int ret = mcount_rstack_idx >= 0;
	unsigned i;

	if (mcount_rstack_idx < 0)
		return 0;

	if (nr_filter && mcount_rstack_idx == 0) {
		for (i = 0; i < nr_filter; i++) {
			if (mcount_match(filter_trace[i], ip))
				return 1;
		}
		ret = 0;
	}

	if (nr_notrace && ret) {
		for (i = 0; i < nr_notrace; i++) {
			if (mcount_match(filter_notrace[i], ip))
				return -1;
		}
	}
	return ret;
}

int mcount_entry(unsigned long parent, unsigned long child)
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
	if (filtered == 0)
		return -1;

	rstack = &mcount_rstack[mcount_rstack_idx++];

	rstack->tid = gettid();
	rstack->depth = mcount_rstack_idx - 1;
	rstack->dyn_idx = MCOUNT_INVALID_DYNIDX;
	rstack->parent_ip = parent;
	rstack->child_ip = child;
	rstack->start_time = mcount_gettime();
	rstack->end_time = 0;
	rstack->child_time = 0;

	if (filtered > 0) {
		if (record_trace_data(rstack, sizeof(*rstack)) < 0)
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

	pr_dbg2("<%d> X %lx\n", mcount_rstack_idx - 1,
		mcount_rstack[mcount_rstack_idx - 1].parent_ip);

	if (mcount_rstack_idx <= 0)
		pr_err_ns("broken ret stack (%d)\n", mcount_rstack_idx);

	rstack = &mcount_rstack[--mcount_rstack_idx];

	if (rstack->depth != mcount_rstack_idx || rstack->end_time != 0)
		pr_err_ns("corrupted mcount ret stack found!\n");

	rstack->end_time = mcount_gettime();
	rstack->tid = gettid();

	if (!was_filtered) {
		if (record_trace_data(rstack, sizeof(*rstack)) < 0)
			pr_err("error during record");
	}

	if (mcount_rstack_idx > 0) {
		int idx = mcount_rstack_idx - 1;
		struct mcount_ret_stack *parent = &mcount_rstack[idx];

		parent->child_time += rstack->end_time - rstack->start_time;
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

static void mcount_setup_filter(char *envstr, unsigned long **filter, unsigned *size)
{
	unsigned int i, nr;
	char *str = getenv(envstr);
	char *pos;

	if (str == NULL)
		return;

	pos = str;
	nr = 0;
	while (pos) {
		nr++;
		pos = strchr(pos, ':');
		if (pos)
			pos++;
	}

	*filter = malloc(sizeof(long) * nr);
	if (*filter == NULL)
		pr_err("failed to allocate memory for %s", envstr);

	*size = nr;

	pos = str;
	for (i = 0; i < nr; i++) {
		(*filter)[i] = strtoul(pos, &pos, 16);
		if (*pos && *pos != ':')
			pr_err_ns("invalid filter string for %s\n", envstr);

		pos++;
	}

	if (debug) {
		pr_dbg("%s: ", envstr);
		for (i = 0; i < nr; i++)
			pr_cont(" 0x%lx", (*filter)[i]);
		pr_cont("\n");
	}
}

static void mcount_cleanup_filter(unsigned long **filter, unsigned *size)
{
	free(*filter);
	*filter = NULL;
	*size = 0;
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
	unsigned long parent_ip;
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

	parent_ip = *ret_addr;

	if (mcount_entry(parent_ip, child_ip) == 0) {
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
	const struct ftrace_msg msg = {
		.magic = FTRACE_MSG_MAGIC,
		.type = FTRACE_MSG_FORK_START,
		.len = sizeof(tmsg),
	};
	int len = sizeof(msg) + sizeof(tmsg);
	char buf[len];

	memcpy(buf, &msg, sizeof(msg));
	memcpy(buf + sizeof(msg), &tmsg, sizeof(tmsg));

	if (pfd >= 0 && write(pfd, &buf, len) != len)
		pr_err("write fork info failed");
}

static void atfork_child_handler(void)
{
	struct ftrace_msg_task tmsg = {
		.time = mcount_gettime(),
		.pid = getppid(),
		.tid = getpid(),
	};
	const struct ftrace_msg msg = {
		.magic = FTRACE_MSG_MAGIC,
		.type = FTRACE_MSG_FORK_END,
		.len = sizeof(tmsg),
	};
	int len = sizeof(msg) + sizeof(tmsg);
	char buf[len];

	memcpy(buf, &msg, sizeof(msg));
	memcpy(buf + sizeof(msg), &tmsg, sizeof(tmsg));

	if (pfd >= 0 && write(pfd, buf, len) != len)
		pr_err("write fork info failed");

	shmem_seqnum = 0;
	get_new_shmem_buffer();
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
	struct stat statbuf;

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

	mcount_setup_filter("FTRACE_FILTER", &filter_trace, &nr_filter);
	mcount_setup_filter("FTRACE_NOTRACE", &filter_notrace, &nr_notrace);

	read_exename();

	if (getenv("FTRACE_PLTHOOK")) {
		load_dynsymtab(&symtabs, mcount_exename);
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

	mcount_cleanup_filter(&filter_trace, &nr_filter);
	mcount_cleanup_filter(&filter_notrace, &nr_notrace);
}
