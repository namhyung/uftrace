#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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

#include "mcount.h"
#include "symbol.h"
#include "utils.h"

__thread int mcount_rstack_idx;
__thread struct mcount_ret_stack *mcount_rstack;

static FILE *fout;
static int pfd = -1;
static bool tracing_enabled = true;
static bool mcount_setup_done;

static unsigned long *filter_trace;
static unsigned nr_filter;
static unsigned long *filter_notrace;
static unsigned nr_notrace;

static __thread bool plthook_recursion_guard;
unsigned long plthook_resolver_addr;

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

static int record_trace_data(void *buf, size_t size)
{
	int ret;

	assert(pfd >= 0 || fout != NULL);

	if (fout)
		ret = (fwrite(buf, size, 1, fout) == 1);
	else if (pfd >= 0)
		ret = (write(pfd, buf, size) == (ssize_t)size);
	else
		ret = 0;

	return ret - 1;
}

static void record_proc_maps(void)
{
	int fd, len;
	char buf[4096];

	fd = open("/proc/self/maps", O_RDONLY);
	if (fd < 0)
		pr_err("mcount: ERROR: cannot open proc maps file\n");

	if (record_trace_data(START_MAPS, sizeof(START_MAPS)) < 0)
		pr_err("mcount: ERROR: write proc maps failed\n");

	while ((len = read(fd, buf, sizeof(buf))) > 0) {
		if (record_trace_data(buf, len) < 0)
			pr_err("mcount: ERROR: write proc maps failed\n");
	}

	if (len < 0) {
		pr_log("mcount: error during read proc maps: %s\n",
		       strerror(errno));
	}

	if (record_trace_data(END_MAPS, sizeof(END_MAPS)) < 0)
		pr_err("mcount: ERROR: write proc maps failed\n");

	close(fd);
}

extern void __monstartup(unsigned long low, unsigned long high);

static void mcount_init_file(void)
{
	struct ftrace_file_header ffh = {
		.magic = FTRACE_MAGIC_STR,
		.version = FTRACE_FILE_VERSION,
		/* other fields are filled by ftrace record */
	};
	char *use_pipe = getenv("FTRACE_PIPE");
	char *filename = getenv("FTRACE_FILE");
	char *bufsize = getenv("FTRACE_BUFFER");
	char buf[256];

	/* This is for the case of library-only tracing */
	if (!mcount_setup_done)
		__monstartup(0, ~0);

	if (use_pipe && pfd >= 0)
		goto record;

	if (filename == NULL)
		filename = FTRACE_FILE_NAME;

	fout = fopen(filename, "wb");
	if (fout == NULL) {
		char *errmsg = strerror_r(errno, buf, sizeof(buf));
		if (errmsg == NULL)
			errmsg = filename;

		pr_err("mcount: ERROR: cannot create data file: %s\n", errmsg);
	}

	if (bufsize) {
		unsigned long size = strtoul(bufsize, NULL, 0);

		setvbuf(fout, NULL, size ? _IOFBF : _IONBF, size);
	}

record:
	if (getenv("FTRACE_LIBRARY_TRACE"))
		ffh.nr_maps = 1; /* just signal that it has maps data */

	if (record_trace_data(&ffh, sizeof(ffh)) < 0) {
		char *errmsg = strerror_r(errno, buf, sizeof(buf));
		if (errmsg == NULL)
			errmsg = filename;

		pr_err("mcount: ERROR: cannot write header info: %s\n", errmsg);
	}

	if (ffh.nr_maps)
		record_proc_maps();
}

static void mcount_prepare(void)
{
	static pthread_once_t once_control = PTHREAD_ONCE_INIT;

	mcount_rstack = xmalloc(MCOUNT_RSTACK_MAX * sizeof(*mcount_rstack));

	pthread_once(&once_control, mcount_init_file);
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

	if (!tracing_enabled)
		return -1;

	if (unlikely(mcount_rstack == NULL))
		mcount_prepare();

	if (mcount_rstack_idx >= MCOUNT_RSTACK_MAX) {
		pr_log("mcount: too deeply nested calls\n");
		return -1;
	}

	filtered = mcount_filter(child);
	if (filtered == 0)
		return -1;

	rstack = &mcount_rstack[mcount_rstack_idx++];

	rstack->tid = gettid();
	rstack->depth = mcount_rstack_idx - 1;
	rstack->parent_ip = parent;
	rstack->child_ip = child;
	rstack->start_time = mcount_gettime();
	rstack->end_time = 0;
	rstack->child_time = 0;

	if (filtered > 0)
		record_trace_data(rstack, sizeof(*rstack));
	else
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
		pr_err("mcount: ERROR: broken ret stack (%d)\n", mcount_rstack_idx);

	rstack = &mcount_rstack[--mcount_rstack_idx];

	if (rstack->tid != gettid() || rstack->depth != mcount_rstack_idx ||
	    rstack->end_time != 0) {
		pr_log("mcount: corrupted mcount ret stack found!\n");
		//exit(1);
	}

	rstack->end_time = mcount_gettime();

	if (!was_filtered)
		record_trace_data(rstack, sizeof(*rstack));

	if (mcount_rstack_idx > 0) {
		int idx = mcount_rstack_idx - 1;
		struct mcount_ret_stack *parent = &mcount_rstack[idx];

		parent->child_time += rstack->end_time - rstack->start_time;
	}
	return rstack->parent_ip;
}

static void mcount_finish(void)
{
	if (fout) {
		fclose(fout);
		fout = NULL;
	}

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
		pr_err("failed to allocate memory for %s\n", envstr);

	*size = nr;

	pos = str;
	for (i = 0; i < nr; i++) {
		(*filter)[i] = strtoul(pos, &pos, 16);
		if (*pos && *pos != ':')
			pr_err("invalid filter string for %s\n", envstr);

		pos++;
	}

	if (debug) {
		pr_dbg("%s: ", envstr);
		for (i = 0; i < nr; i++)
			pr_dbg(" 0x%lx", (*filter)[i]);
		pr_dbg("\n");
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
		pr_err("mcount: invalid memory access.. exiting.\n");
	}
}

extern void __attribute__((weak)) plt_hooker(void);

static int find_got(Elf_Data *dyn_data, size_t nr_dyn)
{
	size_t i;
	unsigned long *got;
	struct sigaction sa, old_sa;

	for (i = 0; i < nr_dyn; i++) {
		GElf_Dyn dyn;

		if (gelf_getdyn(dyn_data, i, &dyn) == NULL)
			return -1;

		if (dyn.d_tag != DT_PLTGOT)
			continue;

		got_addr = (unsigned long)dyn.d_un.d_val;
		got = (void *)got_addr;
		plthook_resolver_addr = got[2];

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
			pr_log("mcount: error during install sig handler\n");
			return -1;
		}

		got[2] = (unsigned long)plt_hooker;

		if (sigaction(SIGSEGV, &old_sa, NULL) < 0) {
			pr_log("mcount: error during recover sig handler\n");
			return -1;
		}

		if (segv_handled) {
			mprotect((void *)(got_addr & ~0xFFF), sizeof(long)*3,
				 PROT_READ);
		}

		pr_dbg("mcount: found GOT at %p (resolver: %#lx)\n",
		       got, plthook_resolver_addr);

		break;
	}
	return 0;
}

static int hook_pltgot(void)
{
	int fd;
	int ret = -1;
	char buf[1024];
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Scn *sec;
	GElf_Shdr shdr;
	Elf_Data *data;
	size_t shstr_idx;
	size_t i;

	int len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
	if (len == -1) {
		pr_log("mcount: error during read executable link\n");
		return -1;
	}
	buf[len] = '\0';

	pr_dbg("opening executable image: %s\n", buf);

	fd = open(buf, O_RDONLY);
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
	pr_log("mcount: %s\n", elf_errmsg(elf_errno()));

	goto out;
}

unsigned long plthook_entry(unsigned long parent_ip, unsigned long child_idx,
			    unsigned long module_id)
{
	struct sym *sym;
	unsigned long child_ip;
	long ret;

	/*
	 * There was a recursion like below:
	 *
	 * plthook_entry -> mcount_entry -> mcount_prepare -> xmalloc
	 *   -> plthook_entry
	 */
	if (plthook_recursion_guard)
		return -1;

	if (should_skip_idx(child_idx))
		return -1;

	plthook_recursion_guard = true;

	sym = find_dynsym(child_idx);
	pr_dbg("%s: %s\n", __func__, sym->name);

	child_ip = sym ? sym->addr : 0;
	if (child_ip == 0) {
		pr_err("mcount: ERROR: invalid function idx found! (idx: %d, %#lx)\n",
		       (int) child_idx, child_idx);
	}

	ret = mcount_entry(parent_ip, child_ip);
	return ret;
}

unsigned long plthook_exit(void)
{
	unsigned long orig_ip = mcount_exit();

	plthook_recursion_guard = false;

	return orig_ip;
}

static void stop_trace(int sig)
{
	tracing_enabled = false;

	mcount_finish();
}

/*
 * external interfaces
 */
void __attribute__((visibility("default")))
__monstartup(unsigned long low, unsigned long high)
{
	char *pipe_fd = getenv("FTRACE_PIPE");
	char *log_fd = getenv("FTRACE_LOGFD");
	struct stat statbuf;

	if (log_fd) {
		logfd = strtol(log_fd, NULL, 0);

		/* minimal sanity check */
		if (fstat(logfd, &statbuf) < 0)
			logfd = STDERR_FILENO;
	}

	if (pipe_fd) {
		pfd = strtol(pipe_fd, NULL, 0);

		/* minimal sanity check */
		if (fstat(pfd, &statbuf) < 0)
			pfd = -1;
	}

	if (getenv("FTRACE_DEBUG"))
		debug = true;

	mcount_setup_filter("FTRACE_FILTER", &filter_trace, &nr_filter);
	mcount_setup_filter("FTRACE_NOTRACE", &filter_notrace, &nr_notrace);

	if (getenv("FTRACE_PLTHOOK")) {
		int len;
		char buf[1024];

		len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
		if (len < 0)
			exit(1);
		buf[len] = '\0';

		load_dynsymtab(buf);
		setup_skip_idx();

		if (hook_pltgot() < 0)
			pr_dbg("mcount: error when hooking plt: skipping...\n");
	}

	if (getenv("FTRACE_SIGNAL")) {
		char *str = getenv("FTRACE_SIGNAL");
		int sig = strtol(str, NULL, 0);

		signal(sig, stop_trace);
	}

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
