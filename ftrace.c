#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <errno.h>
#include <argp.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <gelf.h>

#include "mcount.h"
#include "symbol.h"
#include "rbtree.h"
#include "utils.h"

const char *argp_program_version = "ftrace v0.1";
const char *argp_program_bug_address = "Namhyung Kim <namhyung@gmail.com>";

#define OPT_flat 	301
#define OPT_plthook 	302
#define OPT_symbols	303
#define OPT_daemon	304
#define OPT_signal	305
#define OPT_logfile	306
#define OPT_library	307
#define OPT_threads	308

static struct argp_option ftrace_options[] = {
	{ "library-path", 'L', "PATH", 0, "Load libraries from this PATH" },
	{ "filter", 'F', "FUNC[,FUNC,...]", 0, "Only trace those FUNCs" },
	{ "notrace", 'N', "FUNC[,FUNC,...]", 0, "Don't trace those FUNCs" },
	{ "debug", 'd', 0, 0, "Print debug messages" },
	{ "file", 'f', "FILE", 0, "Use this FILE instead of ftrace.data" },
	{ "flat", OPT_flat, 0, 0, "Use flat output format" },
	{ "no-plthook", OPT_plthook, 0, 0, "Don't hook library function calls" },
	{ "symbols", OPT_symbols, 0, 0, "Print symbol tables" },
	{ "buffer", 'b', "SIZE", 0, "Size of tracing buffer" },
	{ "daemon", OPT_daemon, 0, 0, "Trace daemon process" },
	{ "signal", OPT_signal, "SIGNAL", 0, "Signal number to send to child (daemon)" },
	{ "logfile", OPT_logfile, "FILE", 0, "Save log messages to this file" },
	{ "library", OPT_library, 0, 0, "Also trace internal library functions" },
	{ "threads", OPT_threads, 0, 0, "Report thread stats instead" },
	{ "tid", 'T', "TID[,TID,...]", 0, "Only replay those tasks" },
	{ 0 }
};

#define FTRACE_MODE_INVALID 0
#define FTRACE_MODE_RECORD  1
#define FTRACE_MODE_REPLAY  2
#define FTRACE_MODE_LIVE    3
#define FTRACE_MODE_REPORT  4
#define FTRACE_MODE_INFO    5

#define FTRACE_MODE_DEFAULT  FTRACE_MODE_LIVE

struct opts {
	char *lib_path;
	char *filter;
	char *notrace;
	char *tid;
	char *exename;
	char *dirname;
	char *logfile;
	int mode;
	int idx;
	int signal;
	unsigned long bsize;
	bool flat;
	bool want_plthook;
	bool print_symtab;
	bool daemon;
	bool library;
	bool report_thread;
};

static unsigned long parse_size(char *str)
{
	unsigned long size;
	char *unit;

	size = strtoul(str, &unit, 0);
	switch (*unit) {
	case '\0':
		break;
	case 'k':
	case 'K':
		size <<= 10;
		break;
	case 'm':
	case 'M':
		size <<= 20;
		break;
	case 'g':
	case 'G':
		size <<= 30;
		break;

	default:
		fprintf(stderr, "invalid size unit: %s\n", unit);
		break;
	}

	return size;
}

static error_t parse_option(int key, char *arg, struct argp_state *state)
{
	struct opts *opts = state->input;

	switch (key) {
	case 'L':
		opts->lib_path = arg;
		break;

	case 'F':
		opts->filter = arg;
		break;

	case 'N':
		opts->notrace = arg;
		break;

	case 'T':
		opts->tid = arg;
		break;

	case 'd':
		debug++;
		break;

	case 'f':
		opts->dirname = arg;
		break;

	case 'b':
		opts->bsize = parse_size(arg);
		break;

	case OPT_flat:
		opts->flat = true;
		break;

	case OPT_plthook:
		opts->want_plthook = false;
		break;

	case OPT_symbols:
		opts->print_symtab = true;
		break;

	case OPT_daemon:
		opts->daemon = true;
		break;

	case OPT_signal:
		opts->signal = strtol(arg, NULL, 0);
		break;

	case OPT_logfile:
		opts->logfile = arg;
		break;

	case OPT_library:
		opts->library = true;
		break;

	case OPT_threads:
		opts->report_thread = true;
		break;

	case ARGP_KEY_ARG:
		if (state->arg_num) {
			/*
			 * This is a second non-option argument.
			 * Returning ARGP_ERR_UNKNOWN will pass control to
			 * the ARGP_KEY_ARGS case.
			 */
			return ARGP_ERR_UNKNOWN;
		}
		if (!strcmp("record", arg))
			opts->mode = FTRACE_MODE_RECORD;
		else if (!strcmp("replay", arg))
			opts->mode = FTRACE_MODE_REPLAY;
		else if (!strcmp("live", arg))
			opts->mode = FTRACE_MODE_LIVE;
		else if (!strcmp("report", arg))
			opts->mode = FTRACE_MODE_REPORT;
		else if (!strcmp("info", arg))
			opts->mode = FTRACE_MODE_INFO;
		else
			return ARGP_ERR_UNKNOWN; /* almost same as fall through */
		break;

	case ARGP_KEY_ARGS:
		/*
		 * process remaining non-option arguments
		 */
		if (opts->mode == FTRACE_MODE_INVALID)
			opts->mode = FTRACE_MODE_DEFAULT;

		opts->exename = state->argv[state->next];
		opts->idx = state->next;
		break;

	case ARGP_KEY_NO_ARGS:
	case ARGP_KEY_END:
		if (state->arg_num < 1)
			argp_usage(state);

		if (opts->exename == NULL) {
			switch (opts->mode) {
			case FTRACE_MODE_RECORD:
			case FTRACE_MODE_LIVE:
				argp_usage(state);
				break;
			default:
				/* will be set after read_ftrace_info() */
				break;
			}
		}
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int command_record(int argc, char *argv[], struct opts *opts);
static int command_replay(int argc, char *argv[], struct opts *opts);
static int command_live(int argc, char *argv[], struct opts *opts);
static int command_report(int argc, char *argv[], struct opts *opts);
static int command_info(int argc, char *argv[], struct opts *opts);

static int open_data_file(struct opts *opts, struct ftrace_file_handle *handle);
static void close_data_file(struct opts *opts, struct ftrace_file_handle *handle);

int main(int argc, char *argv[])
{
	struct opts opts = {
		.mode = FTRACE_MODE_INVALID,
		.dirname = FTRACE_DIR_NAME,
		.want_plthook = true,
		.bsize = ~0UL,
		.signal = SIGPROF,
	};
	struct argp argp = {
		.options = ftrace_options,
		.parser = parse_option,
		.args_doc = "[record|replay|live|report|info] [<command> args...]",
		.doc = "ftrace -- a function tracer",
	};

	argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &opts);

	if (opts.logfile) {
		logfd = open(opts.logfile, O_WRONLY | O_CREAT, 0644);
		if (logfd < 0) {
			perror("ftrace: ERROR: cannot open log file");
			exit(1);
		}
	}

	if (opts.print_symtab) {
		if (opts.exename == NULL) {
			struct ftrace_file_handle handle;

			if (open_data_file(&opts, &handle) < 0)
				exit(1);
		}

		load_symtabs(opts.exename);
		print_symtabs();
		unload_symtabs();
		exit(0);
	}

	switch (opts.mode) {
	case FTRACE_MODE_RECORD:
		command_record(argc, argv, &opts);
		break;
	case FTRACE_MODE_REPLAY:
		command_replay(argc, argv, &opts);
		break;
	case FTRACE_MODE_LIVE:
		command_live(argc, argv, &opts);
		break;
	case FTRACE_MODE_REPORT:
		command_report(argc, argv, &opts);
		break;
	case FTRACE_MODE_INFO:
		command_info(argc, argv, &opts);
		break;
	case FTRACE_MODE_INVALID:
		break;
	}

	if (opts.logfile)
		close(logfd);

	return 0;
}

static int write_all(int fd, void *buf, size_t size)
{
	int ret;

	while (size) {
		ret = write(fd, buf, size);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			return -1;

		buf += ret;
		size -= ret;
	}
	return 0;
}

static void build_addrlist(char *buf, char *symlist)
{
	char *p = symlist;
	char *fname = strtok(p, ",:");

	buf[0] = '\0';
	while (fname) {
		struct sym *sym = find_symname(fname);

		if (sym) {
			char tmp[64];

			snprintf(tmp, sizeof(tmp), "%s%#lx",
				 p ? "" : ":", sym->addr);
			strcat(buf, tmp);
		} else {
			pr_dbg("ftrace: cannot find symbol: %s\n", fname);
			pr_dbg("ftrace: skip setting filter..\n");
		}

		p = NULL;
		fname = strtok(p, ",:");
	}
}

static void setup_child_environ(struct opts *opts, int pfd)
{
	char buf[4096];
	const char *old_preload = getenv("LD_PRELOAD");
	const char *old_libpath = getenv("LD_LIBRARY_PATH");

	if (find_symname("__cyg_profile_func_enter"))
		strcpy(buf, "libcygprof.so");
	else
		strcpy(buf, "libmcount.so");

	if (old_preload) {
		strcat(buf, ":");
		strcat(buf, old_preload);
	}
	setenv("LD_PRELOAD", buf, 1);

	if (opts->lib_path) {
		strcpy(buf, opts->lib_path);
		strcat(buf, ":");
	} else {
		/* to make strcat() work */
		buf[0] = '\0';
	}

#ifdef INSTALL_LIB_PATH
	strcat(buf, INSTALL_LIB_PATH);
#endif

	if (old_libpath) {
		strcat(buf, ":");
		strcat(buf, old_libpath);
	}
	setenv("LD_LIBRARY_PATH", buf, 1);

	if (opts->filter) {
		build_addrlist(buf, opts->filter);
		setenv("FTRACE_FILTER", buf, 1);
	}

	if (opts->notrace) {
		build_addrlist(buf, opts->notrace);
		setenv("FTRACE_NOTRACE", buf, 1);
	}

	if (opts->want_plthook) {
		setenv("FTRACE_PLTHOOK", "1", 1);
	}

	if (strcmp(opts->dirname, FTRACE_DIR_NAME))
		setenv("FTRACE_DIR", opts->dirname, 1);

	if (opts->bsize != ~0UL) {
		snprintf(buf, sizeof(buf), "%lu", opts->bsize);
		setenv("FTRACE_BUFFER", buf, 1);
	}

	if (opts->daemon) {
		snprintf(buf, sizeof(buf), "%d", opts->signal);
		setenv("FTRACE_SIGNAL", buf, 1);
	}

	if (opts->logfile) {
		snprintf(buf, sizeof(buf), "%d", logfd);
		setenv("FTRACE_LOGFD", buf, 1);
	}

	snprintf(buf, sizeof(buf), "%d", pfd);
	setenv("FTRACE_PIPE", buf, 1);
	setenv("FTRACE_SHMEM", "1", 1);

	if (debug) {
		snprintf(buf, sizeof(buf), "%d", debug);
		setenv("FTRACE_DEBUG", buf, 1);
	}
}

static uint64_t calc_feat_mask(struct opts *opts)
{
	uint64_t features = 0;

	if (opts->want_plthook)
		features |= 1U << PLTHOOK;
	if (opts->daemon)
		features |= 1U << DAEMON_MODE;
	if (opts->library)
		features |= 1U << LIBRARY_MODE;

	return features;
}

static int fill_file_header(struct opts *opts, int status, char *buf, size_t size)
{
	int fd, efd;
	int ret = -1;
	struct ftrace_file_header hdr;
	Elf *elf;
	GElf_Ehdr ehdr;

	snprintf(buf, size, "%s/info", opts->dirname);
	pr_dbg("fill header (metadata) info in %s\n", buf);

	fd = open(buf, O_WRONLY | O_CREAT| O_TRUNC, 0644);
	if (fd < 0) {
		pr_log("cannot open info file: %s\n", strerror(errno));
		return -1;
	}

	efd = open(opts->exename, O_RDONLY);
	if (efd < 0)
		goto close_fd;

	elf_version(EV_CURRENT);

	elf = elf_begin(efd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto close_efd;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto close_elf;

	strncpy(hdr.magic, FTRACE_MAGIC_STR, FTRACE_MAGIC_LEN);
	hdr.version = FTRACE_FILE_VERSION;
	hdr.header_size = sizeof(hdr);
	hdr.endian = ehdr.e_ident[EI_DATA];
	hdr.class = ehdr.e_ident[EI_CLASS];
	hdr.feat_mask = calc_feat_mask(opts);
	hdr.info_mask = 0;
	hdr.unused = 0;

	if (write(fd, &hdr, sizeof(hdr)) != (int)sizeof(hdr))
		pr_err("writing header info failed: %s\n", strerror(errno));

	fill_ftrace_info(&hdr.info_mask, fd, opts->exename, elf, status);

try_write:
	ret = pwrite(fd, &hdr, sizeof(hdr), 0);
	if (ret != (int)sizeof(hdr)) {
		static int retry = 0;

		if (ret > 0 && retry++ < 3)
			goto try_write;

		pr_log("writing header info failed.\n");
		elf_end(elf);
		goto close_efd;
	}

	ret = 0;

close_elf:
	if (ret < 0) {
		pr_log("error during ELF processing: %s\n",
		       elf_errmsg(elf_errno()));
	}
	elf_end(elf);
close_efd:
	close(efd);
close_fd:
	close(fd);

	return ret;
}

static const char mcount_msg[] =
	"ftrace: ERROR: Can't find '%s' symbol in the '%s'.\n"
	"\tIt seems not to be compiled with -pg or -finstrument-functions flag\n"
	"\twhich generates traceable code.  Please check your binary file.\n";

static volatile bool done;

static void sighandler(int sig)
{
	done = true;
}

static int tgkill(int tgid, int tid, int sig)
{
	return syscall(SYS_tgkill, tgid, tid, sig);
}

#define SHMEM_BUFFER_SIZE  (128 * 1024)
#define SHMEM_NAME_SIZE (64 - (int)sizeof(void*))

struct shmem_list {
	struct shmem_list *next;
	char id[SHMEM_NAME_SIZE];
};

struct shmem_buffer {
	unsigned size;
	char data[];
};

static struct shmem_list *shmem_list_head;

static char *make_disk_name(char *buf, size_t size, const char *dirname, char *id)
{
	char *ptr;
	char *tid;

	/*
	 * extract tid part only from "/ftrace-SESSION-TID-SEQ".
	 */
	tid = strchr(id, '-');
	assert(tid);

	tid++;

	tid = strchr(tid, '-');
	assert(tid);

	tid++;

	ptr = strchr(tid, '-');
	assert(ptr);

	*ptr = '\0';
	snprintf(buf, size, "%s/%s.dat", dirname, tid);
	*ptr = '-';

	/* XXX */
	snprintf(buf, size, "%s/trace.dat", dirname);

	return buf;
}

static int record_mmap_file(const char *dirname, char *sess_id)
{
	int fd;
	char buf[128];
	char *ptr;
	size_t size;
	struct shmem_buffer *shmem_buf;

	/* write (append) it to disk */
	fd = shm_open(sess_id, O_RDONLY, 0400);
	if (fd < 0)
		pr_err("ftrace: ERROR: open shmem buffer\n");

	shmem_buf = mmap(NULL, SHMEM_BUFFER_SIZE, PROT_READ,
			 MAP_SHARED, fd, 0);
	if (shmem_buf == MAP_FAILED)
		pr_err("ftrace: ERROR: mmap shmem buffer\n");

	close(fd);

	fd = open(make_disk_name(buf, sizeof(buf), dirname, sess_id),
		  O_WRONLY | O_CREAT | O_TRUNC, 0644);		  
	if (fd < 0)
		pr_err("ftrace: ERROR: open disk file\n");

	ptr  = shmem_buf->data;
	size = shmem_buf->size;

	if (write_all(fd, ptr, size) < 0)
		pr_err("ftrace: ERROR: write shmem buffer\n");

	close(fd);

	munmap(shmem_buf, SHMEM_BUFFER_SIZE);

	/* it's no longer used */
	shm_unlink(sess_id);
	return 0;
}

static void read_record_mmap(int pfd, const char *dirname)
{
	int ret;
	char buf[128];
	struct shmem_list *sl;

	ret = read(pfd, buf, sizeof(buf)-1);
	if (ret < 0) {
		if (errno == EINTR)
			return;

		pr_err("ftrace: ERROR: reading pipe failed: %s\n",
		       strerror(errno));
	}

	buf[ret] = '\0';
	pr_dbg("reading from pipe: %s\n", buf);

	if (buf[0] == 'S') {
		sl = xmalloc(sizeof(*sl));
		strncpy(sl->id, &buf[2], SHMEM_NAME_SIZE);

		/* link to shmem_list */
		sl->next = shmem_list_head;
		shmem_list_head = sl;
	} else {
		struct shmem_list **psl = &shmem_list_head;

		assert(buf[0] == 'E');

		/* remove from shmem_list */
		while (*psl) {
			sl = *psl;

			if (!strncmp(sl->id, &buf[2], SHMEM_NAME_SIZE)) {
				*psl = sl->next;
			}

			psl = &sl->next;
		}

		record_mmap_file(dirname, &buf[2]);
	}
}

static void flush_shmem_list(char *dirname)
{
	struct shmem_list *sl;

	/* flush remaining list (due to abnormal termination) */
	sl = shmem_list_head;
	while (sl) {
		struct shmem_list *tmp = sl;
		sl = sl->next;

		pr_dbg("flushing %s\n", tmp->id);

		record_mmap_file(dirname, tmp->id);
		free(tmp);
	}
	shmem_list_head = NULL;
}

static int remove_directory(char *dirname)
{
	DIR *dp;
	struct dirent *ent;
	char buf[PATH_MAX];

	dp = opendir(dirname);
	if (dp == NULL)
		return -1;

	pr_dbg("ftrace: removing %s directory\n", dirname);

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", dirname, ent->d_name);
		unlink(buf);
	}

	closedir(dp);
	rmdir(dirname);
	return 0;
}

static int command_record(int argc, char *argv[], struct opts *opts)
{
	int pid;
	int status;
	char buf[4096];
	const char *profile_funcs[] = {
		"mcount",
		"__fentry__",
		"__gnu_mcount_nc",
		"__cyg_profile_func_enter",
	};
	size_t i;
	int pfd[2];
	struct sigaction sa;

	snprintf(buf, sizeof(buf), "%s.old", opts->dirname);

	if (!access(buf, F_OK))
		remove_directory(buf);

	/* don't care about the failure */
	if (rename(opts->dirname, buf) < 0)
		pr_log("ftrace: rename %s -> %s failed: %s\n",
		       opts->dirname, buf, strerror(errno));

	load_symtabs(opts->exename);

	for (i = 0; i < ARRAY_SIZE(profile_funcs); i++) {
		if (find_symname(profile_funcs[i]))
			break;
	}

	if (i == ARRAY_SIZE(profile_funcs) && !opts->library)
		pr_err(mcount_msg, "mcount", opts->exename);

	if (pipe(pfd) < 0) {
		pr_err("ftrace: ERROR: cannot setup internal pipe: %s\n",
		       strerror(errno));
	}

	mkdir(opts->dirname, 0755);

	fflush(stdout);

	pid = fork();
	if (pid < 0) {
		pr_err("ftrace: ERROR: cannot start child process: %s\n",
		       strerror(errno));
	}

	if (pid == 0) {
		close(pfd[0]);

		setup_child_environ(opts, pfd[1]);

		/*
		 * I don't think the traced binary is in PATH.
		 * So use plain 'execv' rather than 'execvp'.
		 */
		execv(opts->exename, &argv[opts->idx]);
		abort();
	}

	close(pfd[1]);

	sa.sa_handler = sighandler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (!opts->daemon)
		sigaction(SIGCHLD, &sa, NULL);

	while (!done) {
		read_record_mmap(pfd[0], opts->dirname);
	}

	if (opts->daemon) {
		tgkill(pid, pid, opts->signal);
		usleep(1000);
	} else {
		waitpid(pid, &status, 0);
		if (WIFSIGNALED(status)) {
			pr_dbg("child (%s) was terminated by signal: %d\n",
			       opts->exename, WTERMSIG(status));
		} else {
			pr_dbg("child terminated with %d\n", WEXITSTATUS(status));
		}
	}

	flush_shmem_list(opts->dirname);

	if (fill_file_header(opts, status, buf, sizeof(buf)) < 0)
		pr_err("ftrace: ERROR: cannot generate data file\n");

	/*
	 * Do not unload symbol tables.  It might save some time when used by
	 * 'live' command as it also need to load the symtabs again.
	 */
	//unload_symtabs();
	return 0;
}

static struct ftrace_proc_maps *proc_maps;

static int open_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	int ret = -1;
	FILE *fp;
	char buf[PATH_MAX];
	const char msg[] = "ftrace: ERROR: Was '%s' compiled with -pg or\n"
		"\t-finstrument-functions flag and ran with ftrace record?\n";

	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);

	fp = fopen(buf, "rb");
	if (fp == NULL) {
		if (errno == ENOENT) {
			pr_log("ftrace: cannot find %s file!\n", buf);

			if (opts->exename)
				pr_err(msg, opts->exename);
		} else {
			pr_err("ftrace: ERROR: cannot open %s file: %s\n",
			       buf, strerror(errno));
		}
		goto out;
	}

	handle->fp = fp;

	if (fread(&handle->hdr, sizeof(handle->hdr), 1, fp) != 1)
		pr_err("ftrace: ERROR: cannot read header data\n");

	if (memcmp(handle->hdr.magic, FTRACE_MAGIC_STR, FTRACE_MAGIC_LEN)) {
		fclose(fp);
		pr_err("ftrace: ERROR: invalid magic string found!\n");
	}
	if (handle->hdr.version < FTRACE_FILE_VERSION_MIN) {
		fclose(fp);
		pr_err("ftrace: ERROR: invalid vergion number found!\n");
	}

	if (read_ftrace_info(handle->hdr.info_mask, handle) < 0)
		pr_err("ftrace: ERROR: cannot read ftrace header info!\n");

	fclose(fp);

	if (opts->exename == NULL)
		opts->exename = handle->info.exename;

	snprintf(buf, sizeof(buf), "%s/maps", opts->dirname);

	fp = fopen(buf, "rb");
	if (fp == NULL)
		pr_err("ftrace: ERROR: cannot open maps file\n");

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		unsigned long start, end;
		char prot[5];
		char path[PATH_MAX];
		size_t namelen;
		struct ftrace_proc_maps *map;

		/* skip anon mappings */
		if (sscanf(buf, "%lx-%lx %s %*x %*x:%*x %*d %s\n",
			   &start, &end, prot, path) != 4)
			continue;

		/* skip non-executable mappings */
		if (prot[2] != 'x')
			continue;

		namelen = ALIGN(strlen(path) + 1, 4);

		map = xmalloc(sizeof(*map) + namelen);

		map->start = start;
		map->end = end;
		map->len = namelen;
		memcpy(map->prot, prot, 4);
		memcpy(map->libname, path, namelen);
		map->libname[strlen(path)] = '\0';

		map->next = proc_maps;
		proc_maps = map;
	}
	fclose(fp);

	snprintf(buf, sizeof(buf), "%s/trace.dat", opts->dirname);

	fp = fopen(buf, "rb");
	if (fp == NULL)
		pr_err("ftrace: ERROR: cannot open data file\n");

	handle->fp = fp;

	ret = 0;

out:
	return ret;
}

static void close_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	struct ftrace_proc_maps *map;

	if (opts->exename == handle->info.exename)
		opts->exename = NULL;

	fclose(handle->fp);
	clear_ftrace_info(&handle->info);

	while (proc_maps) {
		map = proc_maps;
		proc_maps = map->next;

		free(map);
	}
}

static int read_rstack(struct ftrace_file_handle *handle,
		       struct mcount_ret_stack *rstack)
{
	FILE *fp = handle->fp;

	if (fread(rstack, sizeof(*rstack), 1, fp) != 1) {
		if (feof(fp))
			return -1;

		pr_log("ftrace: error reading rstack: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int print_flat_rstack(struct ftrace_file_handle *handle,
			     struct mcount_ret_stack *rstack)
{
	static int count;
	struct sym *parent = find_symtab(rstack->parent_ip, proc_maps);
	struct sym *child = find_symtab(rstack->child_ip, proc_maps);
	char *parent_name = symbol_getname(parent, rstack->parent_ip);
	char *child_name = symbol_getname(child, rstack->child_ip);

	if (rstack->end_time == 0) {
		printf("[%d] %d/%d: ip (%s -> %s), time (%"PRIu64")\n",
		       count++, rstack->tid, rstack->depth, parent_name,
		       child_name, rstack->start_time);
	} else {
		printf("[%d] %d/%d: ip (%s <- %s), time (%"PRIu64":%"PRIu64")\n",
		       count++, rstack->tid, rstack->depth, parent_name,
		       child_name, rstack->end_time,
		       rstack->end_time - rstack->start_time);
	}

	symbol_putname(parent, parent_name);
	symbol_putname(child, child_name);
	return 0;
}

static void print_time_unit(uint64_t start_nsec, uint64_t end_nsec)
{
	uint64_t delta = 0;
	uint64_t delta_small;
	char *unit[] = { "us", "ms", "s", "m", "h", };
	unsigned limit[] = { 1000, 1000, 1000, 60, 24, INT_MAX, };
	unsigned idx;

	if (start_nsec == 0UL && end_nsec == 0UL) {
		printf(" %7s %2s", "", "");
		return;
	}

	for (idx = 0; idx < ARRAY_SIZE(unit); idx++) {
		if (delta == 0)
			delta = end_nsec - start_nsec;

		delta_small = delta % limit[idx];
		delta = delta / limit[idx];

		if (delta < limit[idx+1])
			break;
	}

	assert(idx < ARRAY_SIZE(unit));

	printf(" %3"PRIu64".%03"PRIu64" %2s", delta, delta_small, unit[idx]);
}

static int print_graph_rstack(struct ftrace_file_handle *handle,
			      struct mcount_ret_stack *rstack)
{
	struct sym *sym = find_symtab(rstack->child_ip, proc_maps);
	char *symname = symbol_getname(sym, rstack->child_ip);

	if (rstack->end_time == 0) {
		fpos_t pos;
		struct mcount_ret_stack rstack_next;

		fgetpos(handle->fp, &pos);

		if (read_rstack(handle, &rstack_next) < 0) {
			symbol_putname(sym, symname);
			return -1;
		}

		if (rstack_next.depth == rstack->depth &&
		    rstack_next.tid == rstack->tid &&
		    rstack_next.end_time != 0) {
			/* leaf function - also consume return record */
			print_time_unit(rstack->start_time, rstack_next.end_time);
			printf(" [%5d] | %*s%s();\n", rstack->tid,
			       rstack->depth * 2, "", symname);
		} else {
			/* function entry */
			print_time_unit(0UL, 0UL);
			printf(" [%5d] | %*s%s() {\n", rstack->tid,
			       rstack->depth * 2, "", symname);

			/* need to re-process return record */
			fsetpos(handle->fp, &pos);
		}
	} else {
		/* function exit */
		print_time_unit(rstack->start_time, rstack->end_time);
		printf(" [%5d] | %*s} /* %s */\n", rstack->tid,
		       rstack->depth * 2, "", symname);
	}

	symbol_putname(sym, symname);
	return 0;
}

static int command_replay(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
	struct mcount_ret_stack rstack;
	int *tids = NULL;
	int nr_tids = 0;

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	load_symtabs(opts->exename);

	if (opts->tid) {
		char *p = opts->tid;

		do {
			int id;

			if (*p == ',' || *p == ':')
				p++;

			id = strtol(p, &p, 10);

			tids = xrealloc(tids, (nr_tids+1) * sizeof(int));
			tids[nr_tids++] = id;

		} while (*p);
	}

	if (!opts->flat)
		printf("# DURATION    TID     FUNCTION\n");

	while (read_rstack(&handle, &rstack) == 0) {
		if (opts->tid) {
			int i;

			for (i = 0; i < nr_tids; i++) {
				if (rstack.tid == tids[i])
					break;
			}

			if (i == nr_tids)
				continue;
		}

		if (opts->flat)
			ret = print_flat_rstack(&handle, &rstack);
		else
			ret = print_graph_rstack(&handle, &rstack);

		if (ret)
			break;
	}

	if (opts->tid)
		free(tids);

	unload_symtabs();

	close_data_file(opts, &handle);

	return ret;
}

static char *tmp_dirname;
static void cleanup_tempdir(void)
{
	DIR *dp;
	struct dirent *ent;

	if (!tmp_dirname)
		return;

	dp = opendir(tmp_dirname);
	if (dp == NULL) {
		pr_err("ftrace: ERROR: cannot open temp dir: %s\n",
		       strerror(errno));
	}

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		unlink(ent->d_name);
	}

	closedir(dp);

	rmdir(tmp_dirname);
	tmp_dirname = NULL;
}

static int command_live(int argc, char *argv[], struct opts *opts)
{
	char template[32] = "/tmp/ftrace-live-XXXXXX";
	int fd = mkstemp(template);
	if (fd < 0) {
		pr_err("ftrace: ERROR: cannot create temp dir: %s\n",
		       strerror(errno));
	}

	close(fd);
	unlink(template);

	tmp_dirname = template;
	atexit(cleanup_tempdir);

	opts->dirname = template;

	if (command_record(argc, argv, opts) == 0)
		command_replay(argc, argv, opts);

	cleanup_tempdir();

	return 0;
}

struct trace_entry {
	int pid;
	struct sym *sym;
	uint64_t time_total;
	uint64_t time_self;
	unsigned long nr_called;
	struct rb_node link;
};

static void insert_entry(struct rb_root *root, struct trace_entry *te, bool thread)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	pr_dbg("%s: [%5d] %-40.40s: %"PRIu64" (%lu)\n",
	       __func__, te->pid, te->sym->name, te->time_total, te->nr_called);

	while (*p) {
		int cmp;

		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (thread)
			cmp = te->pid - entry->pid;
		else
			cmp = strcmp(entry->sym->name, te->sym->name);

		if (cmp == 0) {
			entry->time_total += te->time_total;
			entry->time_self  += te->time_self;
			entry->nr_called  += te->nr_called;
			return;
		}

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	entry = xmalloc(sizeof(*entry));
	entry->pid = te->pid;
	entry->sym = te->sym;
	entry->time_total = te->time_total;
	entry->time_self  = te->time_self;
	entry->nr_called  = te->nr_called;

	rb_link_node(&entry->link, parent, p);
	rb_insert_color(&entry->link, root);
}

static void sort_by_time(struct rb_root *root, struct trace_entry *te)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (entry->time_total < te->time_total)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&te->link, parent, p);
	rb_insert_color(&te->link, root);
}

static int command_report(int argc, char *argv[], struct opts *opts)
{
	int ret;
	bool first = true;
	struct ftrace_file_handle handle;
	struct rb_root name_tree = RB_ROOT;
	struct rb_root time_tree = RB_ROOT;
	struct rb_node *node;
	struct trace_entry *entry;
	struct mcount_ret_stack rstack;
	const char h_format[] = "  %-40.40s  %10.10s  %10.10s  %10.10s  \n";
//	const char l_format[] = "  %-40.40s  %10"PRIu64"  %10"PRIu64"  %10lu  \n";
	const char t_format[] = "  %5.5s  %-40.40s  %10.10s  %10.10s  \n";
	const char line[] = "=================================================";

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	load_symtabs(opts->exename);

	while (read_rstack(&handle, &rstack) == 0) {
		struct sym *sym;
		struct trace_entry te;

		if (!opts->report_thread && rstack.end_time == 0)
			continue;

		sym = find_symtab(rstack.child_ip, proc_maps);
		if (sym == NULL) {
			pr_log("cannot find symbol for %lx\n", rstack.child_ip);
			continue;
		}

		te.pid = rstack.tid;
		te.sym = sym;

		if (opts->report_thread && first) {
			sym = find_symname("main");
			if (sym == NULL)
				pr_log("no main thread???\n");
			else
				te.sym = sym;

			first = false;
		}

		if (rstack.end_time) {
			te.time_total = rstack.end_time - rstack.start_time;
			te.time_self = te.time_total - rstack.child_time;
			te.nr_called = 1;
		} else {
			te.time_total = te.time_self = 0;
			te.nr_called = 0;
		}

		insert_entry(&name_tree, &te, opts->report_thread);
	}

	if (opts->report_thread) {
		printf(t_format, "TID", "Start function", "Run time", "Nr. funcs");
		printf(t_format, line, line, line, line);

		while (!RB_EMPTY_ROOT(&name_tree)) {
			char *symname;

			node = rb_first(&name_tree);
			rb_erase(node, &name_tree);

			entry = rb_entry(node, struct trace_entry, link);
			symname = symbol_getname(entry->sym, 0);

			printf("  %5d  %-40.40s ", entry->pid, symname);
			print_time_unit(0UL, entry->time_self);
			printf("  %10lu  \n", entry->nr_called);

			symbol_putname(entry->sym, symname);
		}

		goto out;
	}

	while (!RB_EMPTY_ROOT(&name_tree)) {
		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		sort_by_time(&time_tree, rb_entry(node, struct trace_entry, link));
	}

	printf(h_format, "Function", "Total time", "Self time", "Nr. called");
	printf(h_format, line, line, line, line);

	for (node = rb_first(&time_tree); node; node = rb_next(node)) {
		char *symname;

		entry = rb_entry(node, struct trace_entry, link);

		symname = symbol_getname(entry->sym, 0);

		printf("  %-40.40s ", symname);
		print_time_unit(0UL, entry->time_total);
		putchar(' ');
		print_time_unit(0UL, entry->time_self);
		printf("  %10lu  \n", entry->nr_called);

		symbol_putname(entry->sym, symname);
	}

out:
	unload_symtabs();

	close_data_file(opts, &handle);

	return ret;
}

static int command_info(int argc, char *argv[], struct opts *opts)
{
	int ret;
	char buf[PATH_MAX];
	struct stat statbuf;
	struct ftrace_file_handle handle;
	const char *fmt = "# %-20s: %s\n";

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);

	if (stat(buf, &statbuf) < 0)
		return -1;

	printf("# ftrace information\n");
	printf("# ==================\n");
	printf(fmt, "program version", argp_program_version);
	printf("# %-20s: %s", "recorded on", ctime(&statbuf.st_mtime));

	if (handle.hdr.info_mask & (1UL << CMDLINE))
		printf(fmt, "cmdline", handle.info.cmdline);

	if (handle.hdr.info_mask & (1UL << EXE_NAME))
		printf(fmt, "exe image", handle.info.exename);

	if (handle.hdr.info_mask & (1UL << EXE_BUILD_ID)) {
		int i;
		printf("# %-20s: ", "build id");
		for (i = 0; i < 20; i++)
			printf("%02x", handle.info.build_id[i]);
		printf("\n");
	}

	if (handle.hdr.info_mask & (1UL << EXIT_STATUS)) {
		int status = handle.info.exit_status;

		if (WIFEXITED(status)) {
			snprintf(buf, sizeof(buf), "exited with code: %d",
				 WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			snprintf(buf, sizeof(buf), "terminated by signal: %d",
				 WTERMSIG(status));
		} else {
			snprintf(buf, sizeof(buf), "unknown exit status: %d",
				 status);
		}
		printf(fmt, "exit status", buf);
	}

	if (handle.hdr.info_mask & (1UL << CPUINFO)) {
		printf("# %-20s: %d/%d (online/possible)\n",
		       "nr of cpus", handle.info.nr_cpus_online,
		       handle.info.nr_cpus_possible);
		printf(fmt, "cpu info", handle.info.cpudesc);
	}

	if (handle.hdr.info_mask & (1UL << MEMINFO))
		printf(fmt, "memory info", handle.info.meminfo);

	if (handle.hdr.info_mask & (1UL << OSINFO)) {
		printf(fmt, "kernel version", handle.info.kernel);
		printf(fmt, "hostname", handle.info.hostname);
		printf(fmt, "distro", handle.info.distro);
	}

	printf("\n");

	close_data_file(opts, &handle);

	return ret;
}
