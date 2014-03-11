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
#include <sys/wait.h>
#include <sys/stat.h>
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
#define OPT_usepipe	307
#define OPT_library	308

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
	{ "use-pipe", OPT_usepipe, 0, 0, "Use pipe to record trace data" },
	{ "library", OPT_library, 0, 0, "Also trace internal library functions" },
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
	char *exename;
	char *filename;
	char *logfile;
	int mode;
	int idx;
	int signal;
	unsigned long bsize;
	bool flat;
	bool want_plthook;
	bool print_symtab;
	bool daemon;
	bool use_pipe;
	bool library;
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

	case 'd':
		debug = true;
		break;

	case 'f':
		opts->filename = arg;
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

	case OPT_usepipe:
		opts->use_pipe = true;
		break;

	case OPT_library:
		opts->library = true;
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

int main(int argc, char *argv[])
{
	struct opts opts = {
		.mode = FTRACE_MODE_INVALID,
		.filename = FTRACE_FILE_NAME,
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
		logfd = open(opts.logfile, O_WRONLY | O_CREAT);
		if (logfd < 0) {
			perror("ftrace: ERROR: cannot open log file");
			exit(1);
		}
	}

	if (opts.print_symtab) {
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
		setenv("LD_BIND_NOT", "1", 1);
		setenv("FTRACE_PLTHOOK", "1", 1);
	}

	if (strcmp(opts->filename, FTRACE_FILE_NAME))
		setenv("FTRACE_FILE", opts->filename, 1);

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

	if (opts->use_pipe) {
		snprintf(buf, sizeof(buf), "%d", pfd);
		setenv("FTRACE_PIPE", buf, 1);
	}

	if (opts->library) {
		if (opts->use_pipe)
			setenv("FTRACE_LIBRARY_TRACE", "1", 1);
		else
			pr_log("--library should be used with --use-pipe for now\n");
	}

	if (debug)
		setenv("FTRACE_DEBUG", "1", 1);
}

static int fill_file_header(struct opts *opts, int status)
{
	int fd, efd;
	int ret = -1;
	struct stat statbuf;
	struct ftrace_file_header hdr;
	Elf *elf;
	GElf_Ehdr ehdr;
	off_t header_offset;

	pr_dbg("fill header (metadata) info in %s\n", opts->filename);

	fd = open(opts->filename, O_RDWR);
	if (fd < 0) {
		pr_log("cannot open data file: %s\n", strerror(errno));
		return -1;
	}

	if (fstat(fd, &statbuf) < 0) {
		pr_log("cannot stat data file: %s\n", strerror(errno));
		goto close_fd;
	}

	if (statbuf.st_size < (int)sizeof(hdr)) {
		pr_log("invalid or corrupted data file (size = %lu)\n",
		       (unsigned long)statbuf.st_size);
		goto close_fd;
	}

	if (pread(fd, &hdr, sizeof(hdr), 0) != sizeof(hdr)) {
		pr_log("cannot read header part: %s\n", strerror(errno));
		goto close_fd;
	}

	if (strncmp(FTRACE_MAGIC_STR, hdr.magic, FTRACE_MAGIC_LEN)) {
		pr_log("invalue magic string: %s\n", hdr.magic);
		goto close_fd;
	}

	if (hdr.version != FTRACE_FILE_VERSION) {
		pr_log("invalid version: %d\n", hdr.version);
		goto close_fd;
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

	hdr.header_size = sizeof(hdr);
	hdr.endian = ehdr.e_ident[EI_DATA];
	hdr.class = ehdr.e_ident[EI_CLASS];
	hdr.length = statbuf.st_size;

	header_offset = lseek(fd, 0, SEEK_END);
	pr_dbg("writing header info at %lu\n", (unsigned long)header_offset);

	fill_ftrace_info(&hdr.info_mask, fd, opts->exename, elf, status);

	if (pwrite(fd, &hdr, sizeof(hdr), 0) != sizeof(hdr))
		goto close_elf;

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
static volatile bool child_exited;

static void sighandler(int sig)
{
	if (sig == SIGCHLD)
		child_exited = true;

	done = true;
}

static int tgkill(int tgid, int tid, int sig)
{
	return syscall(SYS_tgkill, tgid, tid, sig);
}

static struct ftrace_proc_maps *proc_maps;

static int read_proc_maps(int fd, char *buf, size_t size, int *remaining)
{
	int len;
	char *pos = NULL;
	int nr_maps = 0;

	len = read(fd, buf, sizeof(START_MAPS));
	if (len != (int)sizeof(START_MAPS) ||
	    memcmp(buf, START_MAPS, sizeof(START_MAPS))) {
		pr_log("invalid maps data.. skipping\n");
		goto out;
	}

	pos = buf;
	len = read(fd, buf, size);
	if (len < 0) {
		pr_err("ftrace: ERROR: cannot read maps data: %s\n",
		       strerror(errno));
	}

	while (len > 0) {
		int n;
		char *p = memchr(pos, '\n', len);
		if (p) {
			unsigned long start, end;
			char prot[4];
			char path[4096];

			if (sscanf(pos, "%lx-%lx %s %*x %*x:%*x %*d %s\n",
				   &start, &end, prot, path) != 4)
				goto skip;

			if (prot[2] == 'x') {
				struct ftrace_proc_maps *map;
				size_t namelen = ALIGN(strlen(path) + 1, 4);

				map = xmalloc(sizeof(*map) + namelen);

				map->start = start;
				map->end = end;
				map->len = namelen;
				memcpy(map->prot, prot, sizeof(prot));
				memcpy(map->libname, path, namelen);
				map->libname[strlen(path)] = '\0';

				pr_dbg("found mapping: %8lx-%-8lx %s\n",
				       start, end, map->libname);

				map->next = proc_maps;
				proc_maps = map;

				nr_maps++;
			}

			p++;
			len -= p - pos;
			pos = p;

			if (len)
				continue;
		}

skip:
		if (len >= (int)sizeof(END_MAPS) &&
		    !memcmp(pos, END_MAPS, sizeof(END_MAPS))) {
			pos += sizeof(END_MAPS);
			len -= sizeof(END_MAPS);

			pr_dbg("found END MAPS marker\n");
			break;
		}

		memcpy(buf, pos, len);

		n = read(fd, buf + len, size - len);
		if (n < 0) {
			pr_err("ftrace: ERROR: cannot read maps data: %s\n",
			       strerror(errno));
		}

		pos = buf;
		len += n;
	}

out:
	if (len) {
		memcpy(buf, pos, len);
		*remaining = len;

		pr_dbg("%s: remaining %d bytes\n", __func__, len);
	}

	return nr_maps;
}

static int command_record(int argc, char *argv[], struct opts *opts)
{
	int pid;
	int status;
	char oldname[512];
	const char *profile_funcs[] = {
		"mcount",
		"__fentry__",
		"__gnu_mcount_nc",
		"__cyg_profile_func_enter",
	};
	size_t i;
	int pfd[2];

	/* backup old 'ftrace.data' file */
	if (strcmp(FTRACE_FILE_NAME, opts->filename) == 0) {
		snprintf(oldname, sizeof(oldname), "%s.old", opts->filename);

		/* don't care about the failure */
		rename(opts->filename, oldname);
	}

	load_symtabs(opts->exename);

	for (i = 0; i < ARRAY_SIZE(profile_funcs); i++) {
		if (find_symname(profile_funcs[i]))
			break;
	}

	if (i == ARRAY_SIZE(profile_funcs) && !opts->library)
		pr_err(mcount_msg, "mcount", opts->exename);

	fflush(stdout);

	if (opts->use_pipe && pipe(pfd) < 0) {
		pr_err("ftrace: ERROR: cannot setup internal pipe: %s\n",
		       strerror(errno));
	}

	pid = fork();
	if (pid < 0) {
		pr_err("ftrace: ERROR: cannot start child process: %s\n",
		       strerror(errno));
	}

	if (pid == 0) {
		if (opts->use_pipe)
			close(pfd[0]);

		setup_child_environ(opts, pfd[1]);

		/*
		 * I don't think the traced binary is in PATH.
		 * So use plain 'execv' rather than 'execvp'.
		 */
		execv(opts->exename, &argv[opts->idx]);
		abort();
	}

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGCHLD, sighandler);

	if (opts->use_pipe) {
		int len;
		char buf[4096];
		struct ftrace_file_header hdr;
		int remaining = 0;

		close(pfd[1]);

		/* reuse pfd[1] to write real data file */
		pfd[1] = open(opts->filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (pfd[1] < 0) {
			pr_err("ftrace: ERROR: cannot open data file: %s\n",
			       strerror(errno));
		}

		len = read(pfd[0], &hdr, sizeof(hdr));
		if (len < (int)sizeof(hdr)) {
			pr_err("ftrace: ERROR: cannot read header data: %s (len = %d)\n",
			       strerror(errno), len);
		}

		if (strncmp(hdr.magic, FTRACE_MAGIC_STR, FTRACE_MAGIC_LEN) ||
		    hdr.version != FTRACE_FILE_VERSION) {
			pr_err("ftrace: ERROR: invalid header data\n");
		}

		if (hdr.nr_maps != 0) {
			hdr.nr_maps = read_proc_maps(pfd[0], buf, sizeof(buf),
						     &remaining);
		}

		len = write(pfd[1], &hdr, sizeof(hdr));
		if (len != (int)sizeof(hdr)) {
			pr_err("ftrace: ERROR: cannot write header data: %s\n",
			       strerror(errno));
		}

		if (hdr.nr_maps) {
			struct ftrace_proc_maps *map = proc_maps;

			while (map) {
				proc_maps = map->next;
				map->next = MAPS_MARKER;

				if (write(pfd[1], map, sizeof(*map) + map->len) < 0) {
					pr_err("ftrace: ERROR: cannot write maps data: %s\n",
					       strerror(errno));
				}

				free(map);
				map = proc_maps;
			}
		}

		if (remaining)
			write(pfd[1], buf, remaining);

		while (!done) {
			len = read(pfd[0], buf, 4096);
			if (len < 0 && errno != -EINTR) {
				pr_err("ftrace: ERROR: cannot read data: %s\n",
				       strerror(errno));
			}

			if (write(pfd[1], buf, len) != len)
				pr_err("ftrace: error during write: %s\n",
				       strerror(errno));
		}

		if (opts->daemon)
			goto send_signal;

		goto wait_child;
	}

	while (!done) {
		if (opts->daemon) {
			sleep(1);
			continue;
		}

wait_child:
		waitpid(pid, &status, 0);
		if (WIFSIGNALED(status)) {
			pr_dbg("child (%s) was terminated by signal: %d\n",
			       opts->exename, WTERMSIG(status));
		} else {
			pr_dbg("child terminated with %d\n", WEXITSTATUS(status));
		}
		break;
	}

	if (opts->daemon) {
send_signal:
		tgkill(pid, pid, opts->signal);
		usleep(1000);
	}

	if (opts->use_pipe) {
		int nread;
		char buf[4096];

		while (ioctl(pfd[0], FIONREAD, &nread) >= 0 && nread) {
			nread = read(pfd[0], buf, sizeof(buf));
			if (nread <= 0)
				pr_err("ftrace: ERROR: error during read\n");

			if (write(pfd[1], buf, nread) != nread) {
				pr_err("ftrace: ERROR: error during write: %s\n",
				       strerror(errno));
			}
		}

		close(pfd[0]);
		close(pfd[1]);
	}

	if (fill_file_header(opts, status) < 0)
		pr_err("ftrace: ERROR: cannot generate data file\n");

	/*
	 * Do not unload symbol tables.  It might save some time when used by
	 * 'live' command as it also need to load the symtabs again.
	 */
	//unload_symtabs();
	return 0;
}

static int open_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	int ret = -1;
	FILE *fp;
	fpos_t pos;
	const char msg[] = "ftrace: ERROR: Was '%s' compiled with -pg or\n"
		"\t-finstrument-functions flag and ran with ftrace record?\n";

	fp = fopen(opts->filename, "rb");
	if (fp == NULL) {
		if (errno == ENOENT) {
			pr_log("ftrace: cannot find %s file!\n", opts->filename);

			if (opts->exename)
				pr_err(msg, opts->exename);
		} else {
			pr_err("ftrace: ERROR: cannot open %s file: %s\n",
			       opts->filename, strerror(errno));
		}
		goto out;
	}

	fread(&handle->hdr, sizeof(handle->hdr), 1, fp);
	if (memcmp(handle->hdr.magic, FTRACE_MAGIC_STR, FTRACE_MAGIC_LEN)) {
		fclose(fp);
		pr_err("ftrace: ERROR: invalid magic string found!\n");
	}
	if (handle->hdr.version != FTRACE_FILE_VERSION) {
		fclose(fp);
		pr_err("ftrace: ERROR: invalid vergion number found!\n");
	}

	handle->fp = fp;

	if (handle->hdr.length == 0) {
		pr_log("ftrace: WARNING: header info was missing.\n"
		       "\tIt seems the ftrace record sesssion was terminated abnormally.\n");

		if (opts->exename == NULL) {
			pr_err("ftrace: You need to specify the orignal executable\n"
			       "\tas an argument to proceed.\n");
		}
	}

	while (handle->hdr.nr_maps) {
		struct ftrace_proc_maps *map = xmalloc(sizeof(*map));

		fread(map, sizeof(*map), 1, fp);

		if (map->next != MAPS_MARKER)
			pr_err("ftrace: ERROR: invalid maps marker found\n");

		map = xrealloc(map, sizeof(*map) + map->len);
		fread(map->libname, map->len, 1, fp);

		pr_dbg("reading map: %lx-%-lx: %s\n",
		       map->start, map->end, map->libname);

		map->next = proc_maps;
		proc_maps = map;

		handle->hdr.nr_maps--;
	}

	fgetpos(fp, &pos);

	fseek(fp, handle->hdr.length, SEEK_SET);
	if (read_ftrace_info(handle->hdr.info_mask, handle) < 0) {
		fclose(fp);
		pr_err("ftrace: ERROR: cannot read ftrace header info!\n");
	}

	fsetpos(fp, &pos);

	if (opts->exename == NULL)
		opts->exename = handle->info.exename;

	ret = 0;

out:
	return ret;
}

static void close_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	if (opts->exename == handle->info.exename)
		opts->exename = NULL;

	fclose(handle->fp);
	clear_ftrace_info(&handle->info);
}

static int read_rstack(struct ftrace_file_handle *handle,
		       struct mcount_ret_stack *rstack)
{
	FILE *fp = handle->fp;
	off_t offset = ftello(fp);

	if (offset >= (off_t)handle->hdr.length ||
	    offset + sizeof(*rstack) > handle->hdr.length)
		return -1;

	if (fread(rstack, sizeof(*rstack), 1, fp) != 1) {
		pr_log("ftrace: error reading rstack: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int print_flat_rstack(struct ftrace_file_handle *handle,
			     struct mcount_ret_stack *rstack)
{
	static int count;
	struct sym *parent = find_symtab(rstack->parent_ip);
	struct sym *child = find_symtab(rstack->child_ip);
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
	struct sym *sym = find_symtab(rstack->child_ip);
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

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	load_symtabs(opts->exename);

	if (!opts->flat)
		printf("# DURATION    TID     FUNCTION\n");

	while (read_rstack(&handle, &rstack) == 0) {
		if (opts->flat)
			ret = print_flat_rstack(&handle, &rstack);
		else
			ret = print_graph_rstack(&handle, &rstack);

		if (ret)
			break;
	}

	unload_symtabs();

	close_data_file(opts, &handle);

	return ret;
}

static char *tmp_filename;
static void cleanup_tempfile(void)
{
	if (tmp_filename)
		unlink(tmp_filename);
}

static int command_live(int argc, char *argv[], struct opts *opts)
{
	char template[32] = "/tmp/ftrace-live-XXXXXX";
	int fd = mkstemp(template);
	if (fd < 0) {
		pr_err("ftrace: ERROR: cannot create temp file: %s\n",
		       strerror(errno));
	}

	close(fd);

	tmp_filename = template;
	atexit(cleanup_tempfile);

	opts->filename = template;

	if (command_record(argc, argv, opts) == 0)
		command_replay(argc, argv, opts);

	tmp_filename = NULL;

	unlink(template);

	return 0;
}

struct trace_entry {
	struct sym *sym;
	uint64_t time_total;
	uint64_t time_self;
	unsigned long nr_called;
	struct rb_node link;
};

static void insert_entry(struct rb_root *root, struct trace_entry *te)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		int cmp;

		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		cmp = strcmp(entry->sym->name, te->sym->name);
		if (cmp == 0) {
			entry->time_total += te->time_total;
			entry->time_self  += te->time_self;
			entry->nr_called  += 1;
			return;
		}

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	entry = xmalloc(sizeof(*entry));
	entry->sym = te->sym;
	entry->time_total = te->time_total;
	entry->time_self  = te->time_self;
	entry->nr_called  = 1;

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
	struct ftrace_file_handle handle;
	struct rb_root name_tree = RB_ROOT;
	struct rb_root time_tree = RB_ROOT;
	struct rb_node *node;
	struct trace_entry *entry;
	struct mcount_ret_stack rstack;
	const char h_format[] = "  %-40.40s  %10.10s  %10.10s  %10.10s  \n";
//	const char l_format[] = "  %-40.40s  %10"PRIu64"  %10"PRIu64"  %10lu  \n";
	const char line[] = "=================================================";

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	load_symtabs(opts->exename);

	while (read_rstack(&handle, &rstack) == 0) {
		struct sym *sym;
		struct trace_entry te;

		if (rstack.end_time == 0)
			continue;

		sym = find_symtab(rstack.child_ip);
		assert(sym != NULL);

		te.sym = sym;
		te.time_total = rstack.end_time - rstack.start_time;
		te.time_self = te.time_total - rstack.child_time;

		insert_entry(&name_tree, &te);
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

	unload_symtabs();

	close_data_file(opts, &handle);

	return ret;
}

static int command_info(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct stat statbuf;
	struct ftrace_file_handle handle;
	const char *fmt = "# %-20s: %s\n";

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	if (stat(opts->filename, &statbuf) < 0)
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
		char buf[1024];
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
