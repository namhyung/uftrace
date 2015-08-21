/*
 * ftrace - Function Tracer
 *
 * Copyright (C) 2014-2015  LG Electornics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <argp.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/eventfd.h>
#include <gelf.h>
#include <pthread.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "ftrace"

#include "mcount.h"
#include "symbol.h"
#include "rbtree.h"
#include "utils.h"
#include "list.h"

const char *argp_program_version = "ftrace v0.4";
const char *argp_program_bug_address = "http://mod.lge.com/hub/otc/ftrace/issues";

#define OPT_flat 	301
#define OPT_plthook 	302
#define OPT_symbols	303
#define OPT_logfile	304
#define OPT_force	305
#define OPT_threads	306
#define OPT_no_merge	307
#define OPT_nop		308
#define OPT_time	309
#define OPT_max_stack	310


static struct argp_option ftrace_options[] = {
	{ "library-path", 'L', "PATH", 0, "Load libraries from this PATH" },
	{ "filter", 'F', "FUNC[,FUNC,...]", 0, "Only trace those FUNCs" },
	{ "notrace", 'N', "FUNC[,FUNC,...]", 0, "Don't trace those FUNCs" },
	{ "depth", 'D', "DEPTH", 0, "Trace functions within DEPTH" },
	{ "debug", 'd', 0, 0, "Print debug messages" },
	{ "file", 'f', "FILE", 0, "Use this FILE instead of ftrace.data" },
	{ "flat", OPT_flat, 0, 0, "Use flat output format" },
	{ "no-plthook", OPT_plthook, 0, 0, "Don't hook library function calls" },
	{ "symbols", OPT_symbols, 0, 0, "Print symbol tables" },
	{ "buffer", 'b', "SIZE", 0, "Size of tracing buffer" },
	{ "logfile", OPT_logfile, "FILE", 0, "Save log messages to this file" },
	{ "force", OPT_force, 0, 0, "Trace even if executable is not instrumented" },
	{ "threads", OPT_threads, 0, 0, "Report thread stats instead" },
	{ "tid", 'T', "TID[,TID,...]", 0, "Only replay those tasks" },
	{ "no-merge", OPT_no_merge, 0, 0, "Don't merge leaf functions" },
	{ "nop", OPT_nop, 0, 0, "No operation (for performance test)" },
	{ "time", OPT_time, 0, 0, "Print time information" },
	{ "max-stack", OPT_max_stack, "DEPTH", 0, "Set max stack depth to DEPTH" },
	{ "kernel", 'K', 0, 0, "Trace kernel functions also (if supported)" },
	{ 0 }
};

#define FTRACE_MODE_INVALID 0
#define FTRACE_MODE_RECORD  1
#define FTRACE_MODE_REPLAY  2
#define FTRACE_MODE_LIVE    3
#define FTRACE_MODE_REPORT  4
#define FTRACE_MODE_INFO    5
#define FTRACE_MODE_DUMP    6

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
	int depth;
	int max_stack;
	unsigned long bsize;
	bool flat;
	bool want_plthook;
	bool print_symtab;
	bool force;
	bool report_thread;
	bool no_merge;
	bool nop;
	bool time;
	bool kernel;
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

	case 'D':
		opts->depth = strtol(arg, NULL, 0);
		if (opts->depth <= 0)
			pr_err_ns("invalid depth given: %s\n", arg);
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
		if (opts->bsize & (getpagesize() - 1))
			pr_err_ns("buffer size should be multiple of page size");
		break;

	case 'K':
		opts->kernel = true;
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

	case OPT_logfile:
		opts->logfile = arg;
		break;

	case OPT_force:
		opts->force = true;
		break;

	case OPT_threads:
		opts->report_thread = true;
		break;

	case OPT_no_merge:
		opts->no_merge = true;
		break;

	case OPT_nop:
		opts->nop = true;
		break;

	case OPT_time:
		opts->time = true;
		break;

	case OPT_max_stack:
		opts->max_stack = strtol(arg, NULL, 0);
		if (opts->max_stack <= 0 || opts->max_stack > MCOUNT_RSTACK_MAX)
			pr_err_ns("max stack depth should be >0 and <%d\n",
				  MCOUNT_RSTACK_MAX);
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
		else if (!strcmp("dump", arg))
			opts->mode = FTRACE_MODE_DUMP;
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
static int command_dump(int argc, char *argv[], struct opts *opts);

static int open_data_file(struct opts *opts, struct ftrace_file_handle *handle);
static void close_data_file(struct opts *opts, struct ftrace_file_handle *handle);

int main(int argc, char *argv[])
{
	struct opts opts = {
		.mode		= FTRACE_MODE_INVALID,
		.dirname	= FTRACE_DIR_NAME,
		.want_plthook	= true,
		.bsize		= SHMEM_BUFFER_SIZE,
		.depth		= MCOUNT_DEFAULT_DEPTH,
		.max_stack	= MCOUNT_RSTACK_MAX,
	};
	struct argp argp = {
		.options = ftrace_options,
		.parser = parse_option,
		.args_doc = "[record|replay|live|report|info|dump] [<command> args...]",
		.doc = "ftrace -- a function tracer",
	};

	argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &opts);

	if (opts.logfile) {
		logfd = open(opts.logfile, O_WRONLY | O_CREAT, 0644);
		if (logfd < 0)
			pr_err("cannot open log file");
	}

	if (opts.print_symtab) {
		struct symtabs symtabs = {
			.loaded = false,
		};

		if (opts.exename == NULL) {
			struct ftrace_file_handle handle;

			if (open_data_file(&opts, &handle) < 0)
				exit(1);
		}

		load_symtabs(&symtabs, opts.exename);
		print_symtabs(&symtabs);
		unload_symtabs(&symtabs);
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
	case FTRACE_MODE_DUMP:
		command_dump(argc, argv, &opts);
		break;
	case FTRACE_MODE_INVALID:
		break;
	}

	if (opts.logfile)
		close(logfd);

	return 0;
}

static int read_all(int fd, void *buf, size_t size)
{
	int ret;

	while (size) {
		ret = read(fd, buf, size);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return -1;

		buf += ret;
		size -= ret;
	}
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

#define REGEX_CHARS  ".?*+-^$|:()[]{}"

static void setup_child_environ(struct opts *opts, int pfd, struct symtabs *symtabs)
{
	char buf[4096];
	const char *old_preload = getenv("LD_PRELOAD");
	const char *old_libpath = getenv("LD_LIBRARY_PATH");
	bool multi_thread = !!find_symname(symtabs, "pthread_create");

	if (opts->nop) {
		strcpy(buf, "libmcount-nop.so");
	}
	else if (multi_thread) {
		if (opts->filter || opts->notrace || debug ||
		    opts->depth != MCOUNT_DEFAULT_DEPTH)
			strcpy(buf, "libmcount.so");
		else
			strcpy(buf, "libmcount-fast.so");
	}
	else {
		if (opts->filter || opts->notrace || debug ||
		    opts->depth != MCOUNT_DEFAULT_DEPTH)
			strcpy(buf, "libmcount-single.so");
		else
			strcpy(buf, "libmcount-fast-single.so");
	}
	pr_dbg("using %s library for tracing\n", buf);

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
		if (strpbrk(opts->filter, REGEX_CHARS))
			setenv("FTRACE_FILTER_REGEX", opts->filter, 1);
		else
			setenv("FTRACE_FILTER", opts->filter, 1);
	}

	if (opts->notrace) {
		if (strpbrk(opts->notrace, REGEX_CHARS))
			setenv("FTRACE_NOTRACE_REGEX", opts->notrace, 1);
		else
			setenv("FTRACE_NOTRACE", opts->notrace, 1);
	}

	if (opts->depth != MCOUNT_DEFAULT_DEPTH) {
		snprintf(buf, sizeof(buf), "%d", opts->depth);
		setenv("FTRACE_DEPTH", buf, 1);
	}

	if (opts->max_stack != MCOUNT_RSTACK_MAX) {
		snprintf(buf, sizeof(buf), "%d", opts->max_stack);
		setenv("FTRACE_MAX_STACK", buf, 1);
	}

	if (opts->want_plthook)
		setenv("FTRACE_PLTHOOK", "1", 1);

	if (strcmp(opts->dirname, FTRACE_DIR_NAME))
		setenv("FTRACE_DIR", opts->dirname, 1);

	if (opts->bsize != SHMEM_BUFFER_SIZE) {
		snprintf(buf, sizeof(buf), "%lu", opts->bsize);
		setenv("FTRACE_BUFFER", buf, 1);
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
		features |= PLTHOOK;

	/* mcount code creates task and sid-XXX.map files */
	features |= TASK_SESSION;

	if (opts->kernel)
		features |= KERNEL;

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
		pr_err("writing header info failed");

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

#define MCOUNT_MSG  "Can't find '%s' symbol in the '%s'.\n"			\
"\tIt seems not to be compiled with -pg or -finstrument-functions flag\n" 	\
"\twhich generates traceable code.  Please check your binary file.\n"

static volatile bool done;

static void sighandler(int sig)
{
	done = true;
}

#define SHMEM_NAME_SIZE (64 - (int)sizeof(void*))

struct shmem_list {
	struct list_head list;
	char id[SHMEM_NAME_SIZE];
};

static LIST_HEAD(shmem_list_head);
static LIST_HEAD(shmem_need_unlink);

struct tid_list {
	struct list_head list;
	int pid;
	int tid;
	bool exited;
};

static LIST_HEAD(tid_list_head);

struct buf_list {
	struct list_head list;
	char id[SHMEM_NAME_SIZE];
	void *data;
	size_t len;
};

static LIST_HEAD(buf_free_list);
static LIST_HEAD(buf_write_list);

static pthread_mutex_t free_list_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t write_list_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t write_cond = PTHREAD_COND_INITIALIZER;
static bool buf_done;

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

	return buf;
}

static int write_buffer_file(const char *dirname, struct buf_list *buf)
{
	int fd;
	char name[1024];

	fd = open(make_disk_name(name, sizeof(name), dirname, buf->id),
		  O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd < 0)
		pr_err("open disk file");

	if (write_all(fd, buf->data, buf->len) < 0)
		pr_err("write shmem buffer");

	close(fd);
	return 0;
}

struct writer_arg {
	struct opts		*opts;
	struct ftrace_kernel	*kern;
};

void *writer_thread(void *arg)
{
	struct buf_list *buf;
	struct writer_arg *warg = arg;

	while (true) {
		pthread_mutex_lock(&write_list_lock);
		while (list_empty(&buf_write_list)) {
			if (buf_done)
				break;
			pthread_cond_wait(&write_cond, &write_list_lock);
		}

		if (buf_done && list_empty(&buf_write_list)) {
			pthread_mutex_unlock(&write_list_lock);
			return NULL;
		}

		buf = list_first_entry(&buf_write_list, struct buf_list, list);
		list_del(&buf->list);

		pthread_mutex_unlock(&write_list_lock);

		write_buffer_file(warg->opts->dirname, buf);

		pthread_mutex_lock(&free_list_lock);
		list_add(&buf->list, &buf_free_list);
		pthread_mutex_unlock(&free_list_lock);

		if (warg->opts->kernel)
			record_kernel_tracing(warg->kern);
	}

	return NULL;
}

static struct buf_list *make_write_buffer(void)
{
	struct buf_list *buf;

	buf = malloc(sizeof(*buf));
	if (buf == NULL)
		return NULL;

	INIT_LIST_HEAD(&buf->list);
	buf->len = SHMEM_BUFFER_SIZE;
	buf->data = malloc(buf->len);
	if (buf->data == NULL) {
		free(buf);
		return NULL;
	}

	return buf;
}

static void copy_to_buffer(struct mcount_shmem_buffer *shm, char *sess_id)
{
	struct buf_list *buf = NULL;

	pthread_mutex_lock(&free_list_lock);
	if (!list_empty(&buf_free_list)) {
		buf = list_first_entry(&buf_free_list, struct buf_list, list);
		list_del(&buf->list);
	}
	pthread_mutex_unlock(&free_list_lock);

	if (buf == NULL) {
		buf = make_write_buffer();
		if (buf == NULL)
			pr_err_ns("not enough memory!\n");

		pr_dbg("make a new write buffer\n");
	}

	memcpy(buf->id, sess_id, strlen(sess_id));
	memcpy(buf->data, shm->data, shm->size);
	buf->len = shm->size;

	pthread_mutex_lock(&write_list_lock);
	list_add_tail(&buf->list, &buf_write_list);
	pthread_cond_signal(&write_cond);
	pthread_mutex_unlock(&write_list_lock);
}

static int record_mmap_file(const char *dirname, char *sess_id, int bufsize)
{
	int fd;
	struct shmem_list *sl;
	struct mcount_shmem_buffer *shmem_buf;

	/* write (append) it to disk */
	fd = shm_open(sess_id, O_RDWR, 0600);
	if (fd < 0) {
		pr_log("open shmem buffer failed: %s: %m\n", sess_id);
		return 0;
	}

	shmem_buf = mmap(NULL, bufsize, PROT_READ | PROT_WRITE,
			 MAP_SHARED, fd, 0);
	if (shmem_buf == MAP_FAILED)
		pr_err("mmap shmem buffer");

	close(fd);

	copy_to_buffer(shmem_buf, sess_id);

	if (shmem_buf->flag & SHMEM_FL_NEW) {
		sl = xmalloc(sizeof(*sl));
		memcpy(sl->id, sess_id, sizeof(sl->id));

		/* link to shmem_list */
		list_add_tail(&sl->list, &shmem_need_unlink);
	}

	/*
	 * Now it has consumed all contents in the shmem buffer,
	 * make it so that mcount can reuse it.
	 * This is paired with get_new_shmem_buffer().
	 */
	__sync_fetch_and_or(&shmem_buf->flag, SHMEM_FL_WRITTEN);

	munmap(shmem_buf, bufsize);
	return 0;
}

static int record_task_file(const char *dirname, void *data, int len)
{
	int fd;
	char buf[1024];
	char zero[8] = {};

	snprintf(buf, sizeof(buf), "%s/task", dirname);
	fd = open(buf, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd < 0)
		pr_err("open task file");

	if (write_all(fd, data, len) < 0)
		pr_err("write task file");

	if ((len % 8) && write_all(fd, zero, 8 - (len % 8)) < 0)
		pr_err("write task padding");

	close(fd);
	return 0;
}

static void flush_shmem_list(const char *dirname, int bufsize)
{
	struct shmem_list *sl, *tmp;

	/* flush remaining list (due to abnormal termination) */
	list_for_each_entry_safe(sl, tmp, &shmem_list_head, list) {
		pr_dbg("flushing %s\n", sl->id);

		list_del(&sl->list);
		record_mmap_file(dirname, sl->id, bufsize);
		free(sl);
	}

	pthread_mutex_lock(&write_list_lock);
	buf_done = true;
	pthread_cond_signal(&write_cond);
	pthread_mutex_unlock(&write_list_lock);
}

static void unlink_shmem_list(void)
{
	struct shmem_list *sl, *tmp;

	/* unlink shmem list (not used anymore) */
	/* flush remaining list (due to abnormal termination) */
	list_for_each_entry_safe(sl, tmp, &shmem_need_unlink, list) {
		pr_dbg("unlink %s\n", sl->id);

		list_del(&sl->list);
		shm_unlink(sl->id);
		free(sl);
	}
}

static void flush_old_shmem(const char *dirname, int tid, int bufsize)
{
	struct shmem_list *sl;

	/* flush remaining list (due to abnormal termination) */
	list_for_each_entry(sl, &shmem_list_head, list) {
		int sl_tid;

		sscanf(sl->id, "/ftrace-%*x-%d-%*d", &sl_tid);

		if (tid == sl_tid) {
			pr_dbg("flushing %s\n", sl->id);

			list_del(&sl->list);
			record_mmap_file(dirname, sl->id, bufsize);
			free(sl);
			return;
		}
	}
}

static int shmem_lost_count;

static void read_record_mmap(int pfd, const char *dirname, int bufsize)
{
	char buf[128];
	struct shmem_list *sl, *tmp;
	struct tid_list *tl, *pos;
	struct ftrace_msg msg;
	struct ftrace_msg_task tmsg;
	struct ftrace_msg_sess sess;
	char *exename;
	int lost;

	if (read_all(pfd, &msg, sizeof(msg)) < 0)
		pr_err("reading pipe failed:");

	if (msg.magic != FTRACE_MSG_MAGIC)
		pr_err_ns("invalid message received: %x\n", msg.magic);

	switch (msg.type) {
	case FTRACE_MSG_REC_START:
		if (msg.len > SHMEM_NAME_SIZE)
			pr_err_ns("invalid message length\n");

		sl = xmalloc(sizeof(*sl));

		if (read_all(pfd, sl->id, msg.len) < 0)
			pr_err("reading pipe failed");

		sl->id[msg.len] = '\0';
		pr_dbg("MSG START: %s\n", sl->id);

		/* link to shmem_list */
		list_add_tail(&sl->list, &shmem_list_head);
		break;

	case FTRACE_MSG_REC_END:
		if (msg.len > SHMEM_NAME_SIZE)
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, buf, msg.len) < 0)
			pr_err("reading pipe failed");

		buf[msg.len] = '\0';
		pr_dbg("MSG  END : %s\n", buf);

		/* remove from shmem_list */
		list_for_each_entry_safe(sl, tmp, &shmem_list_head, list) {
			if (!strncmp(sl->id, buf, SHMEM_NAME_SIZE)) {
				list_del(&sl->list);
				free(sl);
				break;
			}
		}

		record_mmap_file(dirname, buf, bufsize);
		break;

	case FTRACE_MSG_TID:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		pr_dbg("MSG  TID : %d/%d\n", tmsg.pid, tmsg.tid);

		/* check existing tid (due to exec) */
		list_for_each_entry(pos, &tid_list_head, list) {
			if (pos->tid == tmsg.tid) {
				flush_old_shmem(dirname, tmsg.tid, bufsize);
				break;
			}
		}

		if (list_no_entry(pos, &tid_list_head, list)) {
			tl = xmalloc(sizeof(*tl));

			tl->pid = tmsg.pid;
			tl->tid = tmsg.tid;
			tl->exited = false;

			/* link to tid_list */
			list_add(&tl->list, &tid_list_head);
		}

		record_task_file(dirname, &msg, sizeof(msg));
		record_task_file(dirname, &tmsg, sizeof(tmsg));
		break;

	case FTRACE_MSG_FORK_START:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		tl = xmalloc(sizeof(*tl));

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		tl->pid = tmsg.pid;
		tl->tid = -1;

		pr_dbg("MSG FORK1: %d/%d\n", tl->pid, tl->tid);

		tl->exited = false;

		/* link to tid_list */
		list_add(&tl->list, &tid_list_head);
		break;

	case FTRACE_MSG_FORK_END:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		list_for_each_entry(tl, &tid_list_head, list) {
			if (tl->pid == tmsg.pid && tl->tid == -1)
				break;
		}

		if (list_no_entry(tl, &tid_list_head, list) && tmsg.pid == 1) {
			/* daemon process has pid of 1, just pick a
			 * first task has tid of -1 */
			list_for_each_entry(tl, &tid_list_head, list) {
				if (tl->tid == -1) {
					pr_dbg("assume tid 1 as new daemon child\n");
					tmsg.pid = tl->pid;
					break;
				}
			}
		}

		if (list_no_entry(tl, &tid_list_head, list))
			pr_err("cannot find fork pid: %d\n", tmsg.pid);

		tl->tid = tmsg.tid;

		pr_dbg("MSG FORK2: %d/%d\n", tl->pid, tl->tid);

		record_task_file(dirname, &msg, sizeof(msg));
		record_task_file(dirname, &tmsg, sizeof(tmsg));
		break;

	case FTRACE_MSG_SESSION:
		if (msg.len < sizeof(sess))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &sess, sizeof(sess)) < 0)
			pr_err("reading pipe failed");

		exename = xmalloc(sess.namelen + 1);
		if (read_all(pfd, exename, sess.namelen) < 0)
			pr_err("reading pipe failed");
		exename[sess.namelen] = '\0';

		memcpy(buf, sess.sid, 16);
		buf[16] = '\0';

		pr_dbg("MSG SESSION: %d: %s (%s)\n", sess.task.tid, exename, buf);

		record_task_file(dirname, &msg, sizeof(msg));
		record_task_file(dirname, &sess, sizeof(sess));
		record_task_file(dirname, exename, sess.namelen);
		break;

	case FTRACE_MSG_LOST:
		if (msg.len < sizeof(lost))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &lost, sizeof(lost)) < 0)
			pr_err("reading pipe failed");

		shmem_lost_count += lost;
		break;

	default:
		pr_err_ns("Unknown message type: %u\n", msg.type);
		break;
	}
}

static char *map_file;

struct ftrace_session {
	struct rb_node		 node;
	char			 sid[16];
	uint64_t		 start_time;
	int			 pid, tid;
	struct ftrace_proc_maps *maps;
	struct symtabs		 symtabs;
	int 			 namelen;
	char 			 exename[];
};

static struct rb_root sessions = RB_ROOT;
static struct ftrace_session *first_session;

static void create_session(struct ftrace_msg_sess *msg, char *exename)
{
	struct ftrace_session *s;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions.rb_node;

	while (*p) {
		parent = *p;
		s = rb_entry(parent, struct ftrace_session, node);

		if (s->pid > msg->task.pid)
			p = &parent->rb_left;
		else if (s->pid < msg->task.pid)
			p = &parent->rb_right;
		else if (s->start_time > msg->task.time)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	s = xzalloc(sizeof(*s) + msg->namelen + 1);

	memcpy(s->sid, msg->sid, sizeof(s->sid));
	s->start_time = msg->task.time;
	s->pid = msg->task.pid;
	s->tid = msg->task.tid;
	s->namelen = msg->namelen;
	memcpy(s->exename, exename, s->namelen);
	s->exename[s->namelen] = 0;

	load_symtabs(&s->symtabs, s->exename);

	if (first_session == NULL)
		first_session = s;

	rb_link_node(&s->node, parent, p);
	rb_insert_color(&s->node, &sessions);
}

static struct ftrace_session *find_session(int pid, uint64_t timestamp)
{
	struct ftrace_session *iter;
	struct ftrace_session *s = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions.rb_node;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct ftrace_session, node);

		if (iter->pid > pid)
			p = &parent->rb_left;
		else if (iter->pid < pid)
			p = &parent->rb_right;
		else if (iter->start_time > timestamp)
			p = &parent->rb_left;
		else {
			s = iter;
			p = &parent->rb_right;
		}
	}

	return s;
}

struct ftrace_sess_ref {
	struct ftrace_sess_ref	*next;
	struct ftrace_session	*sess;
	uint64_t		 start, end;
};

struct ftrace_task {
	int			 pid, tid;
	struct rb_node		 node;
	struct ftrace_sess_ref	 sess;
	struct ftrace_sess_ref	*sess_last;
};

static struct rb_root task_tree = RB_ROOT;

static struct ftrace_task *find_task(int tid);

static void add_session_ref(struct ftrace_task *task, struct ftrace_session *sess,
			    uint64_t timestamp)
{
	struct ftrace_sess_ref *ref;

	assert(sess);

	if (task->sess_last) {
		task->sess_last->next = ref = xmalloc(sizeof(*ref));
		task->sess_last->end = timestamp;
	} else
		ref = &task->sess;

	ref->next = NULL;
	ref->sess = sess;
	ref->start = timestamp;
	ref->end = -1ULL;

	task->sess_last = ref;
}

static struct ftrace_session *find_task_session(int pid, uint64_t timestamp)
{
	struct ftrace_task *t;
	struct ftrace_sess_ref *r;
	struct ftrace_session *s = find_session(pid, timestamp);

	if (s)
		return s;

	/* if it cannot find its own session, inherit from parent or leader */
	t = find_task(pid);
	if (t == NULL)
		return NULL;

	r = &t->sess;
	while (r) {
		if (r->start <= timestamp && timestamp < r->end)
			return r->sess;
		r = r->next;
	}

	return NULL;
}

static void create_task(struct ftrace_msg_task *msg, bool fork)
{
	struct ftrace_task *t;
	struct ftrace_session *s;
	struct ftrace_sess_ref *r;
	struct rb_node *parent = NULL;
	struct rb_node **p = &task_tree.rb_node;

	while (*p) {
		parent = *p;
		t = rb_entry(parent, struct ftrace_task, node);

		if (t->tid > msg->tid)
			p = &parent->rb_left;
		else if (t->tid < msg->tid)
			p = &parent->rb_right;
		else {
			/* add new session */
			r = xmalloc(sizeof(*r));

			s = find_task_session(msg->pid, msg->time);
			add_session_ref(t, s, msg->time);

			pr_dbg("new session: tid = %d, session = %.16s\n",
			       t->tid, s->sid);
			return;
		}
	}

	t = xmalloc(sizeof(*t));

	t->pid = fork ? msg->tid : msg->pid;
	t->tid = msg->tid;
	t->sess_last = NULL;

	s = find_task_session(msg->pid, msg->time);
	add_session_ref(t, s, msg->time);

	pr_dbg("new task: tid = %d, session = %.16s\n", t->tid, s->sid);

	rb_link_node(&t->node, parent, p);
	rb_insert_color(&t->node, &task_tree);
}

static struct ftrace_task *find_task(int tid)
{
	struct ftrace_task *t;
	struct rb_node *parent = NULL;
	struct rb_node **p = &task_tree.rb_node;

	while (*p) {
		parent = *p;
		t = rb_entry(parent, struct ftrace_task, node);

		if (t->tid > tid)
			p = &parent->rb_left;
		else if (t->tid < tid)
			p = &parent->rb_right;
		else
			return t;
	}

	return NULL;
}

static int read_task_file(char *dirname)
{
	int fd;
	char pad[8];
	char buf[1024];
	struct ftrace_msg msg;
	struct ftrace_msg_task task;
	struct ftrace_msg_sess sess;

	snprintf(buf, sizeof(buf), "%s/task", dirname);
	fd = open(buf, O_RDONLY);
	if (fd < 0)
		pr_err("open task file");

	while (read_all(fd, &msg, sizeof(msg)) == 0) {
		if (msg.magic != FTRACE_MSG_MAGIC)
			return -1;

		switch (msg.type) {
		case FTRACE_MSG_SESSION:
			if (read_all(fd, &sess, sizeof(sess)) < 0)
				return -1;
			if (read_all(fd, buf, sess.namelen) < 0)
				return -1;
			if (sess.namelen % 8 &&
			    read_all(fd, pad, 8 - (sess.namelen % 8)) < 0)
				return -1;

			create_session(&sess, buf);

			if (map_file == NULL)
				asprintf(&map_file, "sid-%.16s.map", sess.sid);
			if (map_file == NULL)
				return -1;
			break;

		case FTRACE_MSG_TID:
			if (read_all(fd, &task, sizeof(task)) < 0)
				return -1;

			create_task(&task, false);
			break;

		case FTRACE_MSG_FORK_END:
			if (read_all(fd, &task, sizeof(task)) < 0)
				return -1;

			create_task(&task, true);
			break;

		default:
			pr_log("invalid contents in task file\n");
			return -1;
		}
	}

	close(fd);
	return 0;
}

int read_tid_list(int *tids, bool skip_unknown)
{
	int nr = 0;
	struct tid_list *tmp;

	list_for_each_entry(tmp, &tid_list_head, list) {
		if (tmp->tid == -1 && skip_unknown)
			continue;

		if (tids)
			tids[nr] = tmp->tid;

		nr++;
	}

	return nr;
}

void free_tid_list(void)
{
	struct tid_list *tl, *tmp;

	list_for_each_entry_safe(tl, tmp, &tid_list_head, list) {
		list_del(&tl->list);
		free(tl);
	}
}

bool check_tid_list(void)
{
	struct tid_list *tl;
	char buf[128];

	list_for_each_entry(tl, &tid_list_head, list) {
		int fd, len;
		char state;
		char line[4096];

		if (tl->exited || tl->tid < 0)
			continue;

		snprintf(buf, sizeof(buf), "/proc/%d/stat", tl->tid);

		fd = open(buf, O_RDONLY);
		if (fd < 0) {
			tl->exited = true;
			continue;
		}

		len = read(fd, line, sizeof(line) - 1);
		if (len < 0) {
			tl->exited = true;
			close(fd);
			continue;
		}

		line[len] = '\0';

		sscanf(line, "%*d %*s %c", &state);
		if (state == 'Z')
			tl->exited = true;

		close(fd);
	}

	list_for_each_entry(tl, &tid_list_head, list) {
		if (!tl->exited)
			return false;
	}

	pr_dbg("all process/thread exited\n");
	return true;
}

static bool child_exited;

static void sigchld_handler(int sig, siginfo_t *sainfo, void *context)
{
	int tid = sainfo->si_pid;
	struct tid_list *tl;

	list_for_each_entry(tl, &tid_list_head, list) {
		if (tl->tid == tid) {
			tl->exited = true;
			break;
		}
	}

	child_exited = true;
}

static int remove_directory(char *dirname)
{
	DIR *dp;
	struct dirent *ent;
	char buf[PATH_MAX];

	dp = opendir(dirname);
	if (dp == NULL)
		return -1;

	pr_dbg("removing %s directory\n", dirname);

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

static void print_child_time(struct timespec *ts1, struct timespec *ts2)
{
#define SEC_TO_NSEC  (1000000000ULL)

	uint64_t  sec = ts2->tv_sec  - ts1->tv_sec;
	uint64_t nsec = ts2->tv_nsec - ts1->tv_nsec;

	if (nsec > SEC_TO_NSEC) {
		nsec += SEC_TO_NSEC;
		sec--;
	}

	printf("elapsed time: %"PRIu64".%09"PRIu64" sec\n", sec, nsec);
}

static void print_child_usage(struct rusage *ru)
{
	printf(" system time: %lu.%06lu000 sec\n",
	       ru->ru_stime.tv_sec, ru->ru_stime.tv_usec);
	printf("   user time: %lu.%06lu000 sec\n",
	       ru->ru_utime.tv_sec, ru->ru_utime.tv_usec);
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
	struct sigaction sa = {
		.sa_flags = 0,
	};
	int remaining = 0;
	struct symtabs symtabs = {
		.loaded = false,
	};
	struct timespec ts1, ts2;
	struct rusage usage;
	pthread_t writer;
	struct ftrace_kernel kern;
	int efd;
	uint64_t go = 1;
	struct writer_arg warg = {
		.opts = opts,
		.kern = &kern,
	};

	snprintf(buf, sizeof(buf), "%s.old", opts->dirname);

	if (!access(buf, F_OK))
		remove_directory(buf);

	if (!access(opts->dirname, F_OK) && rename(opts->dirname, buf) < 0) {
		pr_log("rename %s -> %s failed: %s\n",
		       opts->dirname, buf, strerror(errno));
		/* don't care about the failure */
	}

	load_symtabs(&symtabs, opts->exename);

	for (i = 0; i < ARRAY_SIZE(profile_funcs); i++) {
		if (find_symname(&symtabs, profile_funcs[i]))
			break;
	}

	if (i == ARRAY_SIZE(profile_funcs) && !opts->force)
		pr_err(MCOUNT_MSG, "mcount", opts->exename);

	if (pipe(pfd) < 0)
		pr_err("cannot setup internal pipe");

	mkdir(opts->dirname, 0755);

	fflush(stdout);

	efd = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
	if (efd < 0)
		pr_dbg("creating eventfd failed: %d\n", efd);

	pid = fork();
	if (pid < 0)
		pr_err("cannot start child process");

	if (pid == 0) {
		uint64_t dummy;

		close(pfd[0]);

		setup_child_environ(opts, pfd[1], &symtabs);

		/* wait for parent ready */
		read(efd, &dummy, sizeof(dummy));

		/*
		 * I don't think the traced binary is in PATH.
		 * So use plain 'execv' rather than 'execvp'.
		 */
		execv(opts->exename, &argv[opts->idx]);
		abort();
	}

	clock_gettime(CLOCK_MONOTONIC, &ts1);
	close(pfd[1]);

	sa.sa_handler = sighandler;
	sigfillset(&sa.sa_mask);

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = NULL;
	sa.sa_sigaction = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
	sigaction(SIGCHLD, &sa, NULL);

	pthread_create(&writer, NULL, writer_thread, &warg);

	if (opts->kernel) {
		kern.pid = pid;
		kern.output_dir = opts->dirname;

		if (start_kernel_tracing(&kern) < 0) {
			opts->kernel = false;
			pr_log("kernel tracing disabled due to an error\n");
		}
	}

	/* signal child that I'm ready */
	write(efd, &go, sizeof(go));
	close(efd);

	while (!done) {
		struct pollfd pollfd = {
			.fd = pfd[0],
			.events = POLLIN,
		};
		int ret;

		ret = poll(&pollfd, 1, 1000);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			pr_err("error during poll");

		if (pollfd.revents & POLLIN)
			read_record_mmap(pfd[0], opts->dirname, opts->bsize);

		if (pollfd.revents & (POLLERR | POLLHUP))
			break;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts2);

	while (!done) {
		if (ioctl(pfd[0], FIONREAD, &remaining) < 0)
			break;

		if (remaining) {
			read_record_mmap(pfd[0], opts->dirname, opts->bsize);
			continue;
		}

		/*
		 * It's possible to receive a remaining FORK_START message.
		 * In this case, we need to wait FORK_END message also in
		 * order to get proper pid.  Otherwise replay will fail with
		 * pid of -1.
		 */
		if (child_exited && check_tid_list())
			break;

		pr_dbg2("waiting for FORK2\n");
		usleep(1000);
	}

	if (child_exited) {
		wait4(pid, &status, WNOHANG, &usage);
		if (WIFEXITED(status))
			pr_dbg("child terminated with exit code: %d\n",
			       WEXITSTATUS(status));
		else
			pr_dbg("child terminated by signal: %s\n",
			       strsignal(WTERMSIG(status)));
	} else {
		status = -1;
		getrusage(RUSAGE_CHILDREN, &usage);
	}

	flush_shmem_list(opts->dirname, opts->bsize);
	unlink_shmem_list();

	if (opts->kernel)
		stop_kernel_tracing(&kern);

	if (fill_file_header(opts, status, buf, sizeof(buf)) < 0)
		pr_err("cannot generate data file");

	if (opts->time) {
		print_child_time(&ts1, &ts2);
		print_child_usage(&usage);
	}

	if (shmem_lost_count)
		printf("LOST %d records\n", shmem_lost_count);

	pthread_join(writer, NULL);

	if (opts->kernel)
		finish_kernel_tracing(&kern);

	/*
	 * Do not unload symbol tables.  It might save some time when used by
	 * 'live' command as it also need to load the symtabs again.
	 */
	//unload_symtabs(&symtabs);
	return 0;
}

static struct ftrace_proc_maps *proc_maps;

static void read_map_file(char *filename, struct ftrace_proc_maps **maps)
{
	FILE *fp;
	char buf[PATH_MAX];

	fp = fopen(filename, "rb");
	if (fp == NULL)
		pr_err("cannot open maps file: %s", filename);

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

		map->next = *maps;
		*maps = map;
	}
	fclose(fp);
}

#define RECORD_MSG  "Was '%s' compiled with -pg or\n"		\
"\t-finstrument-functions flag and ran with ftrace record?\n"

static void reset_task_handle(void);

static int open_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	int ret = -1;
	FILE *fp;
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);

	fp = fopen(buf, "rb");
	if (fp == NULL) {
		if (errno == ENOENT) {
			pr_log("cannot find %s file!\n", buf);

			if (opts->exename)
				pr_err(RECORD_MSG, opts->exename);
		} else {
			pr_err("cannot open %s file", buf);
		}
		goto out;
	}

	handle->fp = fp;
	handle->dirname = opts->dirname;
	handle->depth = opts->depth;

	if (fread(&handle->hdr, sizeof(handle->hdr), 1, fp) != 1)
		pr_err("cannot read header data");

	if (memcmp(handle->hdr.magic, FTRACE_MAGIC_STR, FTRACE_MAGIC_LEN))
		pr_err("invalid magic string found!");

	if (handle->hdr.version < FTRACE_FILE_VERSION_MIN)
		pr_err("invalid vergion number found!");

	if (read_ftrace_info(handle->hdr.info_mask, handle) < 0)
		pr_err("cannot read ftrace header info!");

	fclose(fp);

	if (opts->exename == NULL)
		opts->exename = handle->info.exename;

	if (handle->hdr.feat_mask & TASK_SESSION) {
		if (read_task_file(opts->dirname) < 0)
			pr_err("invalid task file");
	} else
		map_file = "maps";

	snprintf(buf, sizeof(buf), "%s/%s", opts->dirname, map_file);
	read_map_file(buf, &proc_maps);

	reset_task_handle();

	ret = 0;

out:
	return ret;
}

static void close_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	struct ftrace_proc_maps *map;

	if (opts->exename == handle->info.exename)
		opts->exename = NULL;

	clear_ftrace_info(&handle->info);

	while (proc_maps) {
		map = proc_maps;
		proc_maps = map->next;

		free(map);
	}

	reset_task_handle();
}

#define FILTER_COUNT_NOTRACE  10000

struct ftrace_task_handle {
	int tid;
	bool valid;
	bool done;
	bool lost_seen;
	FILE *fp;
	struct sym *func;
	int filter_count;
	int filter_depth;
	struct ftrace_ret_stack rstack;
	int stack_count;
	int lost_count;
	struct fstack {
		unsigned long addr;
		bool valid;
		int orig_depth;
		uint64_t total_time;
		uint64_t child_time;
	} func_stack[MCOUNT_RSTACK_MAX];
};

struct ftrace_func_filter {
	bool has_filters;
	bool has_notrace;
	struct rb_root filters;
	struct rb_root notrace;
};

static struct ftrace_task_handle *tasks;
static int nr_tasks;

static struct ftrace_func_filter filters;

static void reset_task_handle(void)
{
	int i;

	for (i = 0; i < nr_tasks; i++) {
		tasks[i].done = true;

		if (tasks[i].fp) {
			fclose(tasks[i].fp);
			tasks[i].fp = NULL;
		}
	}

	free(tasks);
	tasks = NULL;

	nr_tasks = 0;
}

static void setup_task_filter(char *tid_filter, struct ftrace_file_handle *handle)
{
	int i, k;
	int nr_filters = 0;
	int *filter_tids = NULL;
	char *p = tid_filter;

	assert(tid_filter);

	do {
		int id;

		if (*p == ',' || *p == ':')
			p++;

		id = strtol(p, &p, 10);

		filter_tids = xrealloc(filter_tids, (nr_filters+1) * sizeof(int));
		filter_tids[nr_filters++] = id;

	} while (*p);

	nr_tasks = handle->info.nr_tid;
	tasks = xcalloc(sizeof(*tasks), nr_tasks);

	for (i = 0; i < nr_tasks; i++) {
		char *filename;
		bool found = false;
		int tid = handle->info.tids[i];

		tasks[i].tid = tid;

		for (k = 0; k < nr_filters; k++) {
			if (tid == filter_tids[k]) {
				found = true;
				break;
			}
		}

		if (!found) {
			tasks[i].done = true;
			continue;
		}

		if (asprintf(&filename, "%s/%d.dat", handle->dirname, tid) < 0)
			pr_err("cannot open task data file for %d", tid);

		tasks[i].fp = fopen(filename, "rb");
		if (tasks[i].fp == NULL)
			pr_err("cannot open task data file [%s]", filename);

		if (filters.has_filters)
			tasks[i].filter_count = 0;
		else
			tasks[i].filter_count = 1;

		pr_dbg("opening %s\n", filename);
		free(filename);
	}

	free(filter_tids);
}

static void update_filter_count_entry(struct ftrace_task_handle *task,
				      unsigned long addr, int depth)
{
	if (filters.has_filters && ftrace_match_filter(&filters.filters, addr)) {
		task->filter_count++;
		task->func_stack[task->stack_count-1].orig_depth = task->filter_depth;
		task->filter_depth = depth;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	} else if (filters.has_notrace && ftrace_match_filter(&filters.notrace, addr)) {
		task->filter_count -= FILTER_COUNT_NOTRACE;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	}
}

static void update_filter_count_exit(struct ftrace_task_handle *task,
				     unsigned long addr, int depth)
{
	if (filters.has_filters && ftrace_match_filter(&filters.filters, addr)) {
		task->filter_count--;
		task->filter_depth = task->func_stack[task->stack_count].orig_depth;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	} else if (filters.has_notrace && ftrace_match_filter(&filters.notrace, addr)) {
		task->filter_count += FILTER_COUNT_NOTRACE;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	}
}

static int read_task_rstack(struct ftrace_task_handle *handle)
{
	FILE *fp = handle->fp;

	if (fread(&handle->rstack, sizeof(handle->rstack), 1, fp) != 1) {
		if (feof(fp))
			return -1;

		pr_log("error reading rstack: %s\n", strerror(errno));
		return -1;
	}

	if (handle->rstack.unused != FTRACE_UNUSED) {
		pr_log("invalid rstack read\n");
		return -1;
	}

	return 0;
}

static struct ftrace_ret_stack *
get_task_rstack(struct ftrace_file_handle *handle, int idx)
{
	struct ftrace_task_handle *fth;
	char *filename;

	if (unlikely(idx >= nr_tasks)) {
		nr_tasks = idx + 1;
		tasks = xrealloc(tasks, sizeof(*tasks) * nr_tasks);

		memset(&tasks[idx], 0, sizeof(*tasks));

		if (asprintf(&filename, "%s/%d.dat",
			     handle->dirname, handle->info.tids[idx]) < 0)
			pr_err("cannot read task rstack for %d",
			       handle->info.tids[idx]);

		tasks[idx].tid = handle->info.tids[idx];
		tasks[idx].fp = fopen(filename, "rb");

		if (tasks[idx].fp == NULL) {
			pr_log("cannot open task data file [%s]\n", filename);
			tasks[idx].done = true;
			return NULL;
		}

		if (filters.has_filters)
			tasks[idx].filter_count = 0;
		else
			tasks[idx].filter_count = 1;

		tasks[idx].stack_count = 0;
		tasks[idx].filter_depth = handle->depth;

		pr_dbg("opening %s\n", filename);
		free(filename);
	}

	fth = &tasks[idx];

	if (fth->valid)
		return &fth->rstack;

	if (fth->done)
		return NULL;

	if (read_task_rstack(fth) < 0) {
		fth->done = true;
		fclose(fth->fp);
		fth->fp = NULL;
		return NULL;
	}

	if (fth->lost_seen) {
		int i;

		for (i = 0; i <= fth->rstack.depth; i++)
			fth->func_stack[i].valid = false;

		fth->lost_seen = false;
	}

	if (fth->rstack.type == FTRACE_ENTRY) {
		struct fstack *fstack = &fth->func_stack[fth->rstack.depth];

		fstack->total_time = fth->rstack.time;
		fstack->child_time = 0;
		fstack->valid = true;
		fstack->addr = fth->rstack.addr;

		fth->stack_count = fth->rstack.depth + 1;

	} else if (fth->rstack.type == FTRACE_EXIT) {
		uint64_t delta;
		struct fstack *fstack = &fth->func_stack[fth->rstack.depth];

		delta = fth->rstack.time - fstack->total_time;

		if (!fstack->valid)
			delta = 0UL;
		fstack->valid = false;

		fstack->total_time = delta;
		if (fstack->child_time > fstack->total_time)
			fstack->child_time = fstack->total_time;

		fth->stack_count = fth->rstack.depth;
		if (fth->stack_count > 0)
			fth->func_stack[fth->stack_count - 1].child_time += delta;

	} else if (fth->rstack.type == FTRACE_LOST) {
		fth->lost_seen = true;
	}

	fth->valid = true;
	return &fth->rstack;
}

static int __read_rstack(struct ftrace_file_handle *handle,
			 struct ftrace_task_handle **task, bool invalidate)
{
	int i, next_i = -1;
	uint64_t next_time;
	struct ftrace_ret_stack *tmp;

	for (i = 0; i < handle->info.nr_tid; i++) {
		tmp = get_task_rstack(handle, i);
		if (tmp == NULL)
			continue;

		if (next_i < 0 || tmp->time < next_time) {
			next_time = tmp->time;
			next_i = i;
		}
	}

	if (next_i < 0)
		return -1;

	*task = &tasks[next_i];
	if (invalidate)
		(*task)->valid = false;

	return 0;
}

static int read_rstack(struct ftrace_file_handle *handle,
		       struct ftrace_task_handle **task)
{
	return __read_rstack(handle, task, true);
}

static int peek_rstack(struct ftrace_file_handle *handle,
		       struct ftrace_task_handle **task)
{
	return __read_rstack(handle, task, false);
}

static int print_flat_rstack(struct ftrace_file_handle *handle,
			     struct ftrace_task_handle *task)
{
	static int count;
	struct ftrace_ret_stack *rstack = &task->rstack;
	struct ftrace_session *sess = find_task_session(task->tid, rstack->time);
	struct symtabs *symtabs;
	struct sym *sym;
	char *name;
	struct fstack *fstack;

	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtab(symtabs, rstack->addr, proc_maps);
	name = symbol_getname(sym, rstack->addr);
	fstack = &task->func_stack[rstack->depth];

	if (rstack->type == FTRACE_ENTRY) {
		printf("[%d] ==> %d/%d: ip (%s), time (%"PRIu64")\n",
		       count++, task->tid, rstack->depth,
		       name, rstack->time);
	} else if (rstack->type == FTRACE_EXIT) {
		printf("[%d] <== %d/%d: ip (%s), time (%"PRIu64":%"PRIu64")\n",
		       count++, task->tid, rstack->depth,
		       name, rstack->time, fstack->total_time);
	} else if (rstack->type == FTRACE_LOST) {
		printf("[%d] XXX %d: lost %d records\n",
		       count++, task->tid, (int)rstack->addr);
	}

	symbol_putname(sym, name);
	return 0;
}

static void print_time_unit(uint64_t delta_nsec)
{
	uint64_t delta = delta_nsec;
	uint64_t delta_small;
	char *unit[] = { "us", "ms", "s", "m", "h", };
	unsigned limit[] = { 1000, 1000, 1000, 60, 24, INT_MAX, };
	unsigned idx;

	if (delta_nsec == 0UL) {
		printf(" %7s %2s", "", "");
		return;
	}

	for (idx = 0; idx < ARRAY_SIZE(unit); idx++) {
		delta_small = delta % limit[idx];
		delta = delta / limit[idx];

		if (delta < limit[idx+1])
			break;
	}

	assert(idx < ARRAY_SIZE(unit));

	printf(" %3"PRIu64".%03"PRIu64" %2s", delta, delta_small, unit[idx]);
}

static int print_graph_no_merge_rstack(struct ftrace_file_handle *handle,
				       struct ftrace_task_handle *task)
{
	struct ftrace_ret_stack *rstack = &task->rstack;
	struct ftrace_session *sess;
	struct symtabs *symtabs;
	struct sym *sym;
	char *symname;

	if (task == NULL)
		return 0;

	sess = find_task_session(task->tid, rstack->time);
	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtab(symtabs, rstack->addr, proc_maps);
	symname = symbol_getname(sym, rstack->addr);

	if (rstack->type == FTRACE_ENTRY) {
		update_filter_count_entry(task, rstack->addr, handle->depth);
		if (task->filter_count <= 0)
			goto out;

		if (task->filter_depth-- <= 0)
			goto out;

		/* function entry */
		print_time_unit(0UL);
		printf(" [%5d] | %*s%s() {\n", task->tid,
		       rstack->depth * 2, "", symname);
	} else if (rstack->type == FTRACE_EXIT) {
		/* function exit */
		if (task->filter_count > 0 && task->filter_depth++ >= 0) {
			struct fstack *fstack;

			fstack= &task->func_stack[rstack->depth];
			print_time_unit(fstack->total_time);
			printf(" [%5d] | %*s} /* %s */\n", task->tid,
			       rstack->depth * 2, "", symname);
		}

		update_filter_count_exit(task, rstack->addr, handle->depth);
	} else if (rstack->type == FTRACE_LOST) {
		print_time_unit(0UL);
		printf(" [%5d] |     /* LOST %d records!! */\n",
		       task->tid, (int)rstack->addr);
	}
out:
	symbol_putname(sym, symname);
	return 0;
}

static int print_graph_rstack(struct ftrace_file_handle *handle,
			      struct ftrace_task_handle *task)
{
	struct ftrace_ret_stack *rstack = &task->rstack;
	struct ftrace_session *sess;
	struct symtabs *symtabs;
	struct sym *sym;
	char *symname;

	if (task == NULL)
		return 0;

	sess = find_task_session(task->tid, rstack->time);
	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtab(symtabs, rstack->addr, proc_maps);
	symname = symbol_getname(sym, rstack->addr);

	if (rstack->type == FTRACE_ENTRY) {
		struct ftrace_task_handle *next;
		struct fstack *fstack;
		int depth = rstack->depth;

		update_filter_count_entry(task, rstack->addr, handle->depth);
		if (task->filter_count <= 0)
			goto out;

		if (task->filter_depth-- <= 0)
			goto out;

		if (peek_rstack(handle, &next) < 0) {
			symbol_putname(sym, symname);
			return -1;
		}

		if (task == next &&
		    next->rstack.depth == depth &&
		    next->rstack.type == FTRACE_EXIT) {
			/* leaf function - also consume return record */
			fstack = &task->func_stack[rstack->depth];

			print_time_unit(fstack->total_time);
			printf(" [%5d] | %*s%s();\n", task->tid,
			       rstack->depth * 2, "", symname);

			/* consume the rstack */
			read_rstack(handle, &next);

			task->filter_depth++;
			update_filter_count_exit(task, next->rstack.addr, handle->depth);
		} else {
			/* function entry */
			print_time_unit(0UL);
			printf(" [%5d] | %*s%s() {\n", task->tid,
			       depth * 2, "", symname);
		}
	} else if (rstack->type == FTRACE_EXIT) {
		/* function exit */
		if (task->filter_count > 0 && task->filter_depth++ >= 0) {
			struct fstack *fstack;

			fstack = &task->func_stack[rstack->depth];

			print_time_unit(fstack->total_time);
			printf(" [%5d] | %*s} /* %s */\n", task->tid,
			       rstack->depth * 2, "", symname);
		}

		update_filter_count_exit(task, rstack->addr, handle->depth);

	} else if (rstack->type == FTRACE_LOST) {
		print_time_unit(0UL);
		printf(" [%5d] |     /* LOST %d records!! */\n",
		       task->tid, (int)rstack->addr);
	}
out:
	symbol_putname(sym, symname);
	return 0;
}

static void print_remaining_stack(void)
{
	int i;
	int total = 0;

	for (i = 0; i < nr_tasks; i++)
		total += tasks[i].stack_count;

	if (total == 0)
		return;

	printf("\nftrace stopped tracing with remaining functions");
	printf("\n===============================================\n");

	for (i = 0; i < nr_tasks; i++) {
		struct ftrace_task_handle *task = &tasks[i];

		if (task->stack_count == 0)
			continue;

		printf("task: %d\n", task->tid);

		while (task->stack_count-- > 0) {
			struct fstack *fstack = &task->func_stack[task->stack_count];
			uint64_t time = fstack->total_time;
			struct ftrace_session *sess = find_task_session(task->tid, time);
			struct symtabs *symtabs = &sess->symtabs;
			unsigned long ip = fstack->addr;
			struct sym *sym = find_symtab(symtabs, ip, proc_maps);
			char *symname = symbol_getname(sym, ip);

			printf("[%d] %s\n", task->stack_count, symname);

			symbol_putname(sym, symname);
		}
		printf("\n");
	}
}

static int command_replay(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
	struct ftrace_task_handle *task;
	struct sigaction sa = {
		.sa_flags = 0,
	};

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	if (opts->filter) {
		ftrace_setup_filter_regex(opts->filter, &first_session->symtabs,
					  &filters.filters, &filters.has_filters);
		if (!filters.has_filters)
			return -1;
	}

	if (opts->notrace) {
		ftrace_setup_filter_regex(opts->notrace, &first_session->symtabs,
					  &filters.notrace, &filters.has_notrace);
		if (!filters.has_notrace)
			return -1;
	}

	if (opts->tid)
		setup_task_filter(opts->tid, &handle);

	if (!opts->flat)
		printf("# DURATION    TID     FUNCTION\n");

	sa.sa_handler = sighandler;
	sigfillset(&sa.sa_mask);

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	while (read_rstack(&handle, &task) == 0 && !done) {
		if (opts->flat)
			ret = print_flat_rstack(&handle, task);
		else if (opts->no_merge)
			ret = print_graph_no_merge_rstack(&handle, task);
		else
			ret = print_graph_rstack(&handle, task);

		if (ret)
			break;
	}

	print_remaining_stack();

	close_data_file(opts, &handle);

	return ret;
}

static char *tmp_dirname;
static void cleanup_tempdir(void)
{
	DIR *dp;
	struct dirent *ent;
	char path[PATH_MAX];

	if (!tmp_dirname)
		return;

	dp = opendir(tmp_dirname);
	if (dp == NULL)
		pr_err("cannot open temp dir");

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", tmp_dirname, ent->d_name);
		if (unlink(path) < 0)
			pr_err("unlink failed: %s: %m\n", path);
	}

	closedir(dp);

	if (rmdir(tmp_dirname) < 0)
		pr_err("rmdir failed: %s: %m\n", tmp_dirname);
	tmp_dirname = NULL;
}

static void reset_live_opts(struct opts *opts)
{
	/*
	 * These options are handled in record and no need to do it in
	 * replay again.
	 */
	opts->filter	= NULL;
	opts->notrace	= NULL;
	opts->depth	= MCOUNT_DEFAULT_DEPTH;
}

static void sigsegv_handler(int sig)
{
	fprintf(stderr, "ftrace: ERROR: Segmentation fault\n");
	cleanup_tempdir();
	raise(sig);
}

static int command_live(int argc, char *argv[], struct opts *opts)
{
	char template[32] = "/tmp/ftrace-live-XXXXXX";
	int fd = mkstemp(template);
	struct sigaction sa = {
		.sa_flags = SA_RESETHAND,
	};

	if (fd < 0)
		pr_err("cannot create temp name");

	close(fd);
	unlink(template);

	tmp_dirname = template;
	atexit(cleanup_tempdir);

	sa.sa_handler = sigsegv_handler;
	sigfillset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, NULL);

	opts->dirname = template;

	if (command_record(argc, argv, opts) == 0) {
		reset_live_opts(opts);
		command_replay(argc, argv, opts);
	}

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

static void report_functions(struct ftrace_file_handle *handle)
{
	int i;
	struct sym *sym;
	struct trace_entry te;
	struct ftrace_ret_stack *rstack;
	struct rb_root name_tree = RB_ROOT;
	struct rb_root time_tree = RB_ROOT;
	struct rb_node *node;
	const char f_format[] = "  %-40.40s  %10.10s  %10.10s  %10.10s  \n";
	const char line[] = "=================================================";

	for (i = 0; i < handle->info.nr_tid; i++) {
		while ((rstack = get_task_rstack(handle, i)) != NULL) {
			struct ftrace_task_handle *fth = &tasks[i];
			struct ftrace_session *sess = find_task_session(fth->tid, rstack->time);
			struct symtabs *symtabs = &sess->symtabs;
			struct fstack *fstack = &fth->func_stack[rstack->depth];

			if (rstack->type == FTRACE_ENTRY)
				goto next;

			if (sess == NULL)
				goto next;

			sym = find_symtab(symtabs, rstack->addr, proc_maps);
			if (sym == NULL) {
				pr_log("cannot find symbol for %lx\n",
				       rstack->addr);
				goto next;
			}

			te.pid = fth->tid;
			te.sym = sym;
			te.time_total = fstack->total_time;
			te.time_self = te.time_total - fstack->child_time;
			te.nr_called = 1;

			insert_entry(&name_tree, &te, false);

		next:
			tasks[i].valid = false; /* force re-read */
		}
	}

	while (!RB_EMPTY_ROOT(&name_tree)) {
		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		sort_by_time(&time_tree, rb_entry(node, struct trace_entry, link));
	}

	printf(f_format, "Function", "Total time", "Self time", "Nr. called");
	printf(f_format, line, line, line, line);

	for (node = rb_first(&time_tree); node; node = rb_next(node)) {
		char *symname;
		struct trace_entry *entry;

		entry = rb_entry(node, struct trace_entry, link);

		symname = symbol_getname(entry->sym, 0);

		printf("  %-40.40s ", symname);
		print_time_unit(entry->time_total);
		putchar(' ');
		print_time_unit(entry->time_self);
		printf("  %10lu  \n", entry->nr_called);

		symbol_putname(entry->sym, symname);
	}

	while (!RB_EMPTY_ROOT(&time_tree)) {
		node = rb_first(&time_tree);
		rb_erase(node, &time_tree);

		free(rb_entry(node, struct trace_entry, link));
	}
}

static struct sym * find_task_sym(struct ftrace_file_handle *handle, int idx,
				  struct ftrace_ret_stack *rstack)
{
	struct sym *sym;
	struct ftrace_task_handle *task = &tasks[idx];
	struct ftrace_session *sess = find_task_session(task->tid, rstack->time);
	struct symtabs *symtabs = &sess->symtabs;

	if (task->func)
		return task->func;

	if (sess == NULL) {
		pr_log("cannot find session for tid %d\n", task->tid);
		return NULL;
	}

	if (idx == handle->info.nr_tid - 1) {
		/* This is the main thread */
		task->func = sym = find_symname(symtabs, "main");
		if (sym)
			return sym;

		pr_log("no main thread???\n");
		/* fall through */
	}

	task->func = sym = find_symtab(symtabs, rstack->addr, proc_maps);
	if (sym == NULL)
		pr_log("cannot find symbol for %lx\n", rstack->addr);

	return sym;
}

static void report_threads(struct ftrace_file_handle *handle)
{
	int i;
	struct trace_entry te;
	struct ftrace_ret_stack *rstack;
	struct rb_root name_tree = RB_ROOT;
	struct rb_node *node;
	struct ftrace_task_handle *task;
	struct fstack *fstack;
	const char t_format[] = "  %5.5s  %-40.40s  %10.10s  %10.10s  \n";
	const char line[] = "=================================================";

	for (i = 0; i < handle->info.nr_tid; i++) {
		while ((rstack = get_task_rstack(handle, i)) != NULL) {
			task = &tasks[i];

			if (rstack->type == FTRACE_ENTRY && task->func)
				goto next;

			te.pid = task->tid;
			te.sym = find_task_sym(handle, i, rstack);

			fstack = &task->func_stack[rstack->depth];

			if (rstack->type == FTRACE_ENTRY) {
				te.time_total = te.time_self = 0;
				te.nr_called = 0;
			} else if (rstack->type == FTRACE_EXIT) {
				te.time_total = fstack->total_time;
				te.time_self = te.time_total - fstack->child_time;
				te.nr_called = 1;
			}

			insert_entry(&name_tree, &te, true);

		next:
			tasks[i].valid = false; /* force re-read */
		}
	}

	printf(t_format, "TID", "Start function", "Run time", "Nr. funcs");
	printf(t_format, line, line, line, line);

	while (!RB_EMPTY_ROOT(&name_tree)) {
		char *symname;
		struct trace_entry *entry;

		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		entry = rb_entry(node, struct trace_entry, link);
		symname = symbol_getname(entry->sym, 0);

		printf("  %5d  %-40.40s ", entry->pid, symname);
		print_time_unit(entry->time_self);
		printf("  %10lu  \n", entry->nr_called);

		symbol_putname(entry->sym, symname);
	}

	while (!RB_EMPTY_ROOT(&name_tree)) {
		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		free(rb_entry(node, struct trace_entry, link));
	}
}

static int command_report(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	if (opts->tid)
		setup_task_filter(opts->tid, &handle);

	if (opts->report_thread)
		report_threads(&handle);
	else
		report_functions(&handle);

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

	if (handle.hdr.info_mask & (1UL << TASKINFO)) {
		int nr = handle.info.nr_tid;
		bool first = true;

		printf("# %-20s: %d\n", "nr of tasks", nr);

		printf("# %-20s: ", "task list");
		while (nr--) {
			printf("%s%d", first ? "" : ", ", handle.info.tids[nr]);
			first = false;
		}
		printf("\n");
	}

	printf("\n");

	close_data_file(opts, &handle);

	return ret;
}

static int command_dump(int argc, char *argv[], struct opts *opts)
{
	int i;
	int ret;
	char buf[PATH_MAX];
	struct ftrace_file_handle handle;
	struct ftrace_task_handle task;

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	for (i = 0; i < handle.info.nr_tid; i++) {
		int tid = handle.info.tids[i];

		snprintf(buf, sizeof(buf), "%s/%d.dat", opts->dirname, tid);
		task.fp = fopen(buf, "rb");
		if (task.fp == NULL)
			continue;

		printf("reading %d.dat\n", tid);
		while (!read_task_rstack(&task)) {
			struct ftrace_ret_stack *frs = &task.rstack;
			struct ftrace_session *sess = find_task_session(tid, frs->time);
			struct symtabs *symtabs;
			struct sym *sym;
			char *name;

			if (sess == NULL)
				continue;

			symtabs = &sess->symtabs;
			sym = find_symtab(symtabs, frs->addr, proc_maps);
			name = symbol_getname(sym, frs->addr);

			printf("%5d: [%s] %s(%lx) depth: %u\n",
			       tid, frs->type == FTRACE_EXIT ? "exit " : "entry",
			       name, (unsigned long)frs->addr, frs->depth);

			symbol_putname(sym, name);
		}

		fclose(task.fp);
	}

	close_data_file(opts, &handle);

	return ret;
}
