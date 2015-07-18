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
#include <gelf.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "ftrace"

#include "mcount.h"
#include "symbol.h"
#include "rbtree.h"
#include "utils.h"

const char *argp_program_version = "ftrace v0.3";
const char *argp_program_bug_address = "Namhyung Kim <namhyung.kim@lge.com>";

#define OPT_flat 	301
#define OPT_plthook 	302
#define OPT_symbols	303
#define OPT_logfile	304
#define OPT_force	305
#define OPT_threads	306
#define OPT_no_merge	307

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
	{ "logfile", OPT_logfile, "FILE", 0, "Save log messages to this file" },
	{ "force", OPT_force, 0, 0, "Trace even if executable is not instrumented" },
	{ "threads", OPT_threads, 0, 0, "Report thread stats instead" },
	{ "tid", 'T', "TID[,TID,...]", 0, "Only replay those tasks" },
	{ "no-merge", OPT_no_merge, 0, 0, "Don't merge leaf functions" },
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
	unsigned long bsize;
	bool flat;
	bool want_plthook;
	bool print_symtab;
	bool force;
	bool report_thread;
	bool no_merge;
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
		.mode = FTRACE_MODE_INVALID,
		.dirname = FTRACE_DIR_NAME,
		.want_plthook = true,
		.bsize = ~0UL,
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
		struct symtabs symtabs;

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

static void build_addrlist(struct symtabs *symtabs, char *buf, char *symlist)
{
	char *p = symlist;
	char *fname = strtok(p, ",:");

	buf[0] = '\0';
	while (fname) {
		struct sym *sym = find_symname(symtabs, fname);

		if (sym) {
			char tmp[64];

			snprintf(tmp, sizeof(tmp), "%s%#lx",
				 p ? "" : ":", sym->addr);
			strcat(buf, tmp);
		} else {
			pr_dbg("cannot find symbol: %s\n", fname);
			pr_dbg("skip setting filter..\n");
		}

		p = NULL;
		fname = strtok(p, ",:");
	}
}

static void setup_child_environ(struct opts *opts, int pfd, struct symtabs *symtabs)
{
	char buf[4096];
	const char *old_preload = getenv("LD_PRELOAD");
	const char *old_libpath = getenv("LD_LIBRARY_PATH");

	if (find_symname(symtabs, "__cyg_profile_func_enter"))
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
		build_addrlist(symtabs, buf, opts->filter);
		setenv("FTRACE_FILTER", buf, 1);
	}

	if (opts->notrace) {
		build_addrlist(symtabs, buf, opts->notrace);
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

	/* mcount code creates task and sid-XXX.map files */
	features |= 1U << TASK_SESSION;

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

struct tid_list {
	struct tid_list *next;
	int pid;
	int tid;
	bool exited;
};

static struct tid_list *tid_list_head;

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

static int record_mmap_file(const char *dirname, char *sess_id)
{
	int fd;
	char buf[128];
	char *ptr;
	size_t size;
	struct shmem_buffer *shmem_buf;

	/* write (append) it to disk */
	fd = shm_open(sess_id, O_RDONLY, 0400);
	if (fd < 0) {
		pr_log("open shmem buffer failed: %s: %m\n", sess_id);
		return 0;
	}

	shmem_buf = mmap(NULL, SHMEM_BUFFER_SIZE, PROT_READ,
			 MAP_SHARED, fd, 0);
	if (shmem_buf == MAP_FAILED)
		pr_err("mmap shmem buffer");

	close(fd);

	fd = open(make_disk_name(buf, sizeof(buf), dirname, sess_id),
		  O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd < 0)
		pr_err("open disk file");

	ptr  = shmem_buf->data;
	size = shmem_buf->size;

	if (write_all(fd, ptr, size) < 0)
		pr_err("write shmem buffer");

	close(fd);

	munmap(shmem_buf, SHMEM_BUFFER_SIZE);

	/* it's no longer used */
	shm_unlink(sess_id);
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

static void flush_shmem_list(const char *dirname)
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

static void flush_old_shmem(const char *dirname, int tid)
{
	struct shmem_list *curr, *prev;

	/* flush old session (due to exec) */
	prev = NULL;
	curr = shmem_list_head;

	while (curr) {
		int tmp_id;

		sscanf(curr->id, "/ftrace-%*x-%d-%*d", &tmp_id);

		if (tid == tmp_id) {
			if (prev)
				prev->next = curr->next;
			else
				shmem_list_head = curr->next;

			pr_dbg("flushing %s\n", curr->id);

			record_mmap_file(dirname, curr->id);
			free(curr);
			return;
		}

		prev = curr;
		curr = prev->next;
	}
}

static void read_record_mmap(int pfd, const char *dirname)
{
	char buf[128];
	struct shmem_list *sl, **psl;
	struct tid_list *tl, *pos;
	struct ftrace_msg msg;
	struct ftrace_msg_task tmsg;
	struct ftrace_msg_sess sess;
	char *exename;

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
		sl->next = shmem_list_head;
		shmem_list_head = sl;
		break;

	case FTRACE_MSG_REC_END:
		if (msg.len > SHMEM_NAME_SIZE)
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, buf, msg.len) < 0)
			pr_err("reading pipe failed");

		buf[msg.len] = '\0';
		pr_dbg("MSG  END : %s\n", buf);

		psl = &shmem_list_head;

		/* remove from shmem_list */
		while (*psl) {
			sl = *psl;

			if (!strncmp(sl->id, buf, SHMEM_NAME_SIZE)) {
				*psl = sl->next;

				free(sl);
				break;
			}

			psl = &sl->next;
		}

		record_mmap_file(dirname, buf);
		break;

	case FTRACE_MSG_TID:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		pr_dbg("MSG  TID : %d/%d\n", tmsg.pid, tmsg.tid);

		/* check existing tid (due to exec) */
		pos = tid_list_head;
		while (pos) {
			if (pos->tid == tmsg.tid) {
				flush_old_shmem(dirname, tmsg.tid);
				break;
			}

			pos = pos->next;
		}

		if (pos == NULL) {
			tl = xmalloc(sizeof(*tl));

			tl->pid = tmsg.pid;
			tl->tid = tmsg.tid;
			tl->exited = false;

			/* link to tid_list */
			tl->next = tid_list_head;
			tid_list_head = tl;
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

		pr_dbg("MSG FORK1: start\n");

		tl->exited = false;

		/* link to tid_list */
		tl->next = tid_list_head;
		tid_list_head = tl;
		break;

	case FTRACE_MSG_FORK_END:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		tl = tid_list_head;
		while (tl) {
			if (tl->pid == tmsg.pid && tl->tid == -1)
				break;
			tl = tl->next;
		}
		if (tl == NULL)
			pr_err("cannot find fork pid\n");

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
	struct tid_list *tl = tid_list_head;

	while (tl) {
		struct tid_list *tmp = tl;
		tl = tl->next;

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
	struct tid_list *tl = tid_list_head;

	while (tl) {
		struct tid_list *tmp = tl;
		tl = tl->next;

		free(tmp);
	}

	tid_list_head = NULL;
}

bool check_tid_list(void)
{
	struct tid_list *tl = tid_list_head;
	char buf[128];

	while (tl) {
		int fd, len;
		char state;
		char line[4096];
		struct tid_list *tmp = tl;
		tl = tl->next;

		if (tmp->exited || tmp->tid < 0)
			continue;

		snprintf(buf, sizeof(buf), "/proc/%d/stat", tmp->tid);

		fd = open(buf, O_RDONLY);
		if (fd < 0) {
			tmp->exited = true;
			continue;
		}

		len = read(fd, line, sizeof(line) - 1);
		if (len < 0) {
			tmp->exited = true;
			close(fd);
			continue;
		}

		line[len] = '\0';

		sscanf(line, "%*d %*s %c", &state);
		if (state == 'Z')
			tmp->exited = true;

		close(fd);
	}

	tl = tid_list_head;
	while (tl) {
		struct tid_list *tmp = tl;
		tl = tl->next;

		if (!tmp->exited)
			return false;
	}

	pr_dbg("all process/thread exited\n");
	return true;
}

static bool child_exited;

static void sigchld_handler(int sig, siginfo_t *sainfo, void *context)
{
	int tid = sainfo->si_pid;
	struct tid_list *tl = tid_list_head;

	while (tl) {
		struct tid_list *tmp = tl;
		tl = tl->next;

		if (tmp->tid == tid) {
			tmp->exited = true;
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
	struct symtabs symtabs;

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

	pid = fork();
	if (pid < 0)
		pr_err("cannot start child process");

	if (pid == 0) {
		close(pfd[0]);

		setup_child_environ(opts, pfd[1], &symtabs);

		/*
		 * I don't think the traced binary is in PATH.
		 * So use plain 'execv' rather than 'execvp'.
		 */
		execv(opts->exename, &argv[opts->idx]);
		abort();
	}

	close(pfd[1]);

	sa.sa_handler = sighandler;
	sigfillset(&sa.sa_mask);

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = NULL;
	sa.sa_sigaction = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
	sigaction(SIGCHLD, &sa, NULL);

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
			read_record_mmap(pfd[0], opts->dirname);

		if (pollfd.revents & (POLLERR | POLLHUP))
			break;
	}

	while (!done) {
		if (ioctl(pfd[0], FIONREAD, &remaining) < 0)
			break;

		if (remaining) {
			read_record_mmap(pfd[0], opts->dirname);
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
		waitpid(pid, &status, WNOHANG);
		if (WIFEXITED(status))
			pr_dbg("child terminated with exit code: %d\n",
			       WEXITSTATUS(status));
		else
			pr_dbg("child terminated by signal: %s\n",
			       strsignal(WTERMSIG(status)));
	} else {
		status = -1;
	}

	flush_shmem_list(opts->dirname);

	if (fill_file_header(opts, status, buf, sizeof(buf)) < 0)
		pr_err("cannot generate data file");

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
		pr_err("cannot open maps file");

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
	FILE *fp;
	struct sym *func;
	int filter_count;
	int filter_depth;
	struct mcount_ret_stack rstack;
	int stack_count;
	struct {
		unsigned long ip;
		uint64_t time;
	} func_stack[MCOUNT_RSTACK_MAX];
};

struct ftrace_func_filter {
	int nr_filters;
	int nr_notrace;
	unsigned long *filters;
	unsigned long *notrace;
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

		if (filters.nr_filters)
			tasks[i].filter_count = 0;
		else
			tasks[i].filter_count = 1;

		pr_dbg("opening %s\n", filename);
		free(filename);
	}

	free(filter_tids);
}

static int setup_function_filter(unsigned long **filters, char *filter_str)
{
	char buf[4096];
	char *pos = buf;
	int count = 0;

	build_addrlist(&first_session->symtabs, buf, filter_str);

	do {
		unsigned long addr;
		unsigned long *new_filters;

		addr = strtoul(pos, &pos, 16);
		if (*pos != ':' && *pos != '\0')
			return -1;

		new_filters = realloc(*filters, (count + 1) * sizeof(**filters));
		if (new_filters == NULL)
			return -1;

		new_filters[count++] = addr;
		*filters = new_filters;
	} while (*pos == ':');

	return count;
}

static struct ftrace_task_handle *get_task_handle(int pid)
{
	int i;

	for (i = 0; i < nr_tasks; i++) {
		if (tasks[i].tid == pid)
			return &tasks[i];
	}
	return NULL;
}

static int match_filter_addr(unsigned long *filters, int nr_filters, unsigned long addr)
{
	int i;

	for (i = 0; i < nr_filters; i++) {
		if (addr == filters[i])
			return 1;
	}
	return 0;
}

static void update_filter_count_entry(struct ftrace_task_handle *task, unsigned long addr)
{
	if (filters.nr_filters && match_filter_addr(filters.filters,
						    filters.nr_filters,
						    addr)) {
		task->filter_count++;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	} else if (filters.nr_notrace && match_filter_addr(filters.notrace,
							   filters.nr_notrace,
							   addr)) {
		task->filter_count -= FILTER_COUNT_NOTRACE;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	}
}

static void update_filter_count_exit(struct ftrace_task_handle *task, unsigned long addr)
{
	if (filters.nr_filters && match_filter_addr(filters.filters,
						    filters.nr_filters,
						    addr)) {
		task->filter_count--;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	} else if (filters.nr_notrace && match_filter_addr(filters.notrace,
							   filters.nr_notrace,
							   addr)) {
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
	return 0;
}

static struct mcount_ret_stack *
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

		if (filters.nr_filters)
			tasks[idx].filter_count = 0;
		else
			tasks[idx].filter_count = 1;

		tasks[idx].stack_count = 0;

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

	if (fth->rstack.end_time == 0) {
		fth->func_stack[fth->stack_count].time = fth->rstack.start_time;
		fth->func_stack[fth->stack_count].ip = fth->rstack.child_ip;
		fth->stack_count++;
	} else if (fth->stack_count > 0)
		fth->stack_count--;

	fth->valid = true;
	return &fth->rstack;
}

static uint64_t rstack_time(struct mcount_ret_stack *rstack)
{
	assert(rstack->end_time || rstack->start_time);

	return rstack->end_time ? : rstack->start_time;
}

static int __read_rstack(struct ftrace_file_handle *handle,
			 struct mcount_ret_stack *rstack, bool invalidate)
{
	int i, next_i = 0;
	struct mcount_ret_stack *tmp, *next = NULL;

	for (i = 0; i < handle->info.nr_tid; i++) {
		tmp = get_task_rstack(handle, i);
		if (tmp == NULL)
			continue;

		if (!next || rstack_time(tmp) < rstack_time(next)) {
			next = tmp;
			next_i = i;
		}
	}

	if (next == NULL)
		return -1;

	memcpy(rstack, next, sizeof(*rstack));
	if (invalidate)
		tasks[next_i].valid = false;

	return 0;
}

static int read_rstack(struct ftrace_file_handle *handle,
		       struct mcount_ret_stack *rstack)
{
	return __read_rstack(handle, rstack, true);
}

static int peek_rstack(struct ftrace_file_handle *handle,
		       struct mcount_ret_stack *rstack)
{
	return __read_rstack(handle, rstack, false);
}

static int print_flat_rstack(struct ftrace_file_handle *handle,
			     struct mcount_ret_stack *rstack)
{
	static int count;
	struct ftrace_session *sess = find_task_session(rstack->tid, rstack_time(rstack));
	struct symtabs *symtabs = &sess->symtabs;
	struct sym *parent = find_symtab(symtabs, rstack->parent_ip, proc_maps);
	struct sym *child = find_symtab(symtabs, rstack->child_ip, proc_maps);
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

static int print_graph_no_merge_rstack(struct ftrace_file_handle *handle,
				       struct mcount_ret_stack *rstack)
{
	struct ftrace_task_handle *task = get_task_handle(rstack->tid);
	struct ftrace_session *sess;
	struct symtabs *symtabs;
	struct sym *sym;
	char *symname;

	if (task == NULL)
		return 0;

	sess = find_task_session(rstack->tid, rstack_time(rstack));
	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtab(symtabs, rstack->child_ip, proc_maps);
	symname = symbol_getname(sym, rstack->child_ip);

	if (rstack->end_time == 0) {
		update_filter_count_entry(task, rstack->child_ip);
		if (task->filter_count <= 0)
			goto out;

		/* function entry */
		print_time_unit(0UL, 0UL);
		printf(" [%5d] | %*s%s() {\n", rstack->tid,
		       rstack->depth * 2, "", symname);
	} else {
		/* function exit */
		if (task->filter_count > 0) {
			print_time_unit(rstack->start_time, rstack->end_time);
			printf(" [%5d] | %*s} /* %s */\n", rstack->tid,
			       rstack->depth * 2, "", symname);
		}

		update_filter_count_exit(task, rstack->child_ip);
	}
out:
	symbol_putname(sym, symname);
	return 0;
}

static int print_graph_rstack(struct ftrace_file_handle *handle,
			      struct mcount_ret_stack *rstack)
{
	struct ftrace_task_handle *task = get_task_handle(rstack->tid);
	struct ftrace_session *sess;
	struct symtabs *symtabs;
	struct sym *sym;
	char *symname;

	if (task == NULL)
		return 0;

	sess = find_task_session(rstack->tid, rstack_time(rstack));
	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtab(symtabs, rstack->child_ip, proc_maps);
	symname = symbol_getname(sym, rstack->child_ip);

	if (rstack->end_time == 0) {
		struct mcount_ret_stack rstack_next;

		update_filter_count_entry(task, rstack->child_ip);
		if (task->filter_count <= 0)
			goto out;

		if (peek_rstack(handle, &rstack_next) < 0) {
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

			/* consume the rstack */
			read_rstack(handle, &rstack_next);

			update_filter_count_exit(task, rstack_next.child_ip);
		} else {
			/* function entry */
			print_time_unit(0UL, 0UL);
			printf(" [%5d] | %*s%s() {\n", rstack->tid,
			       rstack->depth * 2, "", symname);
		}
	} else {
		/* function exit */
		if (task->filter_count > 0) {
			print_time_unit(rstack->start_time, rstack->end_time);
			printf(" [%5d] | %*s} /* %s */\n", rstack->tid,
			       rstack->depth * 2, "", symname);
		}

		update_filter_count_exit(task, rstack->child_ip);
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
			uint64_t time = task->func_stack[task->stack_count].time;
			struct ftrace_session *sess = find_task_session(task->tid, time);
			struct symtabs *symtabs = &sess->symtabs;
			unsigned long ip = task->func_stack[task->stack_count].ip;
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
	struct mcount_ret_stack rstack;

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	if (opts->filter) {
		filters.nr_filters = setup_function_filter(&filters.filters,
							   opts->filter);
		if (filters.nr_filters < 0)
			return -1;
	}

	if (opts->notrace) {
		filters.nr_notrace = setup_function_filter(&filters.notrace,
							   opts->notrace);
		if (filters.nr_notrace < 0)
			return -1;
	}

	if (opts->tid)
		setup_task_filter(opts->tid, &handle);

	if (!opts->flat)
		printf("# DURATION    TID     FUNCTION\n");

	while (read_rstack(&handle, &rstack) == 0) {
		if (opts->flat)
			ret = print_flat_rstack(&handle, &rstack);
		else if (opts->no_merge)
			ret = print_graph_no_merge_rstack(&handle, &rstack);
		else
			ret = print_graph_rstack(&handle, &rstack);

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

static int command_live(int argc, char *argv[], struct opts *opts)
{
	char template[32] = "/tmp/ftrace-live-XXXXXX";
	int fd = mkstemp(template);
	if (fd < 0)
		pr_err("cannot create temp name");

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

static void report_functions(struct ftrace_file_handle *handle)
{
	int i;
	struct sym *sym;
	struct trace_entry te;
	struct mcount_ret_stack *rstack;
	struct rb_root name_tree = RB_ROOT;
	struct rb_root time_tree = RB_ROOT;
	struct rb_node *node;
	const char f_format[] = "  %-40.40s  %10.10s  %10.10s  %10.10s  \n";
	const char line[] = "=================================================";

	for (i = 0; i < handle->info.nr_tid; i++) {
		while ((rstack = get_task_rstack(handle, i)) != NULL) {
			struct ftrace_session *sess = find_task_session(rstack->tid, rstack_time(rstack));
			struct symtabs *symtabs = &sess->symtabs;

			if (rstack->end_time == 0)
				goto next;

			if (sess == NULL)
				goto next;

			sym = find_symtab(symtabs, rstack->child_ip, proc_maps);
			if (sym == NULL) {
				pr_log("cannot find symbol for %lx\n",
				       rstack->child_ip);
				goto next;
			}

			te.pid = rstack->tid;
			te.sym = sym;
			te.time_total = rstack->end_time - rstack->start_time;
			te.time_self = te.time_total - rstack->child_time;
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
		print_time_unit(0UL, entry->time_total);
		putchar(' ');
		print_time_unit(0UL, entry->time_self);
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
				  struct mcount_ret_stack *rstack)
{
	struct sym *sym;
	struct ftrace_session *sess = find_task_session(rstack->tid, rstack_time(rstack));
	struct symtabs *symtabs = &sess->symtabs;

	if (tasks[idx].func)
		return tasks[idx].func;

	if (sess == NULL) {
		pr_log("cannot find session for tid %d\n", rstack->tid);
		return NULL;
	}

	if (idx == handle->info.nr_tid - 1) {
		/* This is the main thread */
		tasks[idx].func = sym = find_symname(symtabs, "main");
		if (sym)
			return sym;

		pr_log("no main thread???\n");
		/* fall through */
	}

	tasks[idx].func = sym = find_symtab(symtabs, rstack->child_ip, proc_maps);
	if (sym == NULL) {
		pr_log("cannot find symbol for %lx\n",
		       rstack->child_ip);
	}

	return sym;
}

static void report_threads(struct ftrace_file_handle *handle)
{
	int i;
	struct trace_entry te;
	struct mcount_ret_stack *rstack;
	struct rb_root name_tree = RB_ROOT;
	struct rb_node *node;
	const char t_format[] = "  %5.5s  %-40.40s  %10.10s  %10.10s  \n";
	const char line[] = "=================================================";

	for (i = 0; i < handle->info.nr_tid; i++) {
		while ((rstack = get_task_rstack(handle, i)) != NULL) {
			if (!rstack->end_time && tasks[i].func)
				goto next;

			te.pid = rstack->tid;
			te.sym = find_task_sym(handle, i, rstack);

			if (rstack->end_time == 0) {
				te.time_total = te.time_self = 0;
				te.nr_called = 0;
			} else {
				te.time_total = rstack->end_time - rstack->start_time;
				te.time_self = te.time_total - rstack->child_time;
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
		print_time_unit(0UL, entry->time_self);
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
			struct mcount_ret_stack *mrs = &task.rstack;
			struct ftrace_session *sess = find_task_session(mrs->tid, rstack_time(mrs));
			struct symtabs *symtabs = &sess->symtabs;
			struct sym *parent = find_symtab(symtabs, mrs->parent_ip, proc_maps);
			struct sym *child = find_symtab(symtabs, mrs->child_ip, proc_maps);
			char *parent_name = symbol_getname(parent, mrs->parent_ip);
			char *child_name = symbol_getname(child, mrs->child_ip);

			printf("%5d: [%s] %s(%lx)/%s(%lx) depth: %u\n",
			       mrs->tid, mrs->end_time ? "exit " : "entry",
			       parent_name, mrs->parent_ip,
			       child_name, mrs->child_ip, mrs->depth);

			symbol_putname(parent, parent_name);
			symbol_putname(child, child_name);
		}

		fclose(task.fp);
	}

	close_data_file(opts, &handle);

	return ret;
}
