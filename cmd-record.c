#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/resource.h>

#include "ftrace.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/list.h"

#define SHMEM_NAME_SIZE (64 - (int)sizeof(void*))

struct shmem_list {
	struct list_head list;
	char id[SHMEM_NAME_SIZE];
};

static LIST_HEAD(shmem_list_head);
static LIST_HEAD(shmem_need_unlink);

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


static bool can_use_fast_libmcount(struct opts *opts)
{
	if (opts->filter || opts->trigger || debug)
		return false;
	if (opts->depth != MCOUNT_DEFAULT_DEPTH)
		return false;
	return true;
}

static void setup_child_environ(struct opts *opts, int pfd, struct symtabs *symtabs)
{
	char buf[4096];
	const char *old_preload = getenv("LD_PRELOAD");
	const char *old_libpath = getenv("LD_LIBRARY_PATH");
	bool multi_thread = !!find_symname(&symtabs->dsymtab, "pthread_create");

	if (opts->lib_path)
		snprintf(buf, sizeof(buf), "%s/libmcount/", opts->lib_path);
	else
		buf[0] = '\0';  /* to make strcat() work */

	if (opts->nop) {
		strcat(buf, "libmcount-nop.so");
	}
	else if (multi_thread) {
		if (can_use_fast_libmcount(opts))
			strcat(buf, "libmcount-fast.so");
		else
			strcat(buf, "libmcount.so");
	}
	else {
		if (can_use_fast_libmcount(opts))
			strcat(buf, "libmcount-fast-single.so");
		else
			strcat(buf, "libmcount-single.so");
	}
	pr_dbg("using %s library for tracing\n", buf);

	if (old_preload) {
		strcat(buf, ":");
		strcat(buf, old_preload);
	}
	setenv("LD_PRELOAD", buf, 1);

	if (opts->lib_path) {
		strcpy(buf, opts->lib_path);
		strcat(buf, "/libmcount:");
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

	if (opts->filter)
		setenv("FTRACE_FILTER", opts->filter, 1);

	if (opts->trigger)
		setenv("FTRACE_TRIGGER", opts->trigger, 1);

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
		snprintf(buf, sizeof(buf), "%d", fileno(logfp));
		setenv("FTRACE_LOGFD", buf, 1);
	}

	snprintf(buf, sizeof(buf), "%d", pfd);
	setenv("FTRACE_PIPE", buf, 1);
	setenv("FTRACE_SHMEM", "1", 1);

	if (debug) {
		snprintf(buf, sizeof(buf), "%d", debug);
		setenv("FTRACE_DEBUG", buf, 1);
	}

	if (opts->color) {
		snprintf(buf, sizeof(buf), "%d", opts->color);
		setenv("FTRACE_COLOR", buf, 1);
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

static int fill_file_header(struct opts *opts, int status, struct rusage *rusage)
{
	int fd, efd;
	int ret = -1;
	char *filename = NULL;
	struct ftrace_file_header hdr;
	char elf_ident[EI_NIDENT];

	xasprintf(&filename, "%s/info", opts->dirname);
	pr_dbg("fill header (metadata) info in %s\n", filename);

	fd = open(filename, O_WRONLY | O_CREAT| O_TRUNC, 0644);
	if (fd < 0) {
		pr_log("cannot open info file: %s\n", strerror(errno));
		free(filename);
		return -1;
	}

	efd = open(opts->exename, O_RDONLY);
	if (efd < 0)
		goto close_fd;

	if (read(efd, elf_ident, sizeof(elf_ident)) < 0)
		goto close_efd;

	strncpy(hdr.magic, FTRACE_MAGIC_STR, FTRACE_MAGIC_LEN);
	hdr.version = FTRACE_FILE_VERSION;
	hdr.header_size = sizeof(hdr);
	hdr.endian = elf_ident[EI_DATA];
	hdr.class = elf_ident[EI_CLASS];
	hdr.feat_mask = calc_feat_mask(opts);
	hdr.info_mask = 0;
	hdr.unused = 0;

	if (write(fd, &hdr, sizeof(hdr)) != (int)sizeof(hdr))
		pr_err("writing header info failed");

	fill_ftrace_info(&hdr.info_mask, fd, opts, status, rusage);

try_write:
	ret = pwrite(fd, &hdr, sizeof(hdr), 0);
	if (ret != (int)sizeof(hdr)) {
		static int retry = 0;

		if (ret > 0 && retry++ < 3)
			goto try_write;

		pr_log("writing header info failed.\n");
		goto close_efd;
	}

	ret = 0;

close_efd:
	close(efd);
close_fd:
	close(fd);
	free(filename);

	return ret;
}

static void parse_msg_id(char *id, uint64_t *sid, int *tid, int *seq)
{
	uint64_t _sid;
	unsigned _tid;
	unsigned _seq;

	/*
	 * parse message id of "/ftrace-SESSION-TID-SEQ".
	 */
	if (sscanf(id, "/ftrace-%016"SCNx64"-%u-%03u", &_sid, &_tid, &_seq) != 3)
		pr_err("parse msg id failed");

	if (sid)
		*sid = _sid;
	if (tid)
		*tid = _tid;
	if (seq)
		*seq = _seq;
}

static char *make_disk_name(const char *dirname, char *id)
{
	int tid;
	char *filename = NULL;

	parse_msg_id(id, NULL, &tid, NULL);
	xasprintf(&filename, "%s/%d.dat", dirname, tid);

	return filename;
}

static int write_buffer_file(const char *dirname, struct buf_list *buf)
{
	int fd;
	char *filename;

	filename = make_disk_name(dirname, buf->id);
	fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd < 0)
		pr_err("open disk file");

	if (write_all(fd, buf->data, buf->len) < 0)
		pr_err("write shmem buffer");

	close(fd);
	free(filename);
	return 0;
}

struct writer_arg {
	struct opts		*opts;
	struct ftrace_kernel	*kern;
	int			sock;
};

void *writer_thread(void *arg)
{
	struct buf_list *buf;
	struct writer_arg *warg = arg;
	struct opts *opts = warg->opts;

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

		if (opts->host) {
			int tid = 0;

			parse_msg_id(buf->id, NULL, &tid, NULL);
			send_trace_data(warg->sock, tid, buf->data, buf->len);
		} else {
			write_buffer_file(opts->dirname, buf);
		}

		pthread_mutex_lock(&free_list_lock);
		list_add(&buf->list, &buf_free_list);
		pthread_mutex_unlock(&free_list_lock);

		if (opts->kernel)
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

struct tid_list {
	struct list_head list;
	int pid;
	int tid;
	bool exited;
};

static LIST_HEAD(tid_list_head);

static void add_tid_list(int pid, int tid)
{
	struct tid_list *tl;

	tl = xmalloc(sizeof(*tl));

	tl->pid = pid;
	tl->tid = tid;
	tl->exited = false;

	/* link to tid_list */
	list_add(&tl->list, &tid_list_head);
}

static void free_tid_list(void)
{
	struct tid_list *tl, *tmp;

	list_for_each_entry_safe(tl, tmp, &tid_list_head, list) {
		list_del(&tl->list);
		free(tl);
	}
}

static bool check_tid_list(void)
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

		if (list_no_entry(pos, &tid_list_head, list))
			add_tid_list(tmsg.pid, tmsg.tid);

		record_task_file(dirname, &msg, sizeof(msg));
		record_task_file(dirname, &tmsg, sizeof(tmsg));
		break;

	case FTRACE_MSG_FORK_START:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		pr_dbg("MSG FORK1: %d/%d\n", tmsg.pid, -1);

		add_tid_list(tmsg.pid, -1);
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

static void send_task_file(int sock, const char *dirname, struct symtabs *symtabs)
{
	FILE *fp;
	char *filename = NULL;
	struct ftrace_msg msg;
	struct ftrace_msg_task tmsg;
	struct ftrace_msg_sess smsg;
	int namelen;
	char *exename;

	xasprintf(&filename, "%s/task", dirname);

	fp = fopen(filename, "r");
	if (fp == NULL)
		pr_err("open task file failed");

	while (fread_all(&msg, sizeof(msg), fp) == 0) {
		if (msg.magic  != FTRACE_MSG_MAGIC) {
			pr_err_ns("invalid message in task file: %x\n",
				  msg.magic);
		}

		switch (msg.type) {
		case FTRACE_MSG_TID:
		case FTRACE_MSG_FORK_END:
			if (fread_all(&tmsg, sizeof(tmsg), fp) < 0)
				pr_err("read task message failed");

			send_trace_task(sock, &msg, &tmsg);
			break;

		case FTRACE_MSG_SESSION:
			if (fread_all(&smsg, sizeof(smsg), fp) < 0)
				pr_err("read session message failed");

			namelen = ALIGN(smsg.namelen, 8);
			exename = xmalloc(namelen);
			if (fread_all(exename, namelen, fp) < 0)
				pr_err("read exename failed");

			send_trace_session(sock, &msg, &smsg, exename, namelen);
			save_symbol_file(symtabs, dirname, exename);
			free(exename);
			break;

		default:
			pr_err_ns("unknown task file message: %d\n", msg.type);
			break;
		}
	}

	if (!feof(fp))
		pr_err_ns("read task file failed\n");

	fclose(fp);
	free(filename);
}

/* find "sid-XXX.map" file */
static int filter_map(const struct dirent *de)
{
	size_t len = strlen(de->d_name);

	return !strncmp("sid-", de->d_name, 4) &&
	       !strncmp(".map", de->d_name + len - 4, 4);
}

static void send_map_files(int sock, const char *dirname)
{
	int dir_fd;
	int i, maps;
	int map_fd;
	uint64_t sid;
	struct dirent **map_list;
	struct stat stbuf;
	void *map;
	int len;

	dir_fd = open(dirname, O_PATH | O_DIRECTORY);
	if (dir_fd < 0)
		pr_err("dir open failed");

	maps = scandirat(dir_fd, ".", &map_list, filter_map, alphasort);
	if (maps < 0)
		pr_err("cannot scan map files");

	for (i = 0; i < maps; i++) {
		map_fd = openat(dir_fd, map_list[i]->d_name, O_RDONLY);
		if (map_fd < 0)
			pr_err("map open failed");

		if (sscanf(map_list[i]->d_name, "sid-%"PRIx64".map", &sid) < 0)
			pr_err("map sid parse failed");

		if (fstat(map_fd, &stbuf) < 0)
			pr_err("map stat failed");

		len = stbuf.st_size;
		map = xmalloc(len);

		if (read_all(map_fd, map, len) < 0)
			pr_err("map read failed");

		send_trace_map(sock, sid, map, len);

		free(map);
		free(map_list[i]);
		close(map_fd);
	}
	free(map_list);
	close(dir_fd);
}

/* find "XXX.sym" file */
static int filter_sym(const struct dirent *de)
{
	size_t len = strlen(de->d_name);

	return !strncmp(".sym", de->d_name + len - 4, 4);
}

static void send_sym_files(int sock, const char *dirname)
{
	int dir_fd;
	int i, syms;
	int sym_fd;
	struct dirent **sym_list;
	struct stat stbuf;
	void *sym;
	int len;

	dir_fd = open(dirname, O_PATH | O_DIRECTORY);
	if (dir_fd < 0)
		pr_err("dir open failed");

	syms = scandirat(dir_fd, ".", &sym_list, filter_sym, alphasort);
	if (syms < 0)
		pr_err("cannot scan sym files");

	for (i = 0; i < syms; i++) {
		sym_fd = openat(dir_fd, sym_list[i]->d_name, O_RDONLY);
		if (sym_fd < 0)
			pr_err("open symfile failed");

		if (fstat(sym_fd, &stbuf) < 0)
			pr_err("stat symfile failed");

		len = stbuf.st_size;
		sym = xmalloc(len);

		if (read_all(sym_fd, sym, len) < 0)
			pr_err("read symfile failed");

		send_trace_sym(sock, sym_list[i]->d_name, sym, len);

		free(sym);
		free(sym_list[i]);
		close(sym_fd);
	}
	free(sym_list);
	close(dir_fd);
}

static void send_info_file(int sock, const char *dirname)
{
	int fd;
	char *filename = NULL;
	struct ftrace_file_header hdr;
	struct stat stbuf;
	void *info;
	int len;

	xasprintf(&filename, "%s/info", dirname);
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		pr_err("open info failed");

	if (fstat(fd, &stbuf) < 0)
		pr_err("stat info failed");

	if (read_all(fd, &hdr, sizeof(hdr)) < 0)
		pr_err("read file header failed");

	len = stbuf.st_size - sizeof(hdr);
	info = xmalloc(len);

	if (read_all(fd, info, len) < 0)
		pr_err("read info failed");

	send_trace_info(sock, &hdr, info, len);

	close(fd);
	free(filename);
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

#define MCOUNT_MSG  "Can't find '%s' symbol in the '%s'.\n"			\
"\tIt seems not to be compiled with -pg or -finstrument-functions flag\n" 	\
"\twhich generates traceable code.  Please check your binary file.\n"

int command_record(int argc, char *argv[], struct opts *opts)
{
	int pid;
	int status;
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
	int sock = -1;
	struct writer_arg warg = {
		.opts = opts,
		.kern = &kern,
	};

	load_symtabs(&symtabs, opts->dirname, opts->exename);

	for (i = 0; i < ARRAY_SIZE(profile_funcs); i++) {
		if (find_symname(&symtabs.dsymtab, profile_funcs[i]))
			break;
	}

	if (i == ARRAY_SIZE(profile_funcs) && !opts->force)
		pr_err(MCOUNT_MSG, "mcount", opts->exename);

	if (pipe(pfd) < 0)
		pr_err("cannot setup internal pipe");

	create_directory(opts->dirname);

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
		if (read(efd, &dummy, sizeof(dummy)) != (ssize_t)sizeof(dummy))
			pr_err("waiting for parent failed");

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

	if (opts->host) {
		sock = setup_client_socket(opts);
		send_trace_header(sock, opts->dirname);
		warg.sock = sock;
	}

	pthread_create(&writer, NULL, writer_thread, &warg);

	if (opts->kernel) {
		kern.pid = pid;
		kern.output_dir = opts->dirname;
		kern.depth = opts->kernel == 1 ? 1 : MCOUNT_RSTACK_MAX;

		setup_kernel_filters(&kern, opts->filter);

		if (start_kernel_tracing(&kern) < 0) {
			opts->kernel = false;
			pr_log("kernel tracing disabled due to an error\n");
		}
	}

	/* signal child that I'm ready */
	if (write(efd, &go, sizeof(go)) != (ssize_t)sizeof(go))
		pr_err("signal to child failed");

	close(efd);

	while (!ftrace_done) {
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

	while (!ftrace_done) {
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
	free_tid_list();

	if (opts->kernel)
		stop_kernel_tracing(&kern);

	if (fill_file_header(opts, status, &usage) < 0)
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

	if (opts->host) {
		send_task_file(sock, opts->dirname, &symtabs);
		send_map_files(sock, opts->dirname);
		send_sym_files(sock, opts->dirname);
		send_info_file(sock, opts->dirname);
		send_trace_end(sock);
		close(sock);

		remove_directory(opts->dirname);
	}

	/*
	 * Do not unload symbol tables.  It might save some time when used by
	 * 'live' command as it also need to load the symtabs again.
	 */
	//unload_symtabs(&symtabs);
	return 0;
}
