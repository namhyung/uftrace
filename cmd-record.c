#include <stdio.h>
#include <stdlib.h>
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
#include <sys/epoll.h>

#include "uftrace.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/list.h"
#include "utils/filter.h"

#define SHMEM_NAME_SIZE (64 - (int)sizeof(struct list_head))

struct shmem_list {
	struct list_head list;
	char id[SHMEM_NAME_SIZE];
};

static LIST_HEAD(shmem_list_head);
static LIST_HEAD(shmem_need_unlink);

struct buf_list {
	struct list_head list;
	int tid;
	void *shmem_buf;
};

static LIST_HEAD(buf_free_list);
static LIST_HEAD(buf_write_list);

/* currently active writers */
static LIST_HEAD(writer_list);

static pthread_mutex_t free_list_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t write_list_lock = PTHREAD_MUTEX_INITIALIZER;
static bool buf_done;
static int thread_ctl[2];


static bool can_use_fast_libmcount(struct opts *opts)
{
	if (debug)
		return false;
	if (opts->depth != MCOUNT_DEFAULT_DEPTH)
		return false;
	if (getenv("UFTRACE_FILTER") || getenv("UFTRACE_TRIGGER") ||
	    getenv("UFTRACE_ARGUMENT") || getenv("UFTRACE_RETVAL") ||
	    getenv("UFTRACE_PATCH"))
		return false;
	return true;
}

static char *build_debug_domain_string(void)
{
	int i, d;
	static char domain[2*DBG_DOMAIN_MAX + 1];

	for (i = 0, d = 0; d < DBG_DOMAIN_MAX; d++) {
		if (dbg_domain[d]) {
			domain[i++] = DBG_DOMAIN_STR[d];
			domain[i++] = dbg_domain[d] + '0';
		}
	}
	domain[i] = '\0';

	return domain;
}

static void setup_child_environ(struct opts *opts, int pfd)
{
	char buf[4096];
	char *old_preload, *old_libpath;
	bool must_use_multi_thread = check_libpthread(opts->exename);

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

	old_libpath = getenv("LD_LIBRARY_PATH");
	if (old_libpath) {
		size_t len = strlen(buf) + strlen(old_libpath) + 2;
		char *libpath = xmalloc(len);

		snprintf(libpath, len, "%s:%s", buf, old_libpath);
		setenv("LD_LIBRARY_PATH", libpath, 1);
		free(libpath);
	}
	else
		setenv("LD_LIBRARY_PATH", buf, 1);

	if (opts->filter) {
		char *filter_str = uftrace_clear_kernel(opts->filter);

		if (filter_str) {
			setenv("UFTRACE_FILTER", filter_str, 1);
			free(filter_str);
		}
	}

	if (opts->trigger) {
		char *trigger_str = uftrace_clear_kernel(opts->trigger);

		if (trigger_str) {
			setenv("UFTRACE_TRIGGER", trigger_str, 1);
			free(trigger_str);
		}
	}

	if (opts->args) {
		char *arg_str = uftrace_clear_kernel(opts->args);

		if (arg_str) {
			setenv("UFTRACE_ARGUMENT", arg_str, 1);
			free(arg_str);
		}
	}

	if (opts->retval) {
		char *retval_str = uftrace_clear_kernel(opts->retval);

		if (retval_str) {
			setenv("UFTRACE_RETVAL", retval_str, 1);
			free(retval_str);
		}
	}

	if (opts->patch) {
		char *patch_str = uftrace_clear_kernel(opts->patch);

		if (patch_str) {
			setenv("UFTRACE_PATCH", patch_str, 1);
			free(patch_str);
		}
	}

	if (opts->depth != OPT_DEPTH_DEFAULT) {
		snprintf(buf, sizeof(buf), "%d", opts->depth);
		setenv("UFTRACE_DEPTH", buf, 1);
	}

	if (opts->max_stack != OPT_RSTACK_DEFAULT) {
		snprintf(buf, sizeof(buf), "%d", opts->max_stack);
		setenv("UFTRACE_MAX_STACK", buf, 1);
	}

	if (opts->threshold) {
		snprintf(buf, sizeof(buf), "%"PRIu64, opts->threshold);
		setenv("UFTRACE_THRESHOLD", buf, 1);
	}

	if (opts->libcall) {
		setenv("UFTRACE_PLTHOOK", "1", 1);

		if (opts->want_bind_not) {
			/* do not update GOTPLT after resolving symbols */
			setenv("LD_BIND_NOT", "1", 1);
		}
	}

	if (strcmp(opts->dirname, UFTRACE_DIR_NAME))
		setenv("UFTRACE_DIR", opts->dirname, 1);

	if (opts->bufsize != SHMEM_BUFFER_SIZE) {
		snprintf(buf, sizeof(buf), "%lu", opts->bufsize);
		setenv("UFTRACE_BUFFER", buf, 1);
	}

	if (opts->logfile) {
		snprintf(buf, sizeof(buf), "%d", fileno(logfp));
		setenv("UFTRACE_LOGFD", buf, 1);
	}

	snprintf(buf, sizeof(buf), "%d", pfd);
	setenv("UFTRACE_PIPE", buf, 1);
	setenv("UFTRACE_SHMEM", "1", 1);

	if (debug) {
		snprintf(buf, sizeof(buf), "%d", debug);
		setenv("UFTRACE_DEBUG", buf, 1);
		setenv("UFTRACE_DEBUG_DOMAIN", build_debug_domain_string(), 1);
	}

	if(opts->disabled)
		setenv("UFTRACE_DISABLED", "1", 1);

	if (log_color == COLOR_ON) {
		snprintf(buf, sizeof(buf), "%d", log_color);
		setenv("UFTRACE_COLOR", buf, 1);
	}

	snprintf(buf, sizeof(buf), "%d", demangler);
	setenv("UFTRACE_DEMANGLE", buf, 1);

	if (opts->kernel && check_kernel_pid_filter())
		setenv("UFTRACE_KERNEL_PID_UPDATE", "1", 1);

	if (opts->lib_path)
		snprintf(buf, sizeof(buf), "%s/libmcount/", opts->lib_path);
	else
		buf[0] = '\0';  /* to make strcat() work */

	if (opts->nop) {
		strcat(buf, "libmcount-nop.so");
	}
	else if (opts->libmcount_single && !must_use_multi_thread) {
		if (can_use_fast_libmcount(opts))
			strcat(buf, "libmcount-fast-single.so");
		else
			strcat(buf, "libmcount-single.so");
	}
	else {
		if (must_use_multi_thread && opts->libmcount_single)
			pr_dbg("--libmcount-single is off because it calls pthread_create()\n");
		if (can_use_fast_libmcount(opts))
			strcat(buf, "libmcount-fast.so");
		else
			strcat(buf, "libmcount.so");
	}
	pr_dbg("using %s library for tracing\n", buf);

	old_preload = getenv("LD_PRELOAD");
	if (old_preload) {
		size_t len = strlen(buf) + strlen(old_preload) + 2;
		char *preload = xmalloc(len);

		snprintf(preload, len, "%s:%s", buf, old_preload);
		setenv("LD_PRELOAD", preload, 1);
		free(preload);
	}
	else
		setenv("LD_PRELOAD", buf, 1);

	setenv("XRAY_OPTIONS", "patch_premain=false", 1);
}

static uint64_t calc_feat_mask(struct opts *opts)
{
	uint64_t features = 0;

	/* mcount code creates task and sid-XXX.map files */
	features |= TASK_SESSION;

	/* symbol file saves relative address */
	features |= SYM_REL_ADDR;

	/* save mcount_max_stack */
	features |= MAX_STACK;

	if (opts->libcall)
		features |= PLTHOOK;

	if (opts->kernel)
		features |= KERNEL;

	if (opts->args)
		features |= ARGUMENT;

	if (opts->retval)
		features |= RETVAL;

	return features;
}

static int fill_file_header(struct opts *opts, int status, struct rusage *rusage)
{
	int fd, efd;
	int ret = -1;
	char *filename = NULL;
	struct uftrace_file_header hdr;
	char elf_ident[EI_NIDENT];

	xasprintf(&filename, "%s/info", opts->dirname);
	pr_dbg3("fill header (metadata) info in %s\n", filename);

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

	strncpy(hdr.magic, UFTRACE_MAGIC_STR, UFTRACE_MAGIC_LEN);
	hdr.version = UFTRACE_FILE_VERSION;
	hdr.header_size = sizeof(hdr);
	hdr.endian = elf_ident[EI_DATA];
	hdr.class = elf_ident[EI_CLASS];
	hdr.feat_mask = calc_feat_mask(opts);
	hdr.info_mask = 0;
	hdr.max_stack = opts->max_stack;
	hdr.unused1 = 0;
	hdr.unused2 = 0;

	if (write(fd, &hdr, sizeof(hdr)) != (int)sizeof(hdr))
		pr_err("writing header info failed");

	fill_ftrace_info(&hdr.info_mask, fd, opts, status, rusage);

try_write:
	ret = pwrite(fd, &hdr, sizeof(hdr), 0);
	if (ret != (int)sizeof(hdr)) {
		static int retry = 0;

		if (ret > 0 && retry++ < 3)
			goto try_write;

		pr_dbg("writing header info failed.\n");
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

/* size including NUL at the end */
#define MSG_ID_SIZE  36

static void parse_msg_id(char *id, uint64_t *sid, int *tid, int *seq)
{
	uint64_t _sid;
	unsigned _tid;
	unsigned _seq;

	/*
	 * parse message id of "/uftrace-SESSION-TID-SEQ".
	 */
	if (sscanf(id, "/uftrace-%016"SCNx64"-%u-%03u", &_sid, &_tid, &_seq) != 3)
		pr_err("parse msg id failed");

	if (sid)
		*sid = _sid;
	if (tid)
		*tid = _tid;
	if (seq)
		*seq = _seq;
}

static char *make_disk_name(const char *dirname, int tid)
{
	char *filename = NULL;

	xasprintf(&filename, "%s/%d.dat", dirname, tid);

	return filename;
}

static void write_buffer_file(const char *dirname, struct buf_list *buf)
{
	int fd;
	char *filename;
	struct mcount_shmem_buffer *shmbuf = buf->shmem_buf;

	filename = make_disk_name(dirname, buf->tid);
	fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd < 0)
		pr_err("open disk file");

	if (write_all(fd, shmbuf->data, shmbuf->size) < 0)
		pr_err("write shmem buffer");

	close(fd);
	free(filename);
}

static void write_buffer(struct buf_list *buf, struct opts *opts, int sock)
{
	struct mcount_shmem_buffer *shmbuf = buf->shmem_buf;

	if (!opts->host)
		return write_buffer_file(opts->dirname, buf);

	send_trace_data(sock, buf->tid, shmbuf->data, shmbuf->size);
}

struct writer_arg {
	struct list_head	list;
	struct list_head	bufs;
	struct opts		*opts;
	struct ftrace_kernel	*kern;
	int			sock;
	int			idx;
	int			tid;
	int			nr_cpu;
	int			cpus[];
};

static void write_buf_list(struct list_head *buf_head, struct opts *opts,
			   struct writer_arg *warg)
{
	struct buf_list *buf;

	list_for_each_entry(buf, buf_head, list) {
		struct mcount_shmem_buffer *shmbuf = buf->shmem_buf;

		write_buffer(buf, opts, warg->sock);

		/*
		 * Now it has consumed all contents in the shmem buffer,
		 * make it so that mcount can reuse it.
		 * This is paired with get_new_shmem_buffer().
		 */
		__sync_synchronize();
		shmbuf->flag = SHMEM_FL_WRITTEN;

		munmap(shmbuf, opts->bufsize);
		buf->shmem_buf = NULL;
	}

	pthread_mutex_lock(&free_list_lock);
	while (!list_empty(buf_head)) {
		struct list_head *l = buf_head->next;
		list_move(l, &buf_free_list);
	}
	pthread_mutex_unlock(&free_list_lock);
}

void *writer_thread(void *arg)
{
	struct buf_list *buf, *pos;
	struct writer_arg *warg = arg;
	struct opts *opts = warg->opts;
	struct pollfd pollfd[warg->nr_cpu + 1];
	int i, dummy;

	if (opts->rt_prio) {
		struct sched_param param = {
			.sched_priority = opts->rt_prio,
		};

		if (sched_setscheduler(0, SCHED_FIFO, &param) < 0)
			pr_log("set scheduling param failed\n");
	}

	pollfd[0].fd = thread_ctl[0];
	pollfd[0].events = POLLIN;

	for (i = 0; i < warg->nr_cpu; i++) {
		pollfd[i + 1].fd = warg->kern->traces[warg->cpus[i]];
		pollfd[i + 1].events = POLLIN;
	}

	pr_dbg2("start writer thread %d\n", warg->idx);
	while (!buf_done) {
		LIST_HEAD(head);
		bool check_list = false;

		if (poll(pollfd, warg->nr_cpu + 1, 1000) < 0)
			goto out;

		for (i = 0; i < warg->nr_cpu + 1; i++) {
			if (pollfd[i].revents & POLLIN) {
				if (i == 0)
					check_list = true;
				else
					record_kernel_trace_pipe(warg->kern,
								 warg->cpus[i-1]);
			}
		}

		if (!check_list)
			continue;

		if (read(thread_ctl[0], &dummy, sizeof(dummy)) < 0) {
			if (errno == EAGAIN && errno == EINTR)
				continue;
			/* other errors are problematic */
			break;
		}

		pthread_mutex_lock(&write_list_lock);

		if (!list_empty(&buf_write_list)) {
			/* pick first unhandled buf  */
			buf = list_first_entry(&buf_write_list,
					       struct buf_list, list);
			list_move(&buf->list, &head);

			warg->tid = buf->tid;
			list_add(&warg->list, &writer_list);
		}

		list_for_each_entry_safe(buf, pos, &buf_write_list, list) {
			/* list may have multiple buf for this task */
			if (buf->tid == warg->tid)
				list_move_tail(&buf->list, &head);
		}

		pthread_mutex_unlock(&write_list_lock);

		while (!list_empty(&head)) {
			write_buf_list(&head, opts, warg);

			pthread_mutex_lock(&write_list_lock);
			/* check someone sends bufs for me directly */
			list_splice_tail_init(&warg->bufs, &head);

			if (list_empty(&head)) {
				/* I'm done with this tid */
				warg->tid = -1;
				list_del_init(&warg->list);
			}
			pthread_mutex_unlock(&write_list_lock);

			if (!opts->kernel)
				continue;

			poll(&pollfd[1], warg->nr_cpu, 0);

			for (i = 0; i < warg->nr_cpu; i++) {
				if (pollfd[i+1].revents & POLLIN) {
					record_kernel_trace_pipe(warg->kern,
								 warg->cpus[i]);
				}
			}
		}
	}
	pr_dbg2("stop writer thread %d\n", warg->idx);

out:
	free(warg);
	return NULL;
}

static struct buf_list *make_write_buffer(void)
{
	struct buf_list *buf;

	buf = malloc(sizeof(*buf));
	if (buf == NULL)
		return NULL;

	INIT_LIST_HEAD(&buf->list);

	return buf;
}

static void copy_to_buffer(struct mcount_shmem_buffer *shm, char *sess_id)
{
	struct buf_list *buf = NULL;
	struct writer_arg *writer;

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

		pr_dbg3("make a new write buffer\n");
	}

	buf->shmem_buf = shm;
	parse_msg_id(sess_id, NULL, &buf->tid, NULL);

	pthread_mutex_lock(&write_list_lock);
	/* check some writers work for this tid */
	list_for_each_entry(writer, &writer_list, list) {
		if (buf->tid == writer->tid) {
			/* if so, pass the buf directly */
			list_add_tail(&buf->list, &writer->bufs);
			break;
		}
	}
	if (list_no_entry(writer, &writer_list, list)) {
		int kick = 1;

		/* no writer is dealing with the tid */
		list_add_tail(&buf->list, &buf_write_list);
		if (write(thread_ctl[1], &kick, sizeof(kick)) < 0 && !buf_done)
			pr_err("copying to buffer failed");
	}
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
		pr_dbg("open shmem buffer failed: %s: %m\n", sess_id);
		return 0;
	}

	shmem_buf = mmap(NULL, bufsize, PROT_READ | PROT_WRITE,
			 MAP_SHARED, fd, 0);
	if (shmem_buf == MAP_FAILED)
		pr_err("mmap shmem buffer");

	close(fd);

	if (shmem_buf->flag & SHMEM_FL_RECORDING) {
		if (shmem_buf->flag & SHMEM_FL_NEW) {
			bool found = false;

			if (!list_empty(&shmem_need_unlink)) {
				sl = list_last_entry(&shmem_need_unlink,
						     struct shmem_list, list);

				/* length of "uftrace-<session id>-" is 25 */
				if (!strncmp(sl->id, sess_id, 25))
					found = true;
			}

			if (!found) {
				sl = xmalloc(sizeof(*sl));
				memcpy(sl->id, sess_id, sizeof(sl->id));

				/* link to shmem_list */
				list_add_tail(&sl->list, &shmem_need_unlink);
			}
		}

		if (shmem_buf->size) {
			/* shmem_buf will be unmapped */
			copy_to_buffer(shmem_buf, sess_id);
		}
	}

	return 0;
}

static void stop_all_writers(void)
{
	buf_done = true;
	close(thread_ctl[1]);
	thread_ctl[1] = -1;
}

static void record_remaining_buffer(struct opts *opts, int sock)
{
	struct buf_list *buf;

	/* called after all writers gone, no lock is needed */
	while (!list_empty(&buf_write_list)) {
		buf = list_first_entry(&buf_write_list, struct buf_list, list);
		write_buffer(buf, opts, sock);
		munmap(buf->shmem_buf, opts->bufsize);

		list_del(&buf->list);
		free(buf);
	}

	while (!list_empty(&buf_free_list)) {
		buf = list_first_entry(&buf_free_list, struct buf_list, list);

		list_del(&buf->list);
		free(buf);
	}
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
}

static char shmem_session[20];

static int filter_shmem(const struct dirent *de)
{
	/* compare session ID after the "uftrace-" part */
	return !memcmp(&de->d_name[8], shmem_session, 16);
}

static void unlink_shmem_list(void)
{
	struct shmem_list *sl, *tmp;

	/* unlink shmem list (not used anymore) */
	list_for_each_entry_safe(sl, tmp, &shmem_need_unlink, list) {
		char sid[128];
		struct dirent **shmem_bufs;
		int i, num;

		list_del(&sl->list);

		sscanf(sl->id, "/uftrace-%[^-]-%*d-%*d", shmem_session);
		pr_dbg2("unlink for session: %s\n", shmem_session);

		num = scandir("/dev/shm/", &shmem_bufs, filter_shmem, alphasort);
		for (i = 0; i < num; i++) {
			sid[0] = '/';
			strncpy(&sid[1], shmem_bufs[i]->d_name, MSG_ID_SIZE);
			pr_dbg3("unlink %s\n", sid);
			shm_unlink(sid);
			free(shmem_bufs[i]);
		}

		free(shmem_bufs);
		free(sl);
	}
}

static void flush_old_shmem(const char *dirname, int tid, int bufsize)
{
	struct shmem_list *sl;

	/* flush remaining list (due to abnormal termination) */
	list_for_each_entry(sl, &shmem_list_head, list) {
		int sl_tid;

		sscanf(sl->id, "/uftrace-%*x-%d-%*d", &sl_tid);

		if (tid == sl_tid) {
			pr_dbg3("flushing %s\n", sl->id);

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

	pr_dbg2("all process/thread exited\n");
	return true;
}

struct dlopen_list {
	struct list_head list;
	char *libname;
};

static LIST_HEAD(dlopen_libs);

static void read_record_mmap(int pfd, const char *dirname, int bufsize)
{
	char buf[128];
	struct shmem_list *sl, *tmp;
	struct tid_list *tl, *pos;
	struct ftrace_msg msg;
	struct ftrace_msg_task tmsg;
	struct ftrace_msg_sess sess;
	struct ftrace_msg_dlopen dmsg;
	struct dlopen_list *dlib;
	char *exename;
	int lost;

	if (read_all(pfd, &msg, sizeof(msg)) < 0)
		pr_err("reading pipe failed:");

	if (msg.magic != FTRACE_MSG_MAGIC)
		pr_err_ns("invalid message received: %x\n", msg.magic);

	switch (msg.type) {
	case FTRACE_MSG_REC_START:
		if (msg.len >= SHMEM_NAME_SIZE)
			pr_err_ns("invalid message length\n");

		sl = xmalloc(sizeof(*sl));

		if (read_all(pfd, sl->id, msg.len) < 0)
			pr_err("reading pipe failed");

		sl->id[msg.len] = '\0';
		pr_dbg2("MSG START: %s\n", sl->id);

		/* link to shmem_list */
		list_add_tail(&sl->list, &shmem_list_head);
		break;

	case FTRACE_MSG_REC_END:
		if (msg.len >= SHMEM_NAME_SIZE)
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, buf, msg.len) < 0)
			pr_err("reading pipe failed");

		buf[msg.len] = '\0';
		pr_dbg2("MSG  END : %s\n", buf);

		/* remove from shmem_list */
		list_for_each_entry_safe(sl, tmp, &shmem_list_head, list) {
			if (!memcmp(sl->id, buf, SHMEM_NAME_SIZE)) {
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

		pr_dbg2("MSG  TID : %d/%d\n", tmsg.pid, tmsg.tid);

		/* check existing tid (due to exec) */
		list_for_each_entry(pos, &tid_list_head, list) {
			if (pos->tid == tmsg.tid) {
				flush_old_shmem(dirname, tmsg.tid, bufsize);
				break;
			}
		}

		if (list_no_entry(pos, &tid_list_head, list))
			add_tid_list(tmsg.pid, tmsg.tid);

		write_task_info(dirname, &tmsg);
		break;

	case FTRACE_MSG_FORK_START:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		pr_dbg2("MSG FORK1: %d/%d\n", tmsg.pid, -1);

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

		if (list_no_entry(tl, &tid_list_head, list)) {
			/*
			 * daemon process has no guarantee that having parent
			 * pid of 1 anymore due to the systemd, just pick a
			 * first task which has tid of -1.
			 */
			list_for_each_entry(tl, &tid_list_head, list) {
				if (tl->tid == -1) {
					pr_dbg3("override parent of daemon to %d\n",
						tl->pid);
					tmsg.pid = tl->pid;
					break;
				}
			}
		}

		if (list_no_entry(tl, &tid_list_head, list))
			pr_err("cannot find fork pid: %d\n", tmsg.pid);

		tl->tid = tmsg.tid;

		pr_dbg2("MSG FORK2: %d/%d\n", tl->pid, tl->tid);

		write_fork_info(dirname, &tmsg);
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

		pr_dbg2("MSG SESSION: %d: %s (%s)\n", sess.task.tid, exename, buf);

		write_session_info(dirname, &sess, exename);
		break;

	case FTRACE_MSG_LOST:
		if (msg.len < sizeof(lost))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &lost, sizeof(lost)) < 0)
			pr_err("reading pipe failed");

		shmem_lost_count += lost;
		break;

	case FTRACE_MSG_DLOPEN:
		if (msg.len < sizeof(dmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &dmsg, sizeof(dmsg)) < 0)
			pr_err("reading pipe failed");

		exename = xmalloc(dmsg.namelen + 1);
		if (read_all(pfd, exename, dmsg.namelen) < 0)
			pr_err("reading pipe failed");
		exename[dmsg.namelen] = '\0';

		pr_dbg2("MSG DLOPEN: %d: %#lx %s\n", dmsg.task.tid, dmsg.base_addr, exename);

		dlib = xmalloc(sizeof(*dlib));
		dlib->libname = exename;
		list_add_tail(&dlib->list, &dlopen_libs);

		write_dlopen_info(dirname, &dmsg, exename);
		break;

	default:
		pr_log("Unknown message type: %u\n", msg.type);
		break;
	}
}

static void send_task_txt_file(int sock, FILE *fp)
{
	struct stat stbuf;
	void *buf;

	if (fstat(fileno(fp), &stbuf) < 0)
		pr_err("cannot stat task.txt file");

	buf = xmalloc(stbuf.st_size);
	if (fread_all(buf, stbuf.st_size, fp) < 0)
		pr_err("cannot read task.txt file");

	send_trace_task_txt(sock, buf, stbuf.st_size);
	free(buf);
}

static void send_task_file(int sock, const char *dirname, struct symtabs *symtabs)
{
	FILE *fp;
	char *filename = NULL;
	char *p;
	struct ftrace_msg msg;
	struct ftrace_msg_task tmsg;
	struct ftrace_msg_sess smsg;
	int namelen;
	char *exename;

	xasprintf(&filename, "%s/task.txt", dirname);

	fp = fopen(filename, "r");
	if (fp) {
		send_task_txt_file(sock, fp);
		goto out;
	}

	/* try to open (old) task file */
	p = strrchr(filename, '.');
	if (p) {
		*p = '\0';
		fp = fopen(filename, "r");
	}
	if (p == NULL || fp == NULL)
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

out:
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
	int i, maps;
	int map_fd;
	uint64_t sid;
	struct dirent **map_list;
	struct stat stbuf;
	void *map;
	int len;
	char buf[PATH_MAX];

	maps = scandir(dirname, &map_list, filter_map, alphasort);
	if (maps < 0)
		pr_err("cannot scan map files");

	for (i = 0; i < maps; i++) {
		snprintf(buf, sizeof(buf), "%s/%s",
			 dirname, map_list[i]->d_name);
		map_fd = open(buf, O_RDONLY);
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
}

/* find "XXX.sym" file */
static int filter_sym(const struct dirent *de)
{
	size_t len = strlen(de->d_name);

	return !strncmp(".sym", de->d_name + len - 4, 4);
}

static void send_sym_files(int sock, const char *dirname)
{
	int i, syms;
	int sym_fd;
	struct dirent **sym_list;
	struct stat stbuf;
	void *sym;
	int len;
	char buf[PATH_MAX];

	syms = scandir(dirname, &sym_list, filter_sym, alphasort);
	if (syms < 0)
		pr_err("cannot scan sym files");

	for (i = 0; i < syms; i++) {
		snprintf(buf, sizeof(buf), "%s/%s",
			 dirname, sym_list[i]->d_name);
		sym_fd = open(buf, O_RDONLY);
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
}

static void send_info_file(int sock, const char *dirname)
{
	int fd;
	char *filename = NULL;
	struct uftrace_file_header hdr;
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

static void save_module_symbols(struct opts *opts, struct symtabs *symtabs)
{
	struct ftrace_proc_maps *map, *tmp;
	LIST_HEAD(modules);
	struct dirent **map_list;
	char sid[20] = { 0, };
	int i, maps;

	ftrace_setup_filter_module(opts->filter, &modules, symtabs->filename);
	ftrace_setup_filter_module(opts->trigger, &modules, symtabs->filename);
	ftrace_setup_filter_module(opts->args, &modules, symtabs->filename);
	ftrace_setup_filter_module(opts->retval, &modules, symtabs->filename);

	if (list_empty(&modules))
		return;

	maps = scandir(opts->dirname, &map_list, filter_map, alphasort);
	if (maps <= 0)
		pr_err("cannot find map files");

	for (i = 0; i < maps; i++) {
		if (sid[0] == '\0')
			sscanf(map_list[i]->d_name, "sid-%[^.].map", sid);
		free(map_list[i]);
	}
	free(map_list);

	read_session_map(opts->dirname, symtabs, sid);
	load_module_symtabs(symtabs, &modules);
	save_module_symtabs(symtabs, &modules);

	map = symtabs->maps;
	while (map) {
		tmp = map;
		map = map->next;

		free(tmp);
	}
	symtabs->maps = NULL;

	ftrace_cleanup_filter_module(&modules);
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

	pr_out("elapsed time: %"PRIu64".%09"PRIu64" sec\n", sec, nsec);
}

static void print_child_usage(struct rusage *ru)
{
	pr_out(" system time: %lu.%06lu000 sec\n",
	       ru->ru_stime.tv_sec, ru->ru_stime.tv_usec);
	pr_out("   user time: %lu.%06lu000 sec\n",
	       ru->ru_utime.tv_sec, ru->ru_utime.tv_usec);
}

#define FTRACE_MSG  "Cannot trace '%s': No such file\n"			\
"\tNote that ftrace doesn't search $PATH for you.\n"			\
"\tIf you really want to trace executables in the $PATH,\n"		\
"\tplease give it the absolute pathname (like /usr/bin/%s).\n"

#define MCOUNT_MSG  "Can't find '%s' symbol in the '%s'.\n"		\
"\tIt seems not to be compiled with -pg or -finstrument-functions flag\n" 	\
"\twhich generates traceable code.  Please check your binary file.\n"

#define FTRACE_ELF_MSG  "Cannot trace '%s': Invalid file\n"		\
"\tThis file doesn't look like an executable ELF file.\n"		\
"\tPlease check whether it's a kind of script or shell functions.\n"

#define OBJTYPE_MSG  "Cannot trace '%s': Invalid ELF object type\n"	\
"\tNote that ftrace only trace ELF executables by default,\n"		\
"\tIf you want to trace shared libraries, please use --force option.\n"

#define MACHINE_MSG  "Cannot trace '%s': Unsupported machine\n"		\
"\tThis machine type (%u) is not supported currently.\n"		\
"\tSorry about that!\n"

#define ARGUMENT_MSG  "uftrace: -A or -R might not work for binaries"	\
" with -finstrument-functions\n"

static void check_binary(struct opts *opts)
{
	int fd;
	size_t i;
	char elf_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint16_t supported_machines[] = {
		EM_X86_64, EM_ARM,
	};

	pr_dbg3("checking binary %s\n", opts->exename);

	if (access(opts->exename, X_OK) < 0) {
		if (errno == ENOENT && opts->exename[0] != '/') {
			pr_err_ns(FTRACE_MSG, opts->exename, opts->exename);
		}
		pr_err("Cannot trace '%s'", opts->exename);
	}

	fd = open(opts->exename, O_RDONLY);
	if (fd < 0)
		pr_err("Cannot open '%s'", opts->exename);

	if (read(fd, elf_ident, sizeof(elf_ident)) < 0)
		pr_err("Cannot read '%s'", opts->exename);

	if (memcmp(elf_ident, ELFMAG, SELFMAG))
		pr_err_ns(FTRACE_ELF_MSG, opts->exename);

	if (read(fd, &e_type, sizeof(e_type)) < 0)
		pr_err("Cannot read '%s'", opts->exename);

	if (e_type != ET_EXEC && e_type != ET_DYN && !opts->force)
		pr_err_ns(OBJTYPE_MSG, opts->exename);

	if (read(fd, &e_machine, sizeof(e_machine)) < 0)
		pr_err("Cannot read '%s'", opts->exename);

	for (i = 0; i < ARRAY_SIZE(supported_machines); i++) {
		if (e_machine == supported_machines[i])
			break;
	}
	if (i == ARRAY_SIZE(supported_machines))
		pr_err_ns(MACHINE_MSG, opts->exename, e_machine);

	if (!opts->force) {
		int chk = check_trace_functions(opts->exename);

		if (chk == 0 && !opts->patch) {
			/* there's no function to trace */
			pr_err_ns(MCOUNT_MSG, "mcount", opts->exename);
		}
		else if (chk == 2 && (opts->args || opts->retval)) {
			/* arg/retval doesn't support -finstrument-functions */
			pr_out(ARGUMENT_MSG);
		}
		else if (chk < 0) {
			pr_err_ns("Cannot check '%s'\n", opts->exename);
		}
	}

	close(fd);
}

int command_record(int argc, char *argv[], struct opts *opts)
{
	int pid;
	int status;
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
	pthread_t *writers;
	struct ftrace_kernel kern;
	struct dlopen_list *dlib, *tmp;
	int efd;
	uint64_t go = 1;
	int sock = -1;
	int nr_cpu;
	int i, k;
	int ret = UFTRACE_EXIT_SUCCESS;

	if (pipe(pfd) < 0)
		pr_err("cannot setup internal pipe");

	if (create_directory(opts->dirname) < 0)
		return -1;

	check_binary(opts);

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

		setup_child_environ(opts, pfd[1]);

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

	sigfillset(&sa.sa_mask);
	sa.sa_handler = NULL;
	sa.sa_sigaction = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
	sigaction(SIGCHLD, &sa, NULL);

	if (opts->host) {
		sock = setup_client_socket(opts);
		send_trace_header(sock, opts->dirname);
	}

	nr_cpu = sysconf(_SC_NPROCESSORS_ONLN);

	if (opts->kernel) {
		kern.pid = pid;
		kern.output_dir = opts->dirname;
		kern.depth = opts->kernel_depth ?: 1;
		kern.bufsize = opts->kernel_bufsize;

		if (!opts->nr_thread) {
			if (opts->kernel_depth >= 4)
				opts->nr_thread = nr_cpu;
			else if (opts->kernel_depth >= 2)
				opts->nr_thread = nr_cpu / 2;
		}

		if (!opts->kernel_bufsize) {
			if (opts->kernel_depth >= 8)
				kern.bufsize = 4096 * 1024;
			else if (opts->kernel_depth >= 4)
				kern.bufsize = 3072 * 1024;
			else if (opts->kernel_depth >= 2)
				kern.bufsize = 2048 * 1024;
		}

		if (setup_kernel_tracing(&kern, opts) < 0) {
			opts->kernel = false;
			pr_log("kernel tracing disabled due to an error\n");
		}
	}

	if (!opts->nr_thread)
		opts->nr_thread = DIV_ROUND_UP(nr_cpu, 4);
	else if (opts->nr_thread > nr_cpu)
		opts->nr_thread = nr_cpu;

	pr_dbg("creating %d thread(s) for recording\n", opts->nr_thread);
	writers = xmalloc(opts->nr_thread * sizeof(*writers));

//	thread_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (pipe(thread_ctl) < 0)
		pr_err("cannot create an eventfd for writer thread");

	if (opts->kernel && start_kernel_tracing(&kern) < 0) {
		opts->kernel = false;
		pr_log("kernel tracing disabled due to an error\n");
	}

	for (i = 0; i < opts->nr_thread; i++) {
		struct writer_arg *warg;
		int cpu_per_thread = DIV_ROUND_UP(nr_cpu, opts->nr_thread);
		size_t sizeof_warg = sizeof(*warg) + sizeof(int) * cpu_per_thread;

		warg = xmalloc(sizeof_warg);
		warg->opts = opts;
		warg->idx  = i;
		warg->sock = sock;
		warg->kern = &kern;
		warg->nr_cpu = 0;
		INIT_LIST_HEAD(&warg->list);
		INIT_LIST_HEAD(&warg->bufs);

		if (opts->kernel) {
			warg->nr_cpu = cpu_per_thread;

			for (k = 0; k < cpu_per_thread; k++) {
				if (i * cpu_per_thread + k < nr_cpu)
					warg->cpus[k] = i * cpu_per_thread + k;
				else
					warg->cpus[k] = -1;
			}
		}

		pthread_create(&writers[i], NULL, writer_thread, warg);
	}

	/* signal child that I'm ready */
	if (write(efd, &go, sizeof(go)) != (ssize_t)sizeof(go))
		pr_err("signal to child failed");

	close(efd);

	while (!uftrace_done) {
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
			read_record_mmap(pfd[0], opts->dirname, opts->bufsize);

		if (pollfd.revents & (POLLERR | POLLHUP))
			break;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts2);

	while (!uftrace_done) {
		if (ioctl(pfd[0], FIONREAD, &remaining) < 0)
			break;

		if (remaining) {
			read_record_mmap(pfd[0], opts->dirname, opts->bufsize);
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
		if (WIFEXITED(status)) {
			pr_dbg("child terminated with exit code: %d\n",
			       WEXITSTATUS(status));

			if (!WEXITSTATUS(status))
				ret = UFTRACE_EXIT_SUCCESS;
			else
				ret = UFTRACE_EXIT_FAILURE;
		}
		else {
			pr_yellow("child terminated by signal: %d: %s\n",
				  WTERMSIG(status), strsignal(WTERMSIG(status)));
			ret = UFTRACE_EXIT_SIGNALED;
		}
	}
	else {
		status = -1;
		getrusage(RUSAGE_CHILDREN, &usage);
		ret = UFTRACE_EXIT_UNKNOWN;
	}

	stop_all_writers();
	if (opts->kernel)
		stop_kernel_tracing(&kern);

	if (fill_file_header(opts, status, &usage) < 0)
		pr_err("cannot generate data file");

	if (opts->time) {
		print_child_time(&ts1, &ts2);
		print_child_usage(&usage);
	}

	if (shmem_lost_count)
		pr_log("LOST %d records\n", shmem_lost_count);

	for (i = 0; i < opts->nr_thread; i++)
		pthread_join(writers[i], NULL);
	close(thread_ctl[0]);

	flush_shmem_list(opts->dirname, opts->bufsize);
	record_remaining_buffer(opts, sock);
	unlink_shmem_list();
	free_tid_list();

	load_symtabs(&symtabs, opts->dirname, opts->exename);
	save_symbol_file(&symtabs, opts->dirname, opts->exename);
	save_module_symbols(opts, &symtabs);

	list_for_each_entry_safe(dlib, tmp, &dlopen_libs, list) {
		struct symtabs dlib_symtabs = {
			.loaded = false,
		};

		load_symtabs(&dlib_symtabs, opts->dirname, dlib->libname);
		save_symbol_file(&dlib_symtabs, opts->dirname, dlib->libname);

		list_del(&dlib->list);

		free(dlib->libname);
		free(dlib);
	}

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
	else if (geteuid() == 0)
		chown_directory(opts->dirname);

	unload_symtabs(&symtabs);
	return ret;
}
