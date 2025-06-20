#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "libmcount/mcount.h"
#include "uftrace.h"
#include "utils/filter.h"
#include "utils/kernel.h"
#include "utils/list.h"
#include "utils/perf.h"
#include "utils/shmem.h"
#include "utils/symbol.h"
#include "utils/utils.h"

#ifndef EM_RISCV
#define EM_RISCV 243
#endif

#ifndef EFD_SEMAPHORE
#define EFD_SEMAPHORE (1 << 0)
#endif
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

static bool has_perf_event;
static bool has_sched_event;
static bool finish_received;

static bool can_use_fast_libmcount(struct uftrace_opts *opts)
{
	if (debug)
		return false;
	if (opts->depth != MCOUNT_DEFAULT_DEPTH)
		return false;
	if (getenv("UFTRACE_FILTER") || getenv("UFTRACE_TRIGGER") || getenv("UFTRACE_ARGUMENT") ||
	    getenv("UFTRACE_RETVAL") || getenv("UFTRACE_PATCH") || getenv("UFTRACE_SCRIPT") ||
	    getenv("UFTRACE_AUTO_ARGS") || getenv("UFTRACE_WATCH") || getenv("UFTRACE_CALLER") ||
	    getenv("UFTRACE_SIGNAL") || getenv("UFTRACE_AGENT") || getenv("UFTRACE_LOCATION"))
		return false;
	return true;
}

static char *build_debug_domain_string(void)
{
	int i, d;
	static char domain[2 * DBG_DOMAIN_MAX + 1];

	for (i = 0, d = 0; d < DBG_DOMAIN_MAX; d++) {
		if (dbg_domain[d]) {
			domain[i++] = DBG_DOMAIN_STR[d];
			domain[i++] = dbg_domain[d] + '0';
		}
	}
	domain[i] = '\0';

	return domain;
}

char *get_libmcount_path(struct uftrace_opts *opts)
{
	char *libmcount, *lib = xmalloc(PATH_MAX);
	bool must_use_multi_thread = has_dependency(opts->exename, "libpthread.so.0");

	if (opts->nop) {
		libmcount = "libmcount-nop.so";
	}
	else if (opts->libmcount_single && !must_use_multi_thread) {
		if (can_use_fast_libmcount(opts))
			libmcount = "libmcount-fast-single.so";
		else
			libmcount = "libmcount-single.so";
	}
	else {
		if (must_use_multi_thread && opts->libmcount_single)
			pr_dbg("--libmcount-single is off because it uses pthread\n");
		if (can_use_fast_libmcount(opts))
			libmcount = "libmcount-fast.so";
		else
			libmcount = "libmcount.so";
	}

	if (opts->lib_path) {
		snprintf(lib, PATH_MAX, "%s/libmcount/%s", opts->lib_path, libmcount);

		if (access(lib, F_OK) == 0) {
			return lib;
		}
		else if (errno == ENOENT) {
			snprintf(lib, PATH_MAX, "%s/%s", opts->lib_path, libmcount);
			if (access(lib, F_OK) == 0)
				return lib;
		}
		free(lib);
		return NULL;
	}

#ifdef INSTALL_LIB_PATH
	/* try first to load libmcount from the installation path */
	snprintf(lib, PATH_MAX, "%s/%s", INSTALL_LIB_PATH, libmcount);
	if (access(lib, F_OK) == 0)
		return lib;
#endif
	strncpy(lib, libmcount, PATH_MAX);
	return lib;
}

void put_libmcount_path(char *libpath)
{
	free(libpath);
}

static void setup_child_environ(struct uftrace_opts *opts, int argc, char *argv[])
{
	char buf[PATH_MAX];
	char *old_preload, *libpath;

#ifdef INSTALL_LIB_PATH
	if (!opts->lib_path) {
		char *envbuf = getenv("LD_LIBRARY_PATH");

		if (envbuf) {
			envbuf = xstrdup(envbuf);
			libpath = strjoin(envbuf, INSTALL_LIB_PATH, ":");
			setenv("LD_LIBRARY_PATH", libpath, 1);
			free(libpath);
		}
		else {
			setenv("LD_LIBRARY_PATH", INSTALL_LIB_PATH, 1);
		}
	}
#endif

	if (opts->filter) {
		char *filter_str = uftrace_clear_kernel(opts->filter);

		if (filter_str) {
			setenv("UFTRACE_FILTER", filter_str, 1);
			free(filter_str);
		}
	}

	if (opts->loc_filter) {
		char *loc_str = uftrace_clear_kernel(opts->loc_filter);

		if (loc_str) {
			setenv("UFTRACE_LOCATION", loc_str, 1);
			setenv("UFTRACE_SRCLINE", "1", 1);
			free(loc_str);
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

	if (opts->auto_args)
		setenv("UFTRACE_AUTO_ARGS", "1", 1);

	if (opts->patch) {
		char *patch_str = uftrace_clear_kernel(opts->patch);

		if (patch_str) {
			setenv("UFTRACE_PATCH", patch_str, 1);
			free(patch_str);
		}
	}

	if (opts->size_filter) {
		snprintf(buf, sizeof(buf), "%d", opts->size_filter);
		setenv("UFTRACE_MIN_SIZE", buf, 1);
	}

	if (opts->event) {
		char *event_str = uftrace_clear_kernel(opts->event);

		if (event_str) {
			setenv("UFTRACE_EVENT", event_str, 1);
			free(event_str);
		}
	}

	if (opts->watch)
		setenv("UFTRACE_WATCH", opts->watch, 1);

	if (opts->depth != OPT_DEPTH_DEFAULT) {
		snprintf(buf, sizeof(buf), "%d", opts->depth);
		setenv("UFTRACE_DEPTH", buf, 1);
	}

	if (opts->max_stack != OPT_RSTACK_DEFAULT) {
		snprintf(buf, sizeof(buf), "%d", opts->max_stack);
		setenv("UFTRACE_MAX_STACK", buf, 1);
	}

	if (opts->threshold) {
		snprintf(buf, sizeof(buf), "%" PRIu64, opts->threshold);
		setenv("UFTRACE_THRESHOLD", buf, 1);
	}

	if (opts->caller) {
		char *caller_str = uftrace_clear_kernel(opts->caller);

		if (caller_str) {
			setenv("UFTRACE_CALLER", caller_str, 1);
			free(caller_str);
		}
	}

	if (opts->libcall) {
		setenv("UFTRACE_PLTHOOK", "1", 1);

		if (opts->want_bind_not) {
			/* do not update GOT/PLT after resolving symbols */
			setenv("LD_BIND_NOT", "1", 1);
		}

		if (opts->nest_libcall)
			setenv("UFTRACE_NEST_LIBCALL", "1", 1);
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

	setenv("UFTRACE_SHMEM", "1", 1);

	if (debug) {
		snprintf(buf, sizeof(buf), "%d", debug);
		setenv("UFTRACE_DEBUG", buf, 1);
		setenv("UFTRACE_DEBUG_DOMAIN", build_debug_domain_string(), 1);
	}

	if (opts->trace == TRACE_STATE_OFF)
		setenv("UFTRACE_TRACE_OFF", "1", 1);

	if (log_color == COLOR_ON) {
		snprintf(buf, sizeof(buf), "%d", log_color);
		setenv("UFTRACE_COLOR", buf, 1);
	}

	snprintf(buf, sizeof(buf), "%d", demangler);
	setenv("UFTRACE_DEMANGLE", buf, 1);

	if ((opts->kernel || has_kernel_event(opts->event)) && check_kernel_pid_filter())
		setenv("UFTRACE_KERNEL_PID_UPDATE", "1", 1);

	if (opts->script_file)
		setenv("UFTRACE_SCRIPT", opts->script_file, 1);

	if (opts->patt_type != PATT_REGEX)
		setenv("UFTRACE_PATTERN", get_filter_pattern(opts->patt_type), 1);

	if (opts->sig_trigger)
		setenv("UFTRACE_SIGNAL", opts->sig_trigger, 1);

	if (opts->srcline)
		setenv("UFTRACE_SRCLINE", "1", 1);

	if (opts->estimate_return)
		setenv("UFTRACE_ESTIMATE_RETURN", "1", 1);

	if (opts->clock)
		setenv("UFTRACE_CLOCK", opts->clock, 1);

	if (opts->with_syms)
		setenv("UFTRACE_SYMBOL_DIR", opts->with_syms, 1);

	if (opts->agent)
		setenv("UFTRACE_AGENT", "1", 1);

	if (argc > 0) {
		char *args = NULL;
		int i;

		for (i = 0; i < argc; i++)
			args = strjoin(args, argv[i], "\n");

		setenv("UFTRACE_ARGS", args, 1);
		free(args);
	}

	/*
	 * ----- end of option processing -----
	 */

	libpath = get_libmcount_path(opts);
	if (libpath == NULL)
		pr_err_ns("uftrace could not find libmcount.so for record-tracing\n");

	pr_dbg("using %s library for tracing\n", libpath);

	old_preload = getenv("LD_PRELOAD");
	if (old_preload) {
		size_t len = strlen(libpath) + strlen(old_preload) + 2;
		char *preload = xmalloc(len);

		snprintf(preload, len, "%s:%s", libpath, old_preload);
		setenv("LD_PRELOAD", preload, 1);
		free(preload);
	}
	else
		setenv("LD_PRELOAD", libpath, 1);

	put_libmcount_path(libpath);
	setenv("XRAY_OPTIONS", "patch_premain=false", 1);
	setenv("GLIBC_TUNABLES", "glibc.cpu.hwcaps=-IBT,-SHSTK", 1);

	/* disable debuginfo daemon */
	unsetenv("DEBUGINFOD_URLS");
}

static uint64_t calc_feat_mask(struct uftrace_opts *opts)
{
	uint64_t features = 0;
	char *buf = NULL;
	glob_t g;

	/* mcount code creates task and sid-XXX.map files */
	features |= TASK_SESSION;

	/* symbol file saves relative address */
	features |= SYM_REL_ADDR;

	/* save mcount_max_stack */
	features |= MAX_STACK;

	/* provide automatic argument/return value spec */
	features |= AUTO_ARGS;

	if (has_perf_event)
		features |= PERF_EVENT;

	if (opts->libcall)
		features |= PLTHOOK;

	if (opts->kernel)
		features |= KERNEL;

	if (opts->args || opts->auto_args)
		features |= ARGUMENT;

	if (opts->retval || opts->auto_args)
		features |= RETVAL;

	if (opts->event)
		features |= EVENT;

	if (opts->estimate_return)
		features |= ESTIMATE_RETURN;

	/* symbol file saves size */
	features |= SYM_SIZE;

	xasprintf(&buf, "%s/*.dbg", opts->dirname);
	if (glob(buf, GLOB_NOSORT, NULL, &g) != GLOB_NOMATCH)
		features |= DEBUG_INFO;

	globfree(&g);
	free(buf);

	return features;
}

int fill_file_header(struct uftrace_opts *opts, int status, struct rusage *rusage,
		     char *elapsed_time)
{
	int fd, efd;
	int ret = -1;
	char *filename = NULL;
	struct uftrace_file_header hdr;
	char elf_ident[EI_NIDENT];

	xasprintf(&filename, "%s/info", opts->dirname);
	pr_dbg3("fill header (metadata) info in %s\n", filename);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		pr_err("cannot open info file");

	efd = open(opts->exename, O_RDONLY);
	if (efd < 0)
		goto close_fd;

	if (read(efd, elf_ident, sizeof(elf_ident)) < 0)
		goto close_efd;

	strncpy(hdr.magic, UFTRACE_MAGIC_STR, UFTRACE_MAGIC_LEN);
	hdr.version = UFTRACE_FILE_VERSION;
	hdr.header_size = sizeof(hdr);
	hdr.endian = elf_ident[EI_DATA];
	hdr.elf_class = elf_ident[EI_CLASS];
	hdr.feat_mask = calc_feat_mask(opts);
	hdr.info_mask = 0;
	hdr.max_stack = opts->max_stack;
	hdr.unused1 = 0;
	hdr.unused2 = 0;

	if (write(fd, &hdr, sizeof(hdr)) != (int)sizeof(hdr))
		pr_err("writing header info failed");

	fill_uftrace_info(&hdr.info_mask, fd, opts, status, rusage, elapsed_time);

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
#define MSG_ID_SIZE 36

static void parse_msg_id(char *id, uint64_t *sid, int *tid, int *seq)
{
	uint64_t _sid;
	unsigned _tid;
	unsigned _seq;

	/*
	 * parse message id of "/uftrace-SESSION-TID-SEQ".
	 */
	if (sscanf(id, "/uftrace-%016" SCNx64 "-%u-%03u", &_sid, &_tid, &_seq) != 3)
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

static void write_buffer(struct buf_list *buf, struct uftrace_opts *opts, int sock)
{
	struct mcount_shmem_buffer *shmbuf = buf->shmem_buf;

	if (!opts->host)
		write_buffer_file(opts->dirname, buf);
	else
		send_trace_data(sock, buf->tid, shmbuf->data, shmbuf->size);

	shmbuf->size = 0;
}

struct writer_arg {
	struct list_head list;
	struct list_head bufs;
	struct uftrace_opts *opts;
	struct uftrace_kernel_writer *kern;
	struct uftrace_perf_writer *perf;
	int sock;
	int idx;
	int tid;
	int nr_cpu;
	int cpus[];
};

static void write_buf_list(struct list_head *buf_head, struct uftrace_opts *opts,
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

static int setup_pollfd(struct pollfd **pollfd, struct writer_arg *warg, bool setup_perf,
			bool setup_kernel)
{
	int nr_poll = 1;
	struct pollfd *p;
	int i;

	if (setup_perf)
		nr_poll += warg->nr_cpu;
	if (setup_kernel)
		nr_poll += warg->nr_cpu;

	p = xcalloc(nr_poll, sizeof(*p));

	p[0].fd = thread_ctl[0];
	p[0].events = POLLIN;
	nr_poll = 1;

	if (setup_perf) {
		for (i = 0; i < warg->nr_cpu; i++) {
			p[i + nr_poll].fd = warg->perf->event_fd[warg->cpus[i]];
			p[i + nr_poll].events = POLLIN;
		}
		nr_poll += warg->nr_cpu;
	}

	if (setup_kernel) {
		for (i = 0; i < warg->nr_cpu; i++) {
			p[i + nr_poll].fd = warg->kern->traces[warg->cpus[i]];
			p[i + nr_poll].events = POLLIN;
		}
		nr_poll += warg->nr_cpu;
	}

	*pollfd = p;
	return nr_poll;
}

static bool handle_pollfd(struct pollfd *pollfd, struct writer_arg *warg, bool trace_task,
			  bool trace_perf, bool trace_kernel, int timeout)
{
	int start = trace_task ? 0 : 1;
	int nr_poll = trace_task ? 1 : 0;
	bool check_task = false;
	int i;

	if (trace_perf)
		nr_poll += warg->nr_cpu;
	if (trace_kernel)
		nr_poll += warg->nr_cpu;

	if (poll(&pollfd[start], nr_poll, timeout) < 0)
		return false;

	for (i = start; i < nr_poll; i++) {
		if (!(pollfd[i].revents & POLLIN))
			continue;

		if (i == 0)
			check_task = true;
		else if (trace_perf && i < (warg->nr_cpu + 1)) {
			record_perf_data(warg->perf, warg->cpus[i - 1], warg->sock);
		}
		else if (trace_kernel) {
			int idx = i - (nr_poll - warg->nr_cpu);

			record_kernel_trace_pipe(warg->kern, warg->cpus[idx], warg->sock);
		}
	}

	return check_task;
}

static void finish_pollfd(struct pollfd *pollfd)
{
	free(pollfd);
}

void *writer_thread(void *arg)
{
	struct buf_list *buf, *pos;
	struct writer_arg *warg = arg;
	struct uftrace_opts *opts = warg->opts;
	struct pollfd *pollfd;
	int i, dummy;
	sigset_t sigset;

	pthread_setname_np(pthread_self(), "WriterThread");

	if (opts->rt_prio) {
		struct sched_param param = {
			.sched_priority = opts->rt_prio,
		};

		if (sched_setscheduler(0, SCHED_FIFO, &param) < 0)
			pr_warn("set scheduling param failed\n");
	}

	sigfillset(&sigset);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	setup_pollfd(&pollfd, warg, has_perf_event, opts->kernel);

	pr_dbg2("start writer thread %d\n", warg->idx);
	while (!buf_done) {
		LIST_HEAD(head);
		bool check_list = false;

		check_list = handle_pollfd(pollfd, warg, true, has_perf_event, opts->kernel, 1000);
		if (!check_list)
			continue;

		if (read(thread_ctl[0], &dummy, sizeof(dummy)) < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			/* other errors are problematic */
			break;
		}

		pthread_mutex_lock(&write_list_lock);

		if (!list_empty(&buf_write_list)) {
			/* pick first unhandled buf  */
			buf = list_first_entry(&buf_write_list, struct buf_list, list);
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

			if (!has_perf_event && !opts->kernel)
				continue;

			handle_pollfd(pollfd, warg, false, has_perf_event, opts->kernel, 0);
		}
	}
	pr_dbg2("stop writer thread %d\n", warg->idx);

	if (has_perf_event) {
		for (i = 0; i < warg->nr_cpu; i++)
			record_perf_data(warg->perf, warg->cpus[i], warg->sock);
	}

	finish_pollfd(pollfd);
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

static void record_mmap_file(const char *dirname, char *sess_id, int bufsize)
{
	int fd;
	struct shmem_list *sl;
	struct mcount_shmem_buffer *shmem_buf;

	/* write (append) it to disk */
	fd = uftrace_shmem_open(sess_id, O_RDWR, UFTRACE_SHMEM_PERMISSION_MODE);
	if (fd < 0) {
		pr_dbg("open shmem buffer failed: %s: %m\n", sess_id);
		return;
	}

	shmem_buf = mmap(NULL, bufsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (shmem_buf == MAP_FAILED)
		pr_err("mmap shmem buffer");

	close(fd);

	if (shmem_buf->flag & SHMEM_FL_RECORDING) {
		if (shmem_buf->flag & SHMEM_FL_NEW) {
			bool found = false;

			if (!list_empty(&shmem_need_unlink)) {
				sl = list_last_entry(&shmem_need_unlink, struct shmem_list, list);

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
			return;
		}
	}

	munmap(shmem_buf, bufsize);
}

static void stop_all_writers(void)
{
	buf_done = true;
	close(thread_ctl[1]);
	thread_ctl[1] = -1;
}

static void record_remaining_buffer(struct uftrace_opts *opts, int sock)
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
	char *shmem_root = (char *)uftrace_shmem_root();

	/* check the root is existed (due to some embed devices maybe not have it) */
	if (access(shmem_root, F_OK) != 0) {
		shmem_root = NULL;
		pr_warn("access shmem root failed and will ignore it, err: %s\n", strerror(errno));
	}

	/* unlink shmem list (not used anymore) */
	list_for_each_entry_safe(sl, tmp, &shmem_need_unlink, list) {
		char sid[128];
		struct dirent **shmem_bufs;
		int i, num;

		list_del(&sl->list);

		sscanf(sl->id, "/uftrace-%[^-]-%*d-%*d", shmem_session);
		pr_dbg2("unlink for session: %s\n", shmem_session);

		if (shmem_root) {
			num = scandir(shmem_root, &shmem_bufs, filter_shmem, alphasort);
			for (i = 0; i < num; i++) {
				sid[0] = '/';
				memcpy(&sid[1], shmem_bufs[i]->d_name, MSG_ID_SIZE);
				pr_dbg3("unlink %s\n", sid);
				uftrace_shmem_unlink(sid);
				free(shmem_bufs[i]);
			}
			free(shmem_bufs);
		}
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
		char line[PATH_MAX];

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
	child_exited = true;
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
	struct uftrace_msg msg;
	struct uftrace_msg_task tmsg;
	struct uftrace_msg_sess sess;
	struct uftrace_msg_dlopen dmsg;
	struct dlopen_list *dlib;
	char *exename;
	int lost;

	if (read_all(pfd, &msg, sizeof(msg)) < 0)
		pr_err("reading pipe failed:");

	if (msg.magic != UFTRACE_MSG_MAGIC)
		pr_err_ns("invalid message received: %x\n", msg.magic);

	switch (msg.type) {
	case UFTRACE_MSG_REC_START:
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

	case UFTRACE_MSG_REC_END:
		if (msg.len >= SHMEM_NAME_SIZE)
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, buf, msg.len) < 0)
			pr_err("reading pipe failed");

		buf[msg.len] = '\0';
		pr_dbg2("MSG  END : %s\n", buf);

		/* remove from shmem_list */
		list_for_each_entry_safe(sl, tmp, &shmem_list_head, list) {
			if (!memcmp(sl->id, buf, msg.len)) {
				list_del(&sl->list);
				free(sl);
				break;
			}
		}

		record_mmap_file(dirname, buf, bufsize);
		break;

	case UFTRACE_MSG_TASK_START:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		pr_dbg2("MSG TASK_START : %d/%d\n", tmsg.pid, tmsg.tid);

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

	case UFTRACE_MSG_TASK_END:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		pr_dbg2("MSG TASK_END : %d/%d\n", tmsg.pid, tmsg.tid);

		/* mark test exited */
		list_for_each_entry(pos, &tid_list_head, list) {
			if (pos->tid == tmsg.tid) {
				pos->exited = true;
				break;
			}
		}
		break;

	case UFTRACE_MSG_FORK_START:
		if (msg.len != sizeof(tmsg))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &tmsg, sizeof(tmsg)) < 0)
			pr_err("reading pipe failed");

		pr_dbg2("MSG FORK1: %d/%d\n", tmsg.pid, -1);

		add_tid_list(tmsg.pid, -1);
		break;

	case UFTRACE_MSG_FORK_END:
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
					pr_dbg3("override parent of daemon to %d\n", tl->pid);
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

	case UFTRACE_MSG_SESSION:
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
		free(exename);
		break;

	case UFTRACE_MSG_LOST:
		if (msg.len < sizeof(lost))
			pr_err_ns("invalid message length\n");

		if (read_all(pfd, &lost, sizeof(lost)) < 0)
			pr_err("reading pipe failed");

		shmem_lost_count += lost;
		break;

	case UFTRACE_MSG_DLOPEN:
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
		/* exename will be freed with the dlib */
		break;

	case UFTRACE_MSG_FINISH:
		pr_dbg2("MSG FINISH\n");
		finish_received = true;
		break;

	default:
		pr_warn("Unknown message type: %u\n", msg.type);
		break;
	}
}

static void send_task_file(int sock, const char *dirname)
{
	send_trace_metadata(sock, dirname, "task.txt");
}

/* find "sid-XXX.map" file */
static int filter_map(const struct dirent *de)
{
	size_t len = strlen(de->d_name);

	return !strncmp("sid-", de->d_name, 4) && !strncmp(".map", de->d_name + len - 4, 4);
}

static void send_map_files(int sock, const char *dirname)
{
	int i, maps;
	struct dirent **map_list;

	maps = scandir(dirname, &map_list, filter_map, alphasort);
	if (maps < 0)
		pr_err("cannot scan map files");

	for (i = 0; i < maps; i++) {
		send_trace_metadata(sock, dirname, map_list[i]->d_name);
		free(map_list[i]);
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
	struct dirent **sym_list;

	syms = scandir(dirname, &sym_list, filter_sym, alphasort);
	if (syms < 0)
		pr_err("cannot scan sym files");

	for (i = 0; i < syms; i++) {
		send_trace_metadata(sock, dirname, sym_list[i]->d_name);
		free(sym_list[i]);
	}
	free(sym_list);
}

/* find "XXX.dbg" file */
static int filter_dbg(const struct dirent *de)
{
	size_t len = strlen(de->d_name);

	return !strncmp(".dbg", de->d_name + len - 4, 4);
}

static void send_dbg_files(int sock, const char *dirname)
{
	int i, dbgs;
	struct dirent **dbg_list;

	dbgs = scandir(dirname, &dbg_list, filter_dbg, alphasort);
	if (dbgs < 0)
		pr_err("cannot scan dbg files");

	for (i = 0; i < dbgs; i++) {
		send_trace_metadata(sock, dirname, dbg_list[i]->d_name);
		free(dbg_list[i]);
	}
	free(dbg_list);
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
	free(info);
	free(filename);
}

static void send_kernel_metadata(int sock, const char *dirname)
{
	send_trace_metadata(sock, dirname, "kernel_header");
	send_trace_metadata(sock, dirname, "kallsyms");
}

static void send_event_file(int sock, const char *dirname)
{
	char buf[PATH_MAX];

	/* kernel events doesn't create the events file */
	snprintf(buf, sizeof(buf), "%s/events.txt", dirname);
	if (access(buf, F_OK) != 0)
		return;

	send_trace_metadata(sock, dirname, "events.txt");
}

static void send_log_file(int sock, const char *logfile)
{
	if (access(logfile, F_OK) != 0)
		return;

	send_trace_metadata(sock, NULL, (char *)logfile);
}

static void update_session_maps(struct uftrace_opts *opts)
{
	struct dirent **map_list;
	int i, maps;

	maps = scandir(opts->dirname, &map_list, filter_map, alphasort);
	if (maps <= 0) {
		if (maps == 0)
			errno = ENOENT;
		pr_err("cannot find map files");
	}

	for (i = 0; i < maps; i++) {
		char buf[PATH_MAX];

		snprintf(buf, sizeof(buf), "%s/%s", opts->dirname, map_list[i]->d_name);
		update_session_map(buf);
		free(map_list[i]);
	}

	free(map_list);
}

static void load_session_symbols(struct uftrace_opts *opts)
{
	struct dirent **map_list;
	int i, maps;

	maps = scandir(opts->dirname, &map_list, filter_map, alphasort);
	if (maps <= 0) {
		if (maps == 0)
			errno = ENOENT;
		pr_err("cannot find map files");
	}

	for (i = 0; i < maps; i++) {
		struct uftrace_sym_info sinfo = {
			.dirname = opts->dirname,
			.flags = SYMTAB_FL_ADJ_OFFSET,
		};
		char sid[20];

		sscanf(map_list[i]->d_name, "sid-%[^.].map", sid);
		free(map_list[i]);

		pr_dbg2("reading symbols for session %s\n", sid);
		read_session_map(opts->dirname, &sinfo, sid);

		load_module_symtabs(&sinfo);

		delete_session_map(&sinfo);
	}

	free(map_list);
}

static char *get_child_time(struct timespec *ts1, struct timespec *ts2)
{
#define SEC_TO_NSEC (1000000000ULL)

	char *elapsed_time = NULL;
	uint64_t sec = ts2->tv_sec - ts1->tv_sec;
	uint64_t nsec = ts2->tv_nsec - ts1->tv_nsec;

	if (nsec > SEC_TO_NSEC) {
		nsec += SEC_TO_NSEC;
		sec--;
	}

	xasprintf(&elapsed_time, "%" PRIu64 ".%09" PRIu64 " sec", sec, nsec);
	return elapsed_time;
}

static void print_child_time(char *elapsed_time)
{
	pr_out("elapsed time: %20s\n", elapsed_time);
}

static void print_child_usage(struct rusage *ru)
{
	pr_out(" system time: %6lu.%06lu000 sec\n", ru->ru_stime.tv_sec, ru->ru_stime.tv_usec);
	pr_out("   user time: %6lu.%06lu000 sec\n", ru->ru_utime.tv_sec, ru->ru_utime.tv_usec);
}

#define UFTRACE_MSG "Cannot trace '%s': No such executable file.\n"

#define MCOUNT_MSG                                                                                 \
	"Can't find '%s' symbol in the '%s'.\n"                                                    \
	"\tIt seems not to be compiled with -pg or -finstrument-functions flag.\n"                 \
	"\tYou can rebuild your program with it or use -P option for dynamic tracing.\n"

#define UFTRACE_ELF_MSG                                                                            \
	"Cannot trace '%s': Invalid file\n"                                                        \
	"\tThis file doesn't look like an executable ELF file.\n"                                  \
	"\tPlease check whether it's a kind of script or shell functions.\n"

#define MACHINE_MSG                                                                                \
	"Cannot trace '%s': Unsupported machine\n"                                                 \
	"\tThis machine type (%u) is not supported currently.\n"                                   \
	"\tSorry about that!\n"

#define ARGUMENT_MSG "uftrace: -A or -R might not work for binaries with -finstrument-functions\n"

#define STATIC_MSG                                                                                 \
	"Cannot trace static binary: %s\n"                                                         \
	"\tIt seems to be compiled with -static, rebuild the binary without it.\n"

#define SCRIPT_MSG                                                                                 \
	"Cannot trace script file: %s\n"                                                           \
	"\tTo trace binaries run by the script, use --force option.\n"

#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif

static bool is_regular_executable(const char *pathname)
{
	struct stat sb;

	if (!stat(pathname, &sb)) {
		if (S_ISREG(sb.st_mode) && (sb.st_mode & S_IXUSR))
			return true;
	}
	return false;
}

static void find_in_path(char *exename, char *buf, size_t len)
{
	/* try to find the binary in PATH */
	struct strv strv = STRV_INIT;
	char *env = getenv("PATH");
	char *path;
	bool found = false;
	int i;

	if (!env || exename[0] == '/')
		pr_err_ns(UFTRACE_MSG, exename);

	/* search opts->exename in PATH one by one */
	strv_split(&strv, env, ":");

	strv_for_each(&strv, path, i) {
		snprintf(buf, len, "%s/%s", path, exename);
		if (is_regular_executable(buf)) {
			found = true;
			break;
		}
	}

	if (!found)
		pr_err_ns(UFTRACE_MSG, exename);

	strv_free(&strv);
}

static void check_binary(struct uftrace_opts *opts)
{
	int fd;
	int chk;
	size_t i;
	char elf_ident[EI_NIDENT];
	static char altname[PATH_MAX]; // for opts->exename to be persistent
	uint16_t e_type;
	uint16_t e_machine;
	uint16_t supported_machines[] = { EM_X86_64, EM_ARM, EM_AARCH64, EM_386, EM_RISCV };

again:
	/* if it cannot be found in PATH, then fails inside */
	if (!is_regular_executable(opts->exename)) {
		find_in_path(opts->exename, altname, sizeof(altname));
		opts->exename = altname;
	}

	pr_dbg("checking binary %s\n", opts->exename);

	fd = open(opts->exename, O_RDONLY);
	if (fd < 0)
		pr_err("Cannot open '%s'", opts->exename);

	if (read(fd, elf_ident, sizeof(elf_ident)) < 0)
		pr_err("Cannot read '%s'", opts->exename);

	if (memcmp(elf_ident, ELFMAG, SELFMAG)) {
		char *script = altname;
		char *p;

		if (!check_script_file(opts->exename, altname, sizeof(altname)))
			pr_err_ns(UFTRACE_ELF_MSG, opts->exename);

#if defined(HAVE_LIBPYTHON2) || defined(HAVE_LIBPYTHON3)
		if (strstr(script, "python")) {
			opts->force = true;
			/* TODO: disable sched event until it can merge subsequent events */
			opts->no_sched = true;
		}
#endif

		if (!opts->force && !opts->patch)
			pr_err_ns(SCRIPT_MSG, opts->exename);

		script = str_ltrim(script);

		/* ignore options */
		p = strchr(script, ' ');
		if (p)
			*p = '\0';

		opts->exename = script;
		close(fd);
		goto again;
	}

	if (read(fd, &e_type, sizeof(e_type)) < 0)
		pr_err("Cannot read '%s'", opts->exename);

	if (e_type != ET_EXEC && e_type != ET_DYN)
		pr_err_ns(UFTRACE_ELF_MSG, opts->exename);

	if (read(fd, &e_machine, sizeof(e_machine)) < 0)
		pr_err("Cannot read '%s'", opts->exename);

	for (i = 0; i < ARRAY_SIZE(supported_machines); i++) {
		if (e_machine == supported_machines[i])
			break;
	}
	if (i == ARRAY_SIZE(supported_machines))
		pr_err_ns(MACHINE_MSG, opts->exename, e_machine);

	chk = check_static_binary(opts->exename);
	if (chk) {
		if (chk < 0)
			pr_err_ns("Cannot check '%s'\n", opts->exename);
		else
			pr_err_ns(STATIC_MSG, opts->exename);
	}

	if (!opts->force) {
		enum uftrace_trace_type chk_type;

		chk_type = check_trace_functions(opts->exename);

		if (chk_type == TRACE_NONE && !opts->patch) {
			/* there's no function to trace */
			pr_err_ns(MCOUNT_MSG, "mcount", opts->exename);
		}
		else if (chk_type == TRACE_CYGPROF && (opts->args || opts->retval)) {
			/* arg/retval doesn't support -finstrument-functions */
			pr_out(ARGUMENT_MSG);
		}
		else if (chk_type == TRACE_ERROR) {
			pr_err_ns("Cannot check '%s'\n", opts->exename);
		}
	}

	close(fd);
}

static void check_perf_event(struct uftrace_opts *opts)
{
	struct strv strv = STRV_INIT;
	char *evt;
	int i;
	bool found = false;
	enum uftrace_pattern_type ptype = opts->patt_type;

	has_perf_event = has_sched_event = !opts->no_event;

	if (opts->no_sched)
		has_sched_event = false;

	if (opts->event == NULL)
		return;

	strv_split(&strv, opts->event, ";");

	strv_for_each(&strv, evt, i) {
		struct uftrace_pattern patt;

		init_filter_pattern(ptype, &patt, evt);

		if (match_filter_pattern(&patt, "linux:task-new") ||
		    match_filter_pattern(&patt, "linux:task-exit") ||
		    match_filter_pattern(&patt, "linux:task-name"))
			found = true;

		if (match_filter_pattern(&patt, "linux:sched-in") ||
		    match_filter_pattern(&patt, "linux:sched-out") ||
		    match_filter_pattern(&patt, "linux:schedule")) {
			has_sched_event = true;
			found = true;
		}

		free_filter_pattern(&patt);

		if (found && has_sched_event)
			break;
	}

	strv_free(&strv);
	has_perf_event = found;
}

struct writer_data {
	int pid;
	int pipefd;
	int sock;
	int nr_cpu;
	int status;
	pthread_t *writers;
	struct timespec ts1, ts2;
	struct rusage usage;
	struct uftrace_kernel_writer kernel;
	struct uftrace_perf_writer perf;
};

static void setup_writers(struct writer_data *wd, struct uftrace_opts *opts)
{
	struct uftrace_kernel_writer *kernel = &wd->kernel;
	struct uftrace_perf_writer *perf = &wd->perf;
	struct sigaction sa = {
		.sa_flags = 0,
	};

	if (opts->nop) {
		opts->nr_thread = 0;
		opts->kernel = false;
		has_perf_event = false;
		wd->nr_cpu = 0;

		goto out;
	}

	sigfillset(&sa.sa_mask);
	sa.sa_handler = NULL;
	sa.sa_sigaction = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
	sigaction(SIGCHLD, &sa, NULL);

	if (opts->host) {
		wd->sock = setup_client_socket(opts);
		send_trace_dir_name(wd->sock, opts->dirname);
	}
	else
		wd->sock = -1;

	wd->nr_cpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (unlikely(wd->nr_cpu <= 0)) {
		wd->nr_cpu = sysconf(_SC_NPROCESSORS_CONF);
		if (wd->nr_cpu <= 0)
			pr_err("cannot know number of cpu");
	}

	if (opts->kernel || has_kernel_event(opts->event)) {
		int err;

		kernel->pid = wd->pid;
		kernel->output_dir = opts->dirname;
		kernel->depth = opts->kernel_depth;
		kernel->bufsize = opts->kernel_bufsize;
		kernel->clock = opts->clock;

		if (!opts->nr_thread) {
			if (opts->kernel_depth >= 4)
				opts->nr_thread = wd->nr_cpu;
			else if (opts->kernel_depth >= 2)
				opts->nr_thread = wd->nr_cpu / 2;
		}

		if (!opts->kernel_bufsize) {
			if (opts->kernel_depth >= 8)
				kernel->bufsize = PATH_MAX * 1024;
			else if (opts->kernel_depth >= 4)
				kernel->bufsize = 3072 * 1024;
			else if (opts->kernel_depth >= 2)
				kernel->bufsize = 2048 * 1024;
		}

		err = setup_kernel_tracing(kernel, opts);
		if (err) {
			if (err == -EPERM)
				pr_warn("kernel tracing requires root privilege\n");
			else
				pr_warn("kernel tracing disabled due to an error\n"
					"is CONFIG_FUNCTION_GRAPH_TRACER enabled in the kernel?\n");

			opts->kernel = false;
		}
	}

	if (!opts->nr_thread)
		opts->nr_thread = DIV_ROUND_UP(wd->nr_cpu, 4);
	else if (opts->nr_thread > wd->nr_cpu)
		opts->nr_thread = wd->nr_cpu;

	if (has_perf_event) {
		setup_clock_id(opts->clock);
		if (setup_perf_record(perf, wd->nr_cpu, wd->pid, opts->dirname, has_sched_event) <
		    0)
			has_perf_event = false;
	}

out:
	pr_dbg("creating %d thread(s) for recording\n", opts->nr_thread);
	wd->writers = xmalloc(opts->nr_thread * sizeof(*wd->writers));

	if (pipe(thread_ctl) < 0)
		pr_err("cannot create a pipe for writer thread");
}

static void start_tracing(struct writer_data *wd, struct uftrace_opts *opts, int ready_fd)
{
	int i, k;
	uint64_t go = 1;

	clock_gettime(CLOCK_MONOTONIC, &wd->ts1);

	if (opts->kernel && start_kernel_tracing(&wd->kernel) < 0) {
		opts->kernel = false;
		pr_warn("kernel tracing disabled due to an error\n");
	}

	for (i = 0; i < opts->nr_thread; i++) {
		struct writer_arg *warg;
		int cpu_per_thread = DIV_ROUND_UP(wd->nr_cpu, opts->nr_thread);
		size_t sizeof_warg = sizeof(*warg) + sizeof(int) * cpu_per_thread;

		warg = xzalloc(sizeof_warg);
		warg->opts = opts;
		warg->idx = i;
		warg->sock = wd->sock;
		warg->kern = &wd->kernel;
		warg->perf = &wd->perf;
		warg->nr_cpu = 0;
		INIT_LIST_HEAD(&warg->list);
		INIT_LIST_HEAD(&warg->bufs);

		if (opts->kernel || has_perf_event) {
			warg->nr_cpu = cpu_per_thread;

			for (k = 0; k < cpu_per_thread; k++) {
				if (i * cpu_per_thread + k < wd->nr_cpu)
					warg->cpus[k] = i * cpu_per_thread + k;
				else
					warg->cpus[k] = -1;
			}
		}

		pthread_create(&wd->writers[i], NULL, writer_thread, warg);
	}

	/* signal child that I'm ready */
	if (write(ready_fd, &go, sizeof(go)) != (ssize_t)sizeof(go))
		pr_err("signal to child failed");
}

static int stop_tracing(struct writer_data *wd, struct uftrace_opts *opts)
{
	int status = -1;
	int ret = UFTRACE_EXIT_SUCCESS;

	/* child finished, read remaining data in the pipe */
	while (!uftrace_done) {
		int remaining = 0;

		if (ioctl(wd->pipefd, FIONREAD, &remaining) < 0)
			break;

		if (remaining) {
			read_record_mmap(wd->pipefd, opts->dirname, opts->bufsize);
			continue;
		}

		/* wait for SIGCHLD or FORK_END */
		usleep(1000);

		/*
		 * It's possible to receive a remaining FORK_START message.
		 * In this case, we need to wait FORK_END message also in
		 * order to get proper pid.  Otherwise replay will fail with
		 * pid of -1.
		 */
		if (check_tid_list())
			break;

		if (finish_received) {
			status = UFTRACE_EXIT_FINISHED;
			break;
		}

		pr_dbg2("waiting for FORK2\n");
	}

	if (child_exited) {
		wait4(wd->pid, &status, 0, &wd->usage);
		if (WIFEXITED(status)) {
			pr_dbg("child terminated with exit code: %d\n", WEXITSTATUS(status));

			if (WEXITSTATUS(status))
				ret = UFTRACE_EXIT_FAILURE;
			else
				ret = UFTRACE_EXIT_SUCCESS;
		}
		else if (WIFSIGNALED(status)) {
			pr_warn("child terminated by signal: %d: %s\n", WTERMSIG(status),
				strsignal(WTERMSIG(status)));
			ret = UFTRACE_EXIT_SIGNALED;
		}
		else {
			pr_warn("child terminated with unknown reason: %d\n", status);
			memset(&wd->usage, 0, sizeof(wd->usage));
			ret = UFTRACE_EXIT_UNKNOWN;
		}
	}
	else if (opts->keep_pid)
		memset(&wd->usage, 0, sizeof(wd->usage));
	else
		getrusage(RUSAGE_CHILDREN, &wd->usage);

	stop_all_writers();
	if (opts->kernel)
		stop_kernel_tracing(&wd->kernel);

	clock_gettime(CLOCK_MONOTONIC, &wd->ts2);

	wd->status = status;
	return ret;
}

static void finish_writers(struct writer_data *wd, struct uftrace_opts *opts)
{
	int i;
	char *elapsed_time = get_child_time(&wd->ts1, &wd->ts2);

	if (opts->time) {
		print_child_time(elapsed_time);
		print_child_usage(&wd->usage);
	}

	if (opts->nop) {
		free(elapsed_time);
		return;
	}

	if (fill_file_header(opts, wd->status, &wd->usage, elapsed_time) < 0)
		pr_err("cannot generate data file");

	free(elapsed_time);

	if (shmem_lost_count)
		pr_warn("LOST %d records\n", shmem_lost_count);

	for (i = 0; i < opts->nr_thread; i++)
		pthread_join(wd->writers[i], NULL);
	free(wd->writers);
	close(thread_ctl[0]);

	flush_shmem_list(opts->dirname, opts->bufsize);
	record_remaining_buffer(opts, wd->sock);
	unlink_shmem_list();
	free_tid_list();

	if (opts->kernel)
		finish_kernel_tracing(&wd->kernel);
	if (has_perf_event)
		finish_perf_record(&wd->perf);
}

static void copy_data_files(struct uftrace_opts *opts, const char *ext)
{
	char path[PATH_MAX];
	glob_t g;
	size_t i;

	snprintf(path, sizeof(path), "%s/*%s", opts->with_syms, ext);
	glob(path, GLOB_NOSORT, NULL, &g);

	for (i = 0; i < g.gl_pathc; i++) {
		snprintf(path, sizeof(path), "%s/%s", opts->dirname,
			 uftrace_basename(g.gl_pathv[i]));
		copy_file(g.gl_pathv[i], path);
	}

	globfree(&g);
}

static void write_symbol_files(struct writer_data *wd, struct uftrace_opts *opts)
{
	struct dlopen_list *dlib, *tmp;

	if (opts->nop)
		return;

	/* add build-id info map files */
	update_session_maps(opts);

	if (opts->with_syms) {
		copy_data_files(opts, ".sym");
		copy_data_files(opts, ".dbg");
		goto after_save;
	}

	/* main executable and shared libraries */
	load_session_symbols(opts);

	/* dynamically loaded libraries using dlopen() */
	list_for_each_entry_safe(dlib, tmp, &dlopen_libs, list) {
		struct uftrace_sym_info dlib_sinfo = {
			.dirname = opts->dirname,
			.flags = SYMTAB_FL_ADJ_OFFSET,
		};
		char build_id[BUILD_ID_STR_SIZE];

		read_build_id(dlib->libname, build_id, sizeof(build_id));
		load_module_symtab(&dlib_sinfo, dlib->libname, build_id);

		list_del(&dlib->list);

		free(dlib->libname);
		free(dlib);
	}

	save_module_symtabs(opts->dirname);
	unload_module_symtabs();

after_save:
	if (opts->host) {
		int sock = wd->sock;

		send_task_file(sock, opts->dirname);
		send_map_files(sock, opts->dirname);
		send_sym_files(sock, opts->dirname);
		send_dbg_files(sock, opts->dirname);
		send_info_file(sock, opts->dirname);

		if (opts->kernel)
			send_kernel_metadata(sock, opts->dirname);
		if (opts->event)
			send_event_file(sock, opts->dirname);
		if (opts->logfile)
			send_log_file(sock, opts->logfile);

		send_trace_end(sock);
		close(sock);

		remove_directory(opts->dirname);
	}
	else if (geteuid() == 0)
		chown_directory(opts->dirname);
}

static int do_main_loop(int ready[], struct uftrace_opts *opts, int pid)
{
	int ret;
	struct writer_data wd;
	char *channel = NULL;

	close(ready[0]);
	if (opts->nop) {
		setup_writers(&wd, opts);
		start_tracing(&wd, opts, ready[1]);
		close(ready[1]);

		wait(NULL);
		uftrace_done = true;

		ret = stop_tracing(&wd, opts);
		finish_writers(&wd, opts);
		return ret;
	}

	xasprintf(&channel, "%s/%s", opts->dirname, ".channel");

	wd.pid = pid;
	wd.pipefd = open(channel, O_RDONLY | O_NONBLOCK);

	free(channel);
	if (wd.pipefd < 0)
		pr_err("cannot open pipe");

	if (opts->sig_trigger)
		pr_out("uftrace: install signal handlers to task %d\n", pid);

	setup_writers(&wd, opts);
	start_tracing(&wd, opts, ready[1]);
	close(ready[1]);

	while (!uftrace_done) {
		struct pollfd pollfd = {
			.fd = wd.pipefd,
			.events = POLLIN,
		};

		ret = poll(&pollfd, 1, 1000);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			pr_err("error during poll");

		if (pollfd.revents & POLLIN)
			read_record_mmap(wd.pipefd, opts->dirname, opts->bufsize);

		if (pollfd.revents & (POLLERR | POLLHUP))
			break;
	}

	ret = stop_tracing(&wd, opts);
	finish_writers(&wd, opts);

	write_symbol_files(&wd, opts);
	return ret;
}

static int do_child_exec(int ready[], struct uftrace_opts *opts, int argc, char *argv[])
{
	uint64_t dummy;
	char *shebang = NULL;
	char dirpath[PATH_MAX];
	char exepath[PATH_MAX];
	struct strv new_args = STRV_INIT;
	bool is_python = false;

	close(ready[1]);
	if (opts->no_randomize_addr) {
		/* disable ASLR (Address Space Layout Randomization) */
		if (personality(ADDR_NO_RANDOMIZE) < 0)
			pr_dbg("disabling ASLR failed\n");
	}

	/*
	 * The current working directory can be changed by calling chdir.
	 * So dirname has to be converted to an absolute path to avoid unexpected problems.
	 */
	if (realpath(opts->dirname, dirpath) != NULL)
		opts->dirname = dirpath;

	if (access(argv[0], F_OK) == 0) {
		/* prefer current directory over PATH */
		if (check_script_file(argv[0], exepath, sizeof(exepath)))
			shebang = exepath;
	}
	else {
		struct strv path_names = STRV_INIT;
		char *path, *dir;
		int i, ret;

		strv_split(&path_names, getenv("PATH"), ":");
		strv_for_each(&path_names, dir, i) {
			xasprintf(&path, "%s/%s", dir, argv[0]);
			ret = access(path, F_OK);
			if (ret == 0 && check_script_file(path, exepath, sizeof(exepath)))
				shebang = exepath;
			free(path);
			if (ret == 0)
				break;
		}
		strv_free(&path_names);
	}

	if (shebang) {
		char *s, *p;
		int i;

#if defined(HAVE_LIBPYTHON2) || defined(HAVE_LIBPYTHON3)
		if (strstr(shebang, "python"))
			is_python = true;
#endif
		s = str_ltrim(shebang);

		p = strchr(s, ' ');
		if (p != NULL)
			*p++ = '\0';

		strv_append(&new_args, s);
		if (p != NULL)
			strv_append(&new_args, p);

		if (is_python) {
			strv_append(&new_args, "-m");
			strv_append(&new_args, "uftrace");
			if (!opts->libcall)
				setenv("UFTRACE_PY_LIBCALL", "NONE", 1);
			if (opts->nest_libcall)
				setenv("UFTRACE_PY_LIBCALL", "NESTED", 1);
			/* disable library calls for 'python' interpreter */
			opts->libcall = false;
		}

		for (i = 0; i < argc; i++)
			strv_append(&new_args, argv[i]);

		argc = new_args.nr;
		argv = new_args.p;
	}

	setup_child_environ(opts, argc, argv);

	/* wait for parent ready */
	if (read(ready[0], &dummy, sizeof(dummy)) != (ssize_t)sizeof(dummy))
		pr_err("waiting for parent failed");
	close(ready[0]);

	if (is_python) {
		char *python_path = NULL;

		if (getenv("PYTHONPATH"))
			python_path = strdup(getenv("PYTHONPATH"));

#ifdef INSTALL_LIB_PATH
		python_path = strjoin(python_path, INSTALL_LIB_PATH, ":");
#endif
		python_path = strjoin(python_path, "python", ":"); /* FIXME */
		setenv("PYTHONPATH", python_path, 1);
		free(python_path);

		/*
		 * prevent from creating .pyc files inside __pycache__.
		 * it makes some script execution failed.
		 */
		setenv("PYTHONDONTWRITEBYTECODE", "1", 1);
	}

	/*
	 * The traced binary is already resolved into absolute pathname.
	 * So plain 'execv' is enough and no need to use 'execvp'.
	 */
	execv(opts->exename, argv);
	abort();
}

int command_record(int argc, char *argv[], struct uftrace_opts *opts)
{
	int pid;
	int ready[2];
	int ret = -1;
	char *channel = NULL;

	/* apply script-provided options */
	if (opts->script_file)
		parse_script_opt(opts);

	check_binary(opts);
	check_perf_event(opts);

	if (!opts->nop) {
		if (create_directory(opts->dirname) < 0)
			return -1;

		xasprintf(&channel, "%s/%s", opts->dirname, ".channel");
		if (mkfifo(channel, 0600) < 0)
			pr_err("cannot create a communication channel");
	}

	fflush(stdout);

	if (pipe(ready) < 0)
		pr_err("creating pipe failed");

	pid = fork();
	if (pid < 0)
		pr_err("cannot start child process");

	if (pid == 0) {
		if (opts->keep_pid)
			ret = do_main_loop(ready, opts, getppid());
		else
			do_child_exec(ready, opts, argc, argv);

		if (channel) {
			unlink(channel);
			free(channel);
		}
		return ret;
	}

	if (opts->keep_pid)
		do_child_exec(ready, opts, argc, argv);
	else
		ret = do_main_loop(ready, opts, pid);

	if (channel) {
		unlink(channel);
		free(channel);
	}
	return ret;
}
