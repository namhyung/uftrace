/*
 * Linux kernel ftrace support code.
 *
 * Copyright (c) 2015-2016  LG Electronics,  Namhyung Kim <namhyung@gmail.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "kernel"
#define PR_DOMAIN  DBG_KERNEL

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "utils/filter.h"
#include "utils/rbtree.h"
#include "libtraceevent/kbuffer.h"
#include "libtraceevent/event-parse.h"

#define TRACING_DIR  "/sys/kernel/debug/tracing"
#define FTRACE_TRACER  "function_graph"

static bool kernel_tracing_enabled;


static char *get_tracing_file(const char *name)
{
	char *file = NULL;

	xasprintf(&file, "%s/%s", TRACING_DIR, name);
	return file;
}

static void put_tracing_file(char *file)
{
	free(file);
}

static int __write_tracing_file(const char *name, const char *val, bool append,
				bool correct_sys_prefix)
{
	char *file;
	int fd, ret = -1;
	ssize_t size = strlen(val);
	int flags = O_WRONLY;

	file = get_tracing_file(name);
	if (!file) {
		pr_dbg("cannot get tracing file: %s: %m\n", name);
		return -1;
	}

	if (append)
		flags |= O_APPEND;
	else
		flags |= O_TRUNC;

	fd = open(file, flags);
	if (fd < 0) {
		pr_dbg("cannot open tracing file: %s: %m\n", name);
		goto out;
	}

	pr_dbg2("%s '%s' to tracing/%s\n", append ? "appending" : "writing",
	       val, name);

	if (write(fd, val, size) == size)
		ret = 0;
	else {
		if (errno == EINVAL && correct_sys_prefix) {
			char *newval = (char *)val;

			if (!strncmp(val, "sys_", 4))
				newval[0] = newval[2] = 'S';
			else if (!strncmp(val, "compat_sys_", 11))
				newval[7] = newval[9] = 'S';

			if (write(fd, newval, size) == size)
				ret = 0;
			else if (!strncmp(newval, "SyS_", 4) ||
				 !strncmp(newval, "compat_SyS_", 11))
				ret = 0;
		}
		if (ret < 0)
			pr_dbg("write '%s' to tracing/%s failed: %m\n",
			       val, name);
	}

	close(fd);
out:
	put_tracing_file(file);
	return ret;
}

static int write_tracing_file(const char *name, const char *val)
{
	return __write_tracing_file(name, val, false, false);
}

static int append_tracing_file(const char *name, const char *val)
{
	return __write_tracing_file(name, val, true, false);
}

static int set_tracing_pid(int pid)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d", pid);
	return append_tracing_file("set_ftrace_pid", buf);
}

static int set_tracing_clock(void)
{
	return write_tracing_file("trace_clock", "mono");
}

struct kfilter {
	struct list_head list;
	char name[];
};

static int set_tracing_filter(struct ftrace_kernel *kernel)
{
	const char *filter_file;
	struct kfilter *pos, *tmp;

	filter_file = "set_graph_function";
	list_for_each_entry_safe(pos, tmp, &kernel->filters, list) {
		if (__write_tracing_file(filter_file, pos->name,
					 true, true) < 0)
			return -1;

		list_del(&pos->list);
		free(pos);
	}

	filter_file = "set_graph_notrace";
	list_for_each_entry_safe(pos, tmp, &kernel->notrace, list) {
		if (__write_tracing_file(filter_file, pos->name,
					 true, true) < 0)
			return -1;

		list_del(&pos->list);
		free(pos);
	}

	return 0;
}

static int set_tracing_depth(struct ftrace_kernel *kernel)
{
	int ret = 0;
	char buf[32];

	snprintf(buf, sizeof(buf), "%d", kernel->depth);
	ret = write_tracing_file("max_graph_depth", buf);

	return ret;
}

static int set_tracing_bufsize(struct ftrace_kernel *kernel)
{
	int ret = 0;
	char buf[32];

	if (kernel->bufsize) {
		snprintf(buf, sizeof(buf), "%lu", kernel->bufsize >> 10);
		ret = write_tracing_file("buffer_size_kb", buf);
	}
	return ret;
}

static int reset_tracing_files(void)
{
	if (write_tracing_file("tracing_on", "0") < 0)
		return -1;

	if (write_tracing_file("current_tracer", "nop") < 0)
		return -1;

	if (write_tracing_file("trace_clock", "local") < 0)
		return -1;

	if (write_tracing_file("set_ftrace_pid", " ") < 0)
		return -1;

	if (write_tracing_file("set_graph_function", " ") < 0)
		return -1;

	/* ignore error on old kernel */
	write_tracing_file("set_graph_notrace", " ");

	if (write_tracing_file("max_graph_depth", "0") < 0)
		return -1;

	/* default kernel buffer size: 16384 * 88 / 1024 = 1408 */
	if (write_tracing_file("buffer_size_kb", "1408") < 0)
		return -1;

	kernel_tracing_enabled = false;
	return 0;
}

static int __setup_kernel_tracing(struct ftrace_kernel *kernel)
{
	if (geteuid() != 0) {
		pr_log("kernel tracing requires root privilege\n");
		return -1;
	}

	if (reset_tracing_files() < 0) {
		pr_dbg("failed to reset tracing files\n");
		return -1;
	}

	pr_dbg("setting up kernel tracing\n");

	/* reset ftrace buffer */
	if (write_tracing_file("trace", "0") < 0)
		goto out;

	if (set_tracing_clock() < 0)
		goto out;

	if (set_tracing_pid(kernel->pid) < 0)
		goto out;

	if (set_tracing_filter(kernel) < 0)
		goto out;

	if (set_tracing_depth(kernel) < 0)
		goto out;

	if (set_tracing_bufsize(kernel) < 0)
		goto out;

	if (write_tracing_file("current_tracer", FTRACE_TRACER) < 0)
		goto out;

	kernel_tracing_enabled = true;
	return 0;

out:
	reset_tracing_files();
	return -1;
}

/**
 * setup_kernel_tracing - prepare to record kernel ftrace data (binary)
 * @kernel : kernel ftrace handle
 * @filters: CSV of functions to filter
 *
 * This function sets up all necessary data structures and configure
 * kernel ftrace subsystem.
 */
int setup_kernel_tracing(struct ftrace_kernel *kernel, char *filters)
{
	char *pos, *str, *name;
	struct kfilter *kfilter;
	struct list_head *head;
	int i, n;

	INIT_LIST_HEAD(&kernel->filters);
	INIT_LIST_HEAD(&kernel->notrace);

	if (filters == NULL)
		goto setup;

	pos = str = xstrdup(filters);

	name = strtok(pos, ";");
	while (name) {
		pos = strchr(name, '@');
		if (!pos || strncasecmp(pos+1, "kernel", 6))
			goto next;
		*pos = '\0';

		if (name[0] == '!') {
			head = &kernel->notrace;
			name++;
		} else
			head = &kernel->filters;

		kfilter = xmalloc(sizeof(*kfilter) + strlen(name) + 1);
		strcpy(kfilter->name, name);
		list_add(&kfilter->list, head);

		/* add SyS_ (or compat_SyS_) aliases for syscall pattern */
		if (!strncmp(name, "sys_", 4) && strchr(name, '*')) {
			kfilter = xmalloc(sizeof(*kfilter) + strlen(name) + 1);
			strcpy(kfilter->name, name);
			kfilter->name[0] = 'S';
			kfilter->name[2] = 'S';
			list_add(&kfilter->list, head);
		}
		if (!strncmp(name, "compat_sys_", 11) && strchr(name, '*')) {
			kfilter = xmalloc(sizeof(*kfilter) + strlen(name) + 1);
			strcpy(kfilter->name, name);
			kfilter->name[7] = 'S';
			kfilter->name[9] = 'S';
			list_add(&kfilter->list, head);
		}
next:
		name = strtok(NULL, ";");
	}

setup:
	if (__setup_kernel_tracing(kernel) < 0)
		return -1;

	kernel->nr_cpus = n = sysconf(_SC_NPROCESSORS_ONLN);

	kernel->traces	= xcalloc(n, sizeof(*kernel->traces));
	kernel->fds	= xcalloc(n, sizeof(*kernel->fds));

 	for (i = 0; i < kernel->nr_cpus; i++) {
		kernel->traces[i] = -1;
		kernel->fds[i] = -1;
	}

	return 0;
}

/**
 * start_kernel_tracing - prepare to record kernel ftrace data (binary)
 * @kernel : kernel ftrace handle
 *
 * This function sets up all necessary data structures and configure
 * kernel ftrace subsystem.  As this function modifies system ftrace
 * configuration it should be used in pair with stop_kernel_tracing()
 * function.
 *
 * The kernel ftrace data is captured from per-cpu trace_pipe_raw file
 * as binary form and saved to kernel-cpuXX.dat file in the ftrace
 * data directory.
 */
int start_kernel_tracing(struct ftrace_kernel *kernel)
{
	char *trace_file;
	char buf[4096];
	int i;
	int saved_errno;

	for (i = 0; i < kernel->nr_cpus; i++) {
		/* TODO: take an account of (currently) offline cpus */
		snprintf(buf, sizeof(buf), "per_cpu/cpu%d/trace_pipe_raw", i);

		trace_file = get_tracing_file(buf);
		if (!trace_file) {
			pr_dbg("failed to open %s: %m\n", buf);
			goto out;
		}

		kernel->traces[i] = open(trace_file, O_RDONLY);
		saved_errno = errno;

		put_tracing_file(trace_file);

		if (kernel->traces[i] < 0) {
			errno = saved_errno;
			pr_dbg("failed to open %s: %m\n", buf);
			goto out;
		}

		fcntl(kernel->traces[i], F_SETFL, O_NONBLOCK);

		snprintf(buf, sizeof(buf), "%s/kernel-cpu%d.dat",
			 kernel->output_dir, i);

		kernel->fds[i] = open(buf, O_WRONLY | O_TRUNC | O_CREAT, 0600);
		if (kernel->fds[i] < 0) {
			pr_dbg("failed to open output file: %s: %m\n", buf);
			goto out;
		}
	}

	if (write_tracing_file("tracing_on", "1") < 0) {
		pr_dbg("can't enable tracing\n");
		goto out;
	}

	pr_dbg("kernel tracing started..\n");
	return 0;

out:
	for (i = 0; kernel->nr_cpus; i++) {
		close(kernel->traces[i]);
		close(kernel->fds[i]);
	}

	free(kernel->traces);
	free(kernel->fds);

	reset_tracing_files();
	return -1;
}

/**
 * record_kernel_trace_pipe - read and save kernel ftrace data for specific cpu
 * @kernel - kernel ftrace handle
 * @cpu - cpu to read
 *
 * This function read trace data for @cpu and save it to file.
 */
int record_kernel_trace_pipe(struct ftrace_kernel *kernel, int cpu)
{
	char buf[4096];
	ssize_t n;

	if (cpu < 0 || cpu >= kernel->nr_cpus)
		return 0;

retry:
	n = read(kernel->traces[cpu], buf, sizeof(buf));
	if (n < 0) {
		if (errno == EINTR)
			goto retry;
		if (errno == EAGAIN)
			return 0;
		else
			return -errno;
	}

	if (n && write(kernel->fds[cpu], buf, n) != n)
		return -1;

	return n;
}

/**
 * record_kernel_tracing - read and save kernel ftrace data (binary)
 * @kernel - kernel ftrace handle
 *
 * This function read every (online) per-cpu trace data in a
 * round-robin fashion and save them to files.
 */
int record_kernel_tracing(struct ftrace_kernel *kernel)
{
	ssize_t bytes = 0;
	ssize_t n;
	int i;

	if (!kernel_tracing_enabled)
		return -1;

	for (i = 0; i < kernel->nr_cpus; i++) {
		n = record_kernel_trace_pipe(kernel, i);
		if (n < 0) {
			pr_log("record kernel data (cpu %d) failed: %m\n", i);
			return n;
		}
		bytes += n;
	}

	pr_dbg2("kernel ftrace record wrote %zd bytes\n", bytes);
	return bytes;
}

/**
 * stop_kernel_tracing - stop recording kernel ftrace data
 * @kernel - kernel ftrace handle
 *
 * This function signals kernel to stop generating trace data.
 */
int stop_kernel_tracing(struct ftrace_kernel *kernel)
{
	if (!kernel_tracing_enabled)
		return 0;

	return write_tracing_file("tracing_on", "0");
}

/**
 * finish_kernel_tracing - finish kernel ftrace data
 * @kernel - kernel ftrace handle
 *
 * This function reads out remaining ftrace data and restores kernel
 * ftrace configuration.
 */
int finish_kernel_tracing(struct ftrace_kernel *kernel)
{
	int i;

	pr_dbg("kernel tracing stopped.\n");

	while (record_kernel_tracing(kernel) > 0)
		continue;

	for (i = 0; i < kernel->nr_cpus; i++) {
		close(kernel->traces[i]);
		close(kernel->fds[i]);
	}

	free(kernel->traces);
	free(kernel->fds);

	reset_tracing_files();

	return 0;
}

static size_t trace_pagesize;
static struct trace_seq trace_seq;
static struct ftrace_ret_stack trace_rstack = {
	.unused = FTRACE_UNUSED,
};

static int prepare_kbuffer(struct ftrace_kernel *kernel, int cpu);

static int
funcgraph_entry_handler(struct trace_seq *s, struct pevent_record *record,
			struct event_format *event, void *context);
static int
funcgraph_exit_handler(struct trace_seq *s, struct pevent_record *record,
		       struct event_format *event, void *context);

static int scandir_filter(const struct dirent *d)
{
	return !strncmp(d->d_name, "kernel-cpu", 10);
}

/**
 * setup_kernel_data - prepare to read kernel ftrace data from files
 * @kernel - kernel ftrace handle
 *
 * This function initializes necessary data structures for reading
 * kernel ftrace data files.  It should be called in pair with
 * finish_kernel_data().
 */
int setup_kernel_data(struct ftrace_kernel *kernel)
{
	int i;
	int fd;
	size_t len;
	char buf[4096];
	enum kbuffer_endian endian = KBUFFER_ENDIAN_LITTLE;
	enum kbuffer_long_size longsize = KBUFFER_LSIZE_8;
	struct dirent **list;

	kernel->pevent = pevent_alloc();
	if (kernel->pevent == NULL)
		return -1;

	trace_seq_init(&trace_seq);

	kernel->nr_cpus = scandir(kernel->output_dir, &list, scandir_filter, versionsort);
	if (kernel->nr_cpus <= 0) {
		pr_log("cannot find kernel trace data\n");
		return -1;
	}

	pr_dbg("found kernel ftrace data for %d cpus\n", kernel->nr_cpus);

	kernel->fds	= xcalloc(kernel->nr_cpus, sizeof(*kernel->fds));
	kernel->offsets	= xcalloc(kernel->nr_cpus, sizeof(*kernel->offsets));
	kernel->sizes	= xcalloc(kernel->nr_cpus, sizeof(*kernel->sizes));
	kernel->mmaps	= xcalloc(kernel->nr_cpus, sizeof(*kernel->mmaps));
	kernel->kbufs	= xcalloc(kernel->nr_cpus, sizeof(*kernel->kbufs));
	kernel->rstacks = xcalloc(kernel->nr_cpus, sizeof(*kernel->rstacks));

	kernel->rstack_list   = xcalloc(kernel->nr_cpus, sizeof(*kernel->rstack_list));
	kernel->rstack_valid  = xcalloc(kernel->nr_cpus, sizeof(*kernel->rstack_valid));
	kernel->rstack_done   = xcalloc(kernel->nr_cpus, sizeof(*kernel->rstack_done));
	kernel->missed_events = xcalloc(kernel->nr_cpus, sizeof(*kernel->missed_events));
	kernel->tids          = xcalloc(kernel->nr_cpus, sizeof(*kernel->tids));

	/* FIXME: should read recorded data file */
	pevent_set_long_size(kernel->pevent, sizeof(long));
	trace_pagesize = getpagesize(); /* pevent_get_page_size() */

	if (pevent_is_file_bigendian(kernel->pevent))
		endian = KBUFFER_ENDIAN_BIG;
	if (pevent_get_long_size(kernel->pevent) == 4)
		longsize = KBUFFER_LSIZE_4;

	for (i = 0; i < kernel->nr_cpus; i++) {
		struct stat stbuf;

		snprintf(buf, sizeof(buf), "%s/%s",
			 kernel->output_dir, list[i]->d_name);

		kernel->fds[i] = open(buf, O_RDONLY);
		if (kernel->fds[i] < 0)
			break;

		if (fstat(kernel->fds[i], &stbuf) < 0)
			break;

		kernel->sizes[i] = stbuf.st_size;

		kernel->kbufs[i] = kbuffer_alloc(longsize, endian);

		if (kernel->pevent->old_format)
			kbuffer_set_old_format(kernel->kbufs[i]);

		setup_rstack_list(&kernel->rstack_list[i]);

		if (!kernel->sizes[i])
			continue;

		if (prepare_kbuffer(kernel, i) < 0)
			break;
	}

	free(list);
	if (i != kernel->nr_cpus) {
		pr_dbg("failed to access to kernel trace data: %s: %m\n", buf);
		return -1;
	}

	fd = open(TRACING_DIR"/events/header_page", O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, sizeof(buf));
	pevent_parse_header_page(kernel->pevent, buf, len, pevent_get_long_size(kernel->pevent));
	close(fd);

	fd = open(TRACING_DIR"/events/ftrace/funcgraph_entry/format", O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, sizeof(buf));
	pevent_parse_event(kernel->pevent, buf, len, "ftrace");
	close(fd);

	fd = open(TRACING_DIR"/events/ftrace/funcgraph_exit/format", O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, sizeof(buf));
	pevent_parse_event(kernel->pevent, buf, len, "ftrace");
	close(fd);

	/* TODO: read /proc/kallsyms and register functions */

	pevent_register_event_handler(kernel->pevent, -1, "ftrace", "funcgraph_entry",
				      funcgraph_entry_handler, NULL);
	pevent_register_event_handler(kernel->pevent, -1, "ftrace", "funcgraph_exit",
				      funcgraph_exit_handler, NULL);
	return 0;
}

/**
 * finish_kernel_data - tear down data structures for kernel ftrace
 * @kernel - kernel ftrace handle
 *
 * This function destroys all data structures created by
 * setup_kernel_data().
 */
int finish_kernel_data(struct ftrace_kernel *kernel)
{
	int i;

	for (i = 0; i < kernel->nr_cpus; i++) {
		close(kernel->fds[i]);

		if (!kernel->rstack_done[i])
			munmap(kernel->mmaps[i], trace_pagesize);

		kbuffer_free(kernel->kbufs[i]);

		reset_rstack_list(&kernel->rstack_list[i]);
	}

	free(kernel->fds);
	free(kernel->offsets);
	free(kernel->sizes);
	free(kernel->mmaps);
	free(kernel->kbufs);
	free(kernel->rstacks);

	free(kernel->rstack_list);
	free(kernel->rstack_valid);
	free(kernel->rstack_done);
	free(kernel->missed_events);
	free(kernel->tids);

	trace_seq_destroy(&trace_seq);
	pevent_free(kernel->pevent);

	return 0;
}

static int prepare_kbuffer(struct ftrace_kernel *kernel, int cpu)
{
	kernel->mmaps[cpu] = mmap(NULL, trace_pagesize, PROT_READ, MAP_PRIVATE,
				  kernel->fds[cpu], kernel->offsets[cpu]);
	if (kernel->mmaps[cpu] == MAP_FAILED) {
		pr_dbg("loading kbuffer for cpu %d failed", cpu);
		return -1;
	}

	kbuffer_load_subbuffer(kernel->kbufs[cpu], kernel->mmaps[cpu]);
	kernel->missed_events[cpu] = kbuffer_missed_events(kernel->kbufs[cpu]);

	return 0;
}

static int next_kbuffer_page(struct ftrace_kernel *kernel, int cpu)
{
	munmap(kernel->mmaps[cpu], trace_pagesize);
	kernel->mmaps[cpu] = NULL;

	kernel->offsets[cpu] += trace_pagesize;

	if (kernel->offsets[cpu] >= (loff_t)kernel->sizes[cpu]) {
		kernel->rstack_done[cpu] = true;
		return -1;
	}

	return prepare_kbuffer(kernel, cpu);
}

static int
funcgraph_entry_handler(struct trace_seq *s, struct pevent_record *record,
			struct event_format *event, void *context)
{
	unsigned long long depth;
	unsigned long long addr;

	if (pevent_get_any_field_val(s, event, "depth", record, &depth, 1))
		return -1;

	if (pevent_get_any_field_val(s, event, "func", record, &addr, 1))
		return -1;

	trace_rstack.type  = FTRACE_ENTRY;
	trace_rstack.time  = record->ts;
	trace_rstack.addr  = addr;
	trace_rstack.depth = depth;

	return 0;
}

static int
funcgraph_exit_handler(struct trace_seq *s, struct pevent_record *record,
		       struct event_format *event, void *context)
{
	unsigned long long depth;
	unsigned long long addr;

	if (pevent_get_any_field_val(s, event, "depth", record, &depth, 1))
		return -1;

	if (pevent_get_any_field_val(s, event, "func", record, &addr, 1))
		return -1;

	trace_rstack.type  = FTRACE_EXIT;
	trace_rstack.time  = record->ts;
	trace_rstack.addr  = addr;
	trace_rstack.depth = depth;

	return 0;
}

/**
 * read_kernel_cpu_data - read next kernel tracing data of specific cpu
 * @kernel - kernel ftrace handle
 * @cpu    - cpu number
 *
 * This function reads tracing data from kbuffer and saves it to the
 * @kernel->rstacks[@cpu].  It returns 0 if succeeded, -1 if there's
 * no more data.
 */
int read_kernel_cpu_data(struct ftrace_kernel *kernel, int cpu)
{
	unsigned long long timestamp;
	void *data;
	int type;
	struct pevent_record record;
	struct event_format *event;

	data = kbuffer_read_event(kernel->kbufs[cpu], &timestamp);
	while (!data) {
		if (next_kbuffer_page(kernel, cpu) < 0)
			return -1;
		data = kbuffer_read_event(kernel->kbufs[cpu], &timestamp);
	}

	record.ts = timestamp;
	record.cpu = cpu;
	record.data = data;
	record.offset = kbuffer_curr_offset(kernel->kbufs[cpu]);
	record.missed_events = kbuffer_missed_events(kernel->kbufs[cpu]);
	record.size = kbuffer_event_size(kernel->kbufs[cpu]);
	record.record_size = kbuffer_curr_size(kernel->kbufs[cpu]);
//	record.ref_count = 1;
//	record.locked = 1;

	trace_seq_reset(&trace_seq);
	type = pevent_data_type(kernel->pevent, &record);
	event = pevent_find_event(kernel->pevent, type);
	if (event == NULL) {
		pr_dbg("cannot find event for type: %d\n", type);
		return -1;
	}

	/* this will call event handlers */
	pevent_event_info(&trace_seq, event, &record);

	kernel->tids[cpu] = pevent_data_pid(kernel->pevent, &record);
	memcpy(&kernel->rstacks[cpu], &trace_rstack, sizeof(trace_rstack));
	kernel->rstack_valid[cpu] = true;

	kbuffer_next_event(kernel->kbufs[cpu], NULL);

	return 0;
}

static int read_kernel_cpu(struct ftrace_file_handle *handle, int cpu)
{
	struct ftrace_kernel *kernel = handle->kern;
	struct uftrace_rstack_list *rstack_list = &kernel->rstack_list[cpu];
	struct ftrace_ret_stack *curr;
	int tid, prev_tid = -1;

	if (!handle->time_filter)
		return read_kernel_cpu_data(kernel, cpu);

	if (rstack_list->count)
		goto out;

	/*
	 * read task (kernel) stack until it found an entry that exceeds
	 * the given time filter (-t option).
	 */
	while (read_kernel_cpu_data(kernel, cpu) == 0) {
		curr = &kernel->rstacks[cpu];

		/* prevent ustack from invalid access */
		kernel->rstack_valid[cpu] = false;

		tid = kernel->tids[cpu];
		if (prev_tid == -1)
			prev_tid = tid;

		/* XXX: handle scheduled task properly */
		if (tid != prev_tid) {
			add_to_rstack_list(rstack_list, curr, NULL);
			break;
		}
		prev_tid = tid;

		if (curr->type == FTRACE_ENTRY) {
			/* it needs to wait until matching exit found */
			add_to_rstack_list(rstack_list, curr, NULL);
		}
		else if (curr->type == FTRACE_EXIT) {
			struct uftrace_rstack_list_node *last;
			uint64_t delta;

			if (rstack_list->count == 0) {
				/* it's already exceeded time filter, just return */
				add_to_rstack_list(rstack_list, curr, NULL);
				break;
			}

			last = list_last_entry(&rstack_list->read,
					       typeof(*last), list);
			delta = curr->time - last->rstack.time;

			if (delta < handle->time_filter) {
				struct ftrace_session *sess = first_session;
				struct ftrace_trigger tr = {};
				unsigned long real_addr;

				/* filter match needs full (64-bit) address */
				real_addr = get_real_address(curr->addr);
				/*
				 * it might set TRACE trigger, which shows
				 * function even if it's less than the time filter.
				 */
				ftrace_match_filter(&sess->filters,
						    real_addr, &tr);
				if (tr.flags & TRIGGER_FL_TRACE) {
					add_to_rstack_list(rstack_list, curr, NULL);
					break;
				}

				/* also delete matching entry (at the last) */
				delete_last_rstack_list(rstack_list);
			} else {
				/* found! process all existing rstacks in the list */
				add_to_rstack_list(rstack_list, curr, NULL);
				break;
			}
		}
		else {
			/* TODO: handle LOST properly */
			add_to_rstack_list(rstack_list, curr, NULL);
			break;
		}

	}
	if (kernel->rstack_done[cpu] && rstack_list->count == 0)
		return -1;

out:
	kernel->rstack_valid[cpu] = true;
	curr = get_first_rstack_list(rstack_list);
	memcpy(&kernel->rstacks[cpu], curr, sizeof(*curr));
	return 0;
}

/**
 * read_kernel_stack - peek next kernel ftrace data
 * @handle - ftrace file handle
 * @taskp  - pointer to the oldest task
 *
 * This function reads all kernel function trace records of each cpu,
 * compares the timestamp, and find the oldest one.  After this
 * function @task will point a task which has the oldest record, and
 * it can be accessed by @task->kstack.  The oldest record will *NOT*
 * be consumed, that means another call to this function will give you
 * same (*@taskp)->kstack.
 *
 * This function returns the cpu number (> 0) if it reads a rstack,
 * -1 if it's done.
 */
int read_kernel_stack(struct ftrace_file_handle *handle,
		      struct ftrace_task_handle **taskp)
{
	int i;
	int first_cpu = -1;
	int first_tid = -1;
	uint64_t first_timestamp = 0;
	struct ftrace_kernel *kernel = handle->kern;
	struct ftrace_ret_stack *first_rstack = NULL;

	for (i = 0; i < kernel->nr_cpus; i++) {
		uint64_t timestamp;

		if (kernel->rstack_done[i] && kernel->rstack_list[i].count == 0)
			continue;

		if (!kernel->rstack_valid[i]) {
			read_kernel_cpu(handle, i);
			if (!kernel->rstack_valid[i])
				continue;
		}

		timestamp = kernel->rstacks[i].time;
		if (!first_rstack || first_timestamp > timestamp) {
			first_rstack = &kernel->rstacks[i];
			first_timestamp = timestamp;
			first_tid = kernel->tids[i];
			first_cpu = i;
		}
	}

	if (first_rstack == NULL)
		return -1;

	*taskp = get_task_handle(handle, first_tid);
	memcpy(&(*taskp)->kstack, first_rstack, sizeof(*first_rstack));

	return first_cpu;
}
