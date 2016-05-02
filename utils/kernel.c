/*
 * Linux kernel ftrace support code.
 *
 * Copyright (c) 2015  LG Electronics,  Namhyung Kim <namhyung@gmail.com>
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
#include "utils/rbtree.h"
#include "libmcount/mcount.h"
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

static int __write_tracing_file(const char *name, const char *val, bool append)
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
	else
		pr_dbg("write '%s' to tracing/%s failed: %m\n", val, name);

	close(fd);
out:
	put_tracing_file(file);
	return ret;
}

static int write_tracing_file(const char *name, const char *val)
{
	return __write_tracing_file(name, val, false);
}

static int append_tracing_file(const char *name, const char *val)
{
	return __write_tracing_file(name, val, true);
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
		if (append_tracing_file(filter_file, pos->name) < 0)
			return -1;

		list_del(&pos->list);
		free(pos);
	}

	filter_file = "set_graph_notrace";
	list_for_each_entry_safe(pos, tmp, &kernel->notrace, list) {
		if (append_tracing_file(filter_file, pos->name) < 0)
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

	if (kernel->depth != MCOUNT_RSTACK_MAX) {
		snprintf(buf, sizeof(buf), "%d", kernel->depth);
		ret = write_tracing_file("max_graph_depth", buf);
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

	kernel_tracing_enabled = false;
	return 0;
}

static int setup_kernel_tracing(struct ftrace_kernel *kernel)
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

	if (write_tracing_file("current_tracer", FTRACE_TRACER) < 0)
		goto out;

	kernel_tracing_enabled = true;
	return 0;

out:
	reset_tracing_files();
	return -1;
}

int setup_kernel_filters(struct ftrace_kernel *kernel, char *filters)
{
	char *pos, *str, *name;
	struct kfilter *kfilter;
	struct list_head *head;

	INIT_LIST_HEAD(&kernel->filters);
	INIT_LIST_HEAD(&kernel->notrace);

	if (filters == NULL)
		return 0;

	pos = str = xstrdup(filters);

	name = strtok(pos, ",");
	while (name) {
		pos = strchr(name, '@');
		if (!pos || strcasecmp(pos+1, "kernel"))
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
next:
		name = strtok(NULL, ",");
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
	int n, i;
	int saved_errno;

	if (setup_kernel_tracing(kernel) < 0)
		return -1;

	kernel->nr_cpus = n = sysconf(_SC_NPROCESSORS_ONLN);

	kernel->traces	= xcalloc(n, sizeof(*kernel->traces));
	kernel->fds	= xcalloc(n, sizeof(*kernel->fds));

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

static int record_kernel_trace_pipe(struct ftrace_kernel *kernel, int cpu)
{
	char buf[4096];
	ssize_t n;

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
static struct mcount_ret_stack trace_rstack;

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

	kernel->rstack_valid  = xcalloc(kernel->nr_cpus, sizeof(*kernel->rstack_valid));
	kernel->rstack_done   = xcalloc(kernel->nr_cpus, sizeof(*kernel->rstack_done));
	kernel->missed_events = xcalloc(kernel->nr_cpus, sizeof(*kernel->missed_events));

	/* FIXME: should read recorded data file */
	if (pevent_is_file_bigendian(kernel->pevent))
		endian = KBUFFER_ENDIAN_BIG;
	if (pevent_get_long_size(kernel->pevent) == 4)
		longsize = KBUFFER_LSIZE_4;
	trace_pagesize = getpagesize(); /* pevent_get_page_size() */

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
	}

	free(kernel->fds);
	free(kernel->offsets);
	free(kernel->sizes);
	free(kernel->mmaps);
	free(kernel->kbufs);
	free(kernel->rstacks);

	free(kernel->rstack_valid);
	free(kernel->rstack_done);
	free(kernel->missed_events);

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
	unsigned long long tid;
	unsigned long long depth;
	unsigned long long addr;

	if (pevent_get_any_field_val(s, event, "common_pid", record, &tid, 1))
		return -1;

	if (pevent_get_any_field_val(s, event, "depth", record, &depth, 1))
		return -1;

	if (pevent_get_any_field_val(s, event, "func", record, &addr, 1))
		return -1;

	trace_rstack.tid = tid;
	trace_rstack.depth = depth;
	trace_rstack.child_ip = addr;
	trace_rstack.start_time = record->ts;
	trace_rstack.end_time = 0;

	return 0;
}

static int
funcgraph_exit_handler(struct trace_seq *s, struct pevent_record *record,
		       struct event_format *event, void *context)
{
	unsigned long long tid;
	unsigned long long depth;
	unsigned long long addr;
	unsigned long long start;
	unsigned long long end;

	if (pevent_get_any_field_val(s, event, "common_pid", record, &tid, 1))
		return -1;

	if (pevent_get_any_field_val(s, event, "depth", record, &depth, 1))
		return -1;

	if (pevent_get_any_field_val(s, event, "func", record, &addr, 1))
		return -1;

	if (pevent_get_any_field_val(s, event, "calltime", record, &start, 1))
		return -1;

	if (pevent_get_any_field_val(s, event, "rettime", record, &end, 1))
		return -1;

	trace_rstack.tid = tid;
	trace_rstack.depth = depth;
	trace_rstack.child_ip = addr;
	/*
	 * It seems that 'mono' clock is applied only to record->ts,
	 * so convert start and end time to correlated to record->ts.
	 */
	trace_rstack.start_time = record->ts - end + start ;
	trace_rstack.end_time = record->ts;

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

	memcpy(&kernel->rstacks[cpu], &trace_rstack, sizeof(trace_rstack));
	kernel->rstack_valid[cpu] = true;

	kbuffer_next_event(kernel->kbufs[cpu], NULL);

	return 0;
}

/**
 * read_kernel_stack - peek next kernel ftrace data
 * @kernel - kernel ftrace handle
 * @rstack - ftrace return stack
 *
 * This function returns next return stack (based on timestamp)
 * from data files.
 */
int read_kernel_stack(struct ftrace_kernel *kernel,
		      struct mcount_ret_stack *rstack)
{
	int i;
	int first_cpu = -1;
	uint64_t first_timestamp = 0;
	struct mcount_ret_stack *first_rstack = NULL;

	for (i = 0; i < kernel->nr_cpus; i++) {
		uint64_t timestamp;

		if (kernel->rstack_done[i])
			continue;

		if (!kernel->rstack_valid[i]) {
			read_kernel_cpu_data(kernel, i);
			if (!kernel->rstack_valid[i])
				continue;
		}

		timestamp = kernel->rstacks[i].end_time ?: kernel->rstacks[i].start_time;
		if (!first_rstack || first_timestamp > timestamp) {
			first_rstack = &kernel->rstacks[i];
			first_timestamp = timestamp;
			first_cpu = i;
		}
	}

	if (first_rstack == NULL) {
		pr_dbg("no more kernel data\n");
		return -1;
	}

	memcpy(rstack, first_rstack, sizeof(*rstack));

	return first_cpu;
}
