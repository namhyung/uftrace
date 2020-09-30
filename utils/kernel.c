/*
 * Linux kernel ftrace support code.
 *
 * Copyright (c) 2015-2018  LG Electronics,  Namhyung Kim <namhyung@gmail.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <inttypes.h>
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
#include "utils/kernel.h"
#include "libtraceevent/kbuffer.h"
#include "libtraceevent/event-parse.h"

#define TRACING_DIR  "/sys/kernel/debug/tracing"

static bool kernel_tracing_enabled;

/* tree of executed kernel functions */
static struct rb_root kfunc_tree = RB_ROOT;

static int prepare_kbuffer(struct uftrace_kernel_reader *kernel, int cpu);

static int
funcgraph_entry_handler(struct trace_seq *s, struct pevent_record *record,
			struct event_format *event, void *context);
static int
funcgraph_exit_handler(struct trace_seq *s, struct pevent_record *record,
		       struct event_format *event, void *context);
static int
generic_event_handler(struct trace_seq *s, struct pevent_record *record,
		      struct event_format *event, void *context);

static int save_kernel_files(struct uftrace_kernel_writer *kernel);
static int load_kernel_files(struct uftrace_kernel_reader *kernel);

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

static int open_tracing_file(const char *name, bool append)
{
	char *file;
	int fd;
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
	if (fd < 0)
		pr_dbg("cannot open tracing file: %s: %m\n", name);

	put_tracing_file(file);
	return fd;
}

static int __write_tracing_file(int fd, const char *name, const char *val,
				bool append, bool correct_sys_prefix)
{
	int ret = -1;
	ssize_t size = strlen(val);

	if (correct_sys_prefix) {
		char *newval = (char *)val;

		if (!strncmp(val, "sys_", 4))
			newval[0] = newval[2] = 'S';
		else if (!strncmp(val, "compat_sys_", 11))
			newval[7] = newval[9] = 'S';
		else
			correct_sys_prefix = false;
	}

	pr_dbg2("%s '%s' to tracing/%s\n", append ? "appending" : "writing",
	       val, name);

	if (write(fd, val, size) == size)
		ret = 0;

	if (correct_sys_prefix) {
		char *newval = (char *)val;

		if (!strncmp(val, "SyS_", 4))
			newval[0] = newval[2] = 's';
		else if (!strncmp(val, "compat_SyS_", 11))
			newval[7] = newval[9] = 's';

		/* write a whitespace to distinguish the previous pattern */
		if (write(fd, " ", 1) < 0)
			ret = -1;

		pr_dbg2("%s '%s' to tracing/%s\n", append ? "appending" : "writing",
			val, name);

		if (write(fd, val, size) == size)
			ret = 0;
	}

	if (ret < 0)
		pr_dbg("write '%s' to tracing/%s failed: %m\n", val, name);

	return ret;
}

static int write_tracing_file(const char *name, const char *val)
{
	int ret;
	int fd = open_tracing_file(name, false);

	if (fd < 0)
		return -1;

	ret = __write_tracing_file(fd, name, val, false, false);

	close(fd);
	return ret;
}

static int append_tracing_file(const char *name, const char *val)
{
	int ret;
	int fd = open_tracing_file(name, true);

	if (fd < 0)
		return -1;

	ret = __write_tracing_file(fd, name, val, true, false);

	close(fd);
	return ret;
}

static int set_tracing_pid(int pid)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d", pid);
	if (append_tracing_file("set_ftrace_pid", buf) < 0)
		return -1;

	/* ignore error on old kernel */
	append_tracing_file("set_event_pid", buf);
	return 0;
}

static int set_tracing_clock(void)
{
	return write_tracing_file("trace_clock", "mono");
}

struct kfilter {
	struct list_head list;
	char name[];
};

static int set_filter_file(const char *filter_file, struct list_head *filters)
{
	struct kfilter *pos, *tmp;
	int ret = -1;
	int fd;

	fd = open_tracing_file(filter_file, true);
	if (fd < 0)
		return -1;

	list_for_each_entry_safe(pos, tmp, filters, list) {
		/*
		 * it might fail with non-existing functions added by
		 * add_single_filter() or skip_kernel_functions().
		 */
		__write_tracing_file(fd, filter_file, pos->name, true, true);

		list_del(&pos->list);
		free(pos);

		/* separate filters by space */
		if (write(fd, " ", 1) != 1)
			pr_dbg2("writing filter file failed, but ignoring...\n");
	}
	ret = 0;

	close(fd);
	return ret;
}

static int set_tracing_filter(struct uftrace_kernel_writer *kernel)
{
	if (set_filter_file("set_graph_function", &kernel->filters) < 0)
		return -1;

	/* ignore error on old kernel */
	set_filter_file("set_graph_notrace", &kernel->notrace);

	if (set_filter_file("set_ftrace_filter", &kernel->patches) < 0)
		return -1;

	if (set_filter_file("set_ftrace_notrace", &kernel->nopatch) < 0)
		return -1;

	return 0;
}

static int set_tracing_depth(struct uftrace_kernel_writer *kernel)
{
	int ret = 0;
	char buf[32];

	snprintf(buf, sizeof(buf), "%d", kernel->depth);
	ret = write_tracing_file("max_graph_depth", buf);

	return ret;
}

static int set_tracing_bufsize(struct uftrace_kernel_writer *kernel)
{
	int ret = 0;
	char buf[32];

	if (kernel->bufsize) {
		snprintf(buf, sizeof(buf), "%lu", kernel->bufsize >> 10);
		ret = write_tracing_file("buffer_size_kb", buf);
	}
	return ret;
}

/* check whether the kernel supports pid filter inheritance */
bool check_kernel_pid_filter(void)
{
	bool ret = true;
	char *filename = get_tracing_file("options/function-fork");

	if (!access(filename, F_OK))
		ret = false;

	put_tracing_file(filename);
	return ret;
}

static int set_tracing_options(struct uftrace_kernel_writer *kernel)
{
	/* old kernels don't have the options, ignore errors */
	if (!write_tracing_file("options/function-fork", "1"))
		write_tracing_file("options/event-fork", "1");

	return 0;
}

static void add_single_filter(struct list_head *head, char *name)
{
	struct kfilter *kfilter;

	kfilter = xmalloc(sizeof(*kfilter) + strlen(name) + 1);
	strcpy(kfilter->name, name);
	list_add(&kfilter->list, head);
}

static void add_pattern_filter(struct list_head *head,
			       struct uftrace_pattern *patt)
{
	char *filename;
	FILE *fp;
	char buf[1024];

	filename = get_tracing_file("available_filter_functions");
	fp = fopen(filename, "r");
	if (fp == NULL)
		pr_err("failed to open 'tracing/available_filter_functions' file");

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/* remove module name part */
		char *pos = strchr(buf, '[');
		size_t len;

		if (pos)
			*pos = '\0';

		/* remove trailing whitespace */
		len = strlen(buf);
		if (isspace(buf[len - 1]))
			buf[len - 1] = '\0';

		if (match_filter_pattern(patt, buf))
			add_single_filter(head, buf);
	}

	fclose(fp);
	put_tracing_file(filename);
}

static void build_kernel_filter(struct uftrace_kernel_writer *kernel,
				char *filter_str,
				enum uftrace_pattern_type ptype,
				struct list_head *filters,
				struct list_head *notrace)
{
	struct list_head *head;
	struct strv strv = STRV_INIT;
	char *pos, *name;
	int j;

	if (filter_str == NULL)
		return;

	strv_split(&strv, filter_str, ";");

	strv_for_each(&strv, name, j) {
		struct uftrace_pattern patt;

		pos = has_kernel_filter(name);
		if (pos == NULL)
			continue;
		*pos = '\0';

		if (name[0] == '!') {
			head = notrace;
			name++;
		}
		else
			head = filters;

		init_filter_pattern(ptype, &patt, name);

		if (patt.type == PATT_SIMPLE)
			add_single_filter(head, name);
		else
			add_pattern_filter(head, &patt);

		free_filter_pattern(&patt);
	}
	strv_free(&strv);
}

struct kevent {
	struct list_head list;
	char name[];
};

static int set_tracing_event(struct uftrace_kernel_writer *kernel)
{
	struct kevent *pos, *tmp;

	list_for_each_entry_safe(pos, tmp, &kernel->events, list) {
		if (append_tracing_file("set_event", pos->name) < 0)
			return -1;

		list_del(&pos->list);
		free(pos);
	}

	return 0;
}

static void add_single_event(struct list_head *events, char *name)
{
	struct kevent *kevent;

	kevent = xmalloc(sizeof(*kevent) + strlen(name) + 1);
	strcpy(kevent->name, name);
	list_add_tail(&kevent->list, events);
}

static void add_pattern_event(struct list_head *events,
			      struct uftrace_pattern *patt)
{
	char *filename;
	FILE *fp;
	char buf[1024];

	filename = get_tracing_file("available_events");
	fp = fopen(filename, "r");
	if (fp == NULL)
		pr_err("failed to open 'tracing/available_event' file");

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/* it's ok to have a trailing '\n' */
		if (match_filter_pattern(patt, buf))
			add_single_event(events, buf);
	}

	fclose(fp);
	put_tracing_file(filename);
}

static void build_kernel_event(struct uftrace_kernel_writer *kernel,
			       char *event_str, enum uftrace_pattern_type ptype,
			       struct list_head *events)
{
	struct strv strv = STRV_INIT;
	char *pos, *name;
	int j;

	if (event_str == NULL)
		return;

	strv_split(&strv, event_str, ";");

	strv_for_each(&strv, name, j) {
		struct uftrace_pattern patt;

		pos = has_kernel_filter(name);
		if (pos == NULL)
			continue;
		*pos = '\0';

		init_filter_pattern(ptype, &patt, name);

		if (patt.type == PATT_SIMPLE)
			add_single_event(events, name);
		else
			add_pattern_event(events, &patt);

		free_filter_pattern(&patt);
	}
	strv_free(&strv);
}

static int reset_tracing_files(void)
{
	if (write_tracing_file("tracing_on", "1") < 0)
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
	write_tracing_file("set_event_pid", " ");
	write_tracing_file("set_graph_notrace", " ");
	write_tracing_file("options/event-fork", "0");
	write_tracing_file("options/function-fork", "0");

	if (write_tracing_file("set_ftrace_filter", " ") < 0)
		return -1;

	if (write_tracing_file("set_ftrace_notrace", " ") < 0)
		return -1;

	if (write_tracing_file("max_graph_depth", "0") < 0)
		return -1;

	if (write_tracing_file("set_event", " ") < 0)
		return -1;

	/* default kernel buffer size: 16384 * 88 / 1024 = 1408 */
	if (write_tracing_file("buffer_size_kb", "1408") < 0)
		return -1;

	kernel_tracing_enabled = false;
	return 0;
}

static int __setup_kernel_tracing(struct uftrace_kernel_writer *kernel)
{
	if (geteuid() != 0)
		return -EPERM;

	if (reset_tracing_files() < 0) {
		pr_dbg("failed to reset tracing files\n");
		return -ENOSYS;
	}

	pr_dbg("setting up kernel tracing\n");

	/* disable tracing */
	if (write_tracing_file("tracing_on", "0") < 0)
		return -ENOSYS;

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

	if (set_tracing_event(kernel) < 0)
		goto out;

	if (set_tracing_options(kernel) < 0)
		goto out;

	if (set_tracing_bufsize(kernel) < 0)
		goto out;

	if (write_tracing_file("current_tracer", kernel->tracer) < 0)
		goto out;

	kernel_tracing_enabled = true;
	return 0;

out:
	reset_tracing_files();
	return -EINVAL;
}

static void check_and_add_list(struct uftrace_kernel_writer *kernel,
			       const char *funcs[], size_t funcs_len,
			       struct list_head *list)
{
	unsigned int i;
	struct kfilter *kfilter;

	for (i = 0; i < funcs_len; i++) {
		bool add = true;
		const char *name = funcs[i];
		struct kfilter *pos;

		/* Don't skip it if user particularly want to see them*/
		list_for_each_entry(pos, &kernel->filters, list) {
			if (!strcmp(pos->name, name)) {
				add = false;
				break;
			}
		}

		list_for_each_entry(pos, &kernel->patches, list) {
			if (!strcmp(pos->name, name)) {
				add = false;
				break;
			}
		}

		if (add) {
			kfilter = xmalloc(sizeof(*kfilter) + strlen(name) + 1);
			strcpy(kfilter->name, name);
			list_add_tail(&kfilter->list, list);
		}
	}
}

static void skip_kernel_functions(struct uftrace_kernel_writer *kernel)
{
	const char *skip_funcs[] = {
		/*
		 * Some (old) kernel and architecture doesn't support VDSO
		 * so there will be many sys_clock_gettime() in the output
		 * due to internal call in libmcount.  It'd be better
		 * ignoring them not to confuse users.  I think it does NOT
		 * affect to the output when VDSO is enabled.
		 */
		"sys_clock_gettime",
		/*
		 * Currently kernel tracing seems to wake up uftrace writer
		 * threads too often using the irq_work interrupt.  This
		 * messes up the trace output so it'd be better hiding them.
		 */
		"smp_irq_work_interrupt",
		/* Disable syscall tracing in the kernel */
		"syscall_trace_enter_phase1",
		"syscall_slow_exit_work",
#ifdef __aarch64__
		/*
		 * TTBR is for page table setting and it is needed for security
		 * enhancement against spectre/meltdown attacks.
		 * post_ttbr_update_workaround() is better to be hidden not to
		 * confuse general users unnecessarily.
		 */
		"post_ttbr_update_workaround",
#endif
	};
	const char *skip_patches[] = {
		/* kernel 4.17 changed syscall entry on x86_64 */
		"do_syscall_64",
	};

	check_and_add_list(kernel, skip_funcs, ARRAY_SIZE(skip_funcs),
			   &kernel->notrace);
	check_and_add_list(kernel, skip_patches, ARRAY_SIZE(skip_patches),
			   &kernel->nopatch);
}

/**
 * setup_kernel_tracing - prepare to record kernel ftrace data (binary)
 * @kernel : kernel ftrace handle
 * @opts: option related to kernel tracing
 *
 * This function sets up all necessary data structures and configure
 * kernel ftrace subsystem.
 */
int setup_kernel_tracing(struct uftrace_kernel_writer *kernel, struct opts *opts)
{
	int i, n;
	int ret;

	INIT_LIST_HEAD(&kernel->filters);
	INIT_LIST_HEAD(&kernel->notrace);
	INIT_LIST_HEAD(&kernel->patches);
	INIT_LIST_HEAD(&kernel->nopatch);
	INIT_LIST_HEAD(&kernel->events);

	build_kernel_filter(kernel, opts->filter, opts->patt_type,
			    &kernel->filters, &kernel->notrace);
	build_kernel_filter(kernel, opts->patch, opts->patt_type,
			    &kernel->patches, &kernel->nopatch);
	build_kernel_event(kernel, opts->event, opts->patt_type,
			   &kernel->events);

	if (opts->kernel)
		kernel->tracer = KERNEL_GRAPH_TRACER;
	else
		kernel->tracer = KERNEL_NOP_TRACER;

	/* mark kernel tracing is enabled (for event tracing) */
	opts->kernel = true;

	if (opts->kernel_skip_out)
		skip_kernel_functions(kernel);

	ret = __setup_kernel_tracing(kernel);
	if (ret < 0)
		return ret;

	kernel->nr_cpus = n = sysconf(_SC_NPROCESSORS_CONF);

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
int start_kernel_tracing(struct uftrace_kernel_writer *kernel)
{
	char *trace_file;
	char buf[PATH_MAX];
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

		kernel->fds[i] = open(buf, O_WRONLY | O_TRUNC | O_CREAT, 0644);
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
 * @sock - socket descriptor (for network transfer)
 *
 * This function read trace data for @cpu and save it to file.
 */
int record_kernel_trace_pipe(struct uftrace_kernel_writer *kernel,
			     int cpu, int sock)
{
	char buf[PATH_MAX];
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

	if (n == 0)
		return 0;

	if (sock > 0)
		send_trace_kernel_data(sock, cpu, buf, n);
	else
		write_all(kernel->fds[cpu], buf, n);

	return n;
}

/**
 * record_kernel_tracing - read and save kernel ftrace data (binary)
 * @kernel - kernel ftrace handle
 *
 * This function read every (online) per-cpu trace data in a
 * round-robin fashion and save them to files.
 */
int record_kernel_tracing(struct uftrace_kernel_writer *kernel)
{
	ssize_t bytes = 0;
	ssize_t n;
	int i;

	if (!kernel_tracing_enabled)
		return -1;

	for (i = 0; i < kernel->nr_cpus; i++) {
		n = record_kernel_trace_pipe(kernel, i, -1);
		if (n < 0) {
			pr_warn("record kernel data (cpu %d) failed: %m\n", i);
			return n;
		}
		bytes += n;
	}

	pr_dbg3("kernel ftrace record wrote %zd bytes\n", bytes);
	return bytes;
}

/**
 * stop_kernel_tracing - stop recording kernel ftrace data
 * @kernel - kernel ftrace handle
 *
 * This function signals kernel to stop generating trace data.
 */
int stop_kernel_tracing(struct uftrace_kernel_writer *kernel)
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
int finish_kernel_tracing(struct uftrace_kernel_writer *kernel)
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

	if (kernel_tracing_enabled) {
		save_kernel_files(kernel);
		save_kernel_symbol(kernel->output_dir);
	}

	reset_tracing_files();

	return 0;
}

void list_kernel_events(void)
{
	char *filename;
	FILE *fp;
	char buf[BUFSIZ];

	filename = get_tracing_file("available_events");
	fp = fopen(filename, "r");
	if (fp == NULL) {
		pr_dbg("failed to open 'tracing/avaiable_events");
		return;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL)
		pr_out("[kernel event] %s", buf);

	fclose(fp);
	put_tracing_file(filename);
}

static const char *get_endian_str(void)
{
	if (get_elf_endian() == ELFDATA2LSB)
		return "LE";
	else
		return "BE";
}

static int read_file(char *filename, char *buf, size_t len)
{
	int fd, ret;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -errno;

	ret = read(fd, buf, len);
	close(fd);

	return ret;
}

static int save_kernel_file(FILE *fp, const char *name)
{
	ssize_t len;
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s/%s", TRACING_DIR, name);

	len = read_file(buf, buf, sizeof(buf));
	if (len < 0)
		return -1;

	fprintf(fp, "TRACEFS: %s: %zd\n", name, len);
	fwrite(buf, len, 1, fp);

	return 0;
}

static int save_event_files(struct uftrace_kernel_writer *kernel, FILE *fp)
{
	int ret = -1;
	char buf[PATH_MAX];
	DIR *subsys = NULL;
	DIR *event = NULL;
	struct dirent *sys, *name;

	snprintf(buf, sizeof(buf), "%s/events/enable", TRACING_DIR);

	if (read_file(buf, buf, sizeof(buf)) < 0)
		goto out;

	/* no events enabled: exit */
	if (buf[0] == '0') {
		ret = 0;
		goto out;
	}

	snprintf(buf, sizeof(buf), "%s/events", TRACING_DIR);

	subsys = opendir(buf);
	if (subsys == NULL)
		goto out;

	while ((sys = readdir(subsys)) != NULL) {
		if (sys->d_name[0] == '.' || sys->d_type != DT_DIR)
			continue;

		/* ftrace events are special - skip it */
		if (!strcmp(sys->d_name, "ftrace"))
			continue;

		snprintf(buf, sizeof(buf), "%s/events/%s/enable",
			 TRACING_DIR, sys->d_name);

		if (read_file(buf, buf, sizeof(buf)) < 0)
			goto out;

		/* this subsystem has no events enabled */
		if (buf[0] == '0')
			continue;

		snprintf(buf, sizeof(buf), "%s/events/%s",
			 TRACING_DIR, sys->d_name);

		event = opendir(buf);
		if (event == NULL)
			goto out;

		while ((name = readdir(event)) != NULL) {
			if (name->d_name[0] == '.' || name->d_type != DT_DIR)
				continue;

			snprintf(buf, sizeof(buf), "%s/events/%s/%s/enable",
				 TRACING_DIR, sys->d_name, name->d_name);

			if (read_file(buf, buf, sizeof(buf)) < 0)
				goto out;

			/* this event is not enabled */
			if (buf[0] == '0')
				continue;

			snprintf(buf, sizeof(buf), "events/%s/%s/format",
				 sys->d_name, name->d_name);

			if (save_kernel_file(fp, buf) < 0)
				goto out;
		}
		closedir(event);
		event = NULL;
	}

	ret = 0;

out:
	if (event)
		closedir(event);
	if (subsys)
		closedir(subsys);
	return ret;
}

static int save_kernel_files(struct uftrace_kernel_writer *kernel)
{
	char *path = NULL;
	FILE *fp;
	int ret = -1;

	xasprintf(&path, "%s/kernel_header", kernel->output_dir);

	fp = fopen(path, "w");
	if (fp == NULL)
		pr_err("cannot write kernel header");

	fprintf(fp, "PAGE_SIZE: %d\n", getpagesize());
	fprintf(fp, "LONG_SIZE: %zd\n", sizeof(long));
	fprintf(fp, "ENDIAN: %s\n", get_endian_str());

	if (save_kernel_file(fp, "events/header_page") < 0)
		goto out;

	if (save_kernel_file(fp, "events/ftrace/funcgraph_entry/format") < 0)
		goto out;

	if (save_kernel_file(fp, "events/ftrace/funcgraph_exit/format") < 0)
		goto out;

	if (save_event_files(kernel, fp) < 0)
		goto out;

	ret = 0;

out:
	fclose(fp);
	free(path);
	return ret;
}

/* provided for backward compatibility */
static int load_current_kernel(struct uftrace_kernel_reader *kernel)
{
	int fd;
	size_t len;
	char buf[PATH_MAX];
	bool is_big_endian = !strcmp(get_endian_str(), "BE");
	struct pevent *pevent = kernel->pevent;

	pevent_set_long_size(pevent, sizeof(long));
	pevent_set_page_size(pevent, getpagesize());
	pevent_set_file_bigendian(pevent, is_big_endian);
	pevent_set_host_bigendian(pevent, is_big_endian);

	fd = open(TRACING_DIR"/events/header_page", O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, sizeof(buf));
	pevent_parse_header_page(pevent, buf, len, sizeof(long));
	close(fd);

	fd = open(TRACING_DIR"/events/ftrace/funcgraph_entry/format", O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, sizeof(buf));
	pevent_parse_event(pevent, buf, len, "ftrace");
	close(fd);

	fd = open(TRACING_DIR"/events/ftrace/funcgraph_exit/format", O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, sizeof(buf));
	pevent_parse_event(pevent, buf, len, "ftrace");
	close(fd);

	return 0;
}

static int load_kernel_files(struct uftrace_kernel_reader *kernel)
{
	char *path = NULL;
	FILE *fp;
	char buf[PATH_MAX];
	struct pevent *pevent = kernel->pevent;
	int ret = 0;

	xasprintf(&path, "%s/kernel_header", kernel->dirname);

	fp = fopen(path, "r");
	if (fp == NULL)  /* old data doesn't have the kernel header */
		return load_current_kernel(kernel);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char name[128];
		size_t len = 0;

		if (strncmp(buf, "TRACEFS:", 8) != 0) {
			char val[32];

			sscanf(buf, "%[^:]: %s\n", name, val);

			if (!strcmp(name, "PAGE_SIZE")) {
				ret = strtol(val, NULL, 0);
				pevent_set_page_size(pevent, ret);
			}
			else if (!strcmp(name, "LONG_SIZE")) {
				ret = strtol(val, NULL, 0);
				pevent_set_long_size(pevent, ret);
			}
			else if (!strcmp(name, "ENDIAN")) {
				ret = (strcmp(val, "BE") == 0);
				pevent_set_file_bigendian(pevent, ret);

				ret = (strcmp(get_endian_str(), "BE") == 0);
				pevent_set_host_bigendian(pevent, ret);
			}
			continue;
		}

		if (sscanf(buf, "TRACEFS: %[^:]: %zd\n", name, &len) != 2) {
			ret = -1;
			break;
		}

		if (fread(buf, 1, len, fp) != len) {
			ret = -1;
			break;
		}

		if (!strcmp(name, "events/header_page")) {
			pevent_parse_header_page(pevent, buf, len,
						 pevent_get_long_size(pevent));
		}
		else if (!strncmp(name, "events/ftrace/", 14)) {
			ret = pevent_parse_event(pevent, buf, len, "ftrace");
			if (ret != 0) {
				pevent_strerror(pevent, ret, buf, len);
				pr_err_ns("%s: %s\n", name, buf);
			}
		}
		else if (!strncmp(name, "events/", 7) &&
			 !strncmp(name + strlen(name) - 7, "/format", 7)) {
			/* extract subsystem and event names */
			char *pos1 = strchr(name + 8, '/');
			char *pos2 = strrchr(name, '/');

			if (pos1 == NULL || pos2 == NULL)
				continue;

			*pos1 = '\0';

			/* add event so that we can skip the record */
			ret = pevent_parse_event(pevent, buf, len, name + 7);
			if (ret != 0) {
				*pos1 = '/';
				pevent_strerror(pevent, ret, buf, len);
				pr_err_ns("%s: %s\n", name, buf);
			}

			*pos2 = '\0';

			pevent_register_event_handler(kernel->pevent, -1,
						      name + 7, pos1 + 1,
						      generic_event_handler,
						      kernel);
		}
		else {
			pr_dbg("unknown data: %s\n", name);
			ret = -1;
			break;
		}
	}

	fclose(fp);
	free(path);
	return ret;
}

static int scandir_filter(const struct dirent *d)
{
	return !strncmp(d->d_name, "kernel-cpu", 10);
}

static int scandir_sort(const struct dirent **a, const struct dirent **b)
{
	return strtol((*a)->d_name + sizeof("kernel-cpu") - 1, NULL, 0)
		- strtol((*b)->d_name + sizeof("kernel-cpu") - 1, NULL, 0);
}

/**
 * setup_kernel_data - prepare to read kernel ftrace data from files
 * @kernel - kernel ftrace handle
 *
 * This function initializes necessary data structures for reading
 * kernel ftrace data files.  It should be called in pair with
 * finish_kernel_data().
 */
int setup_kernel_data(struct uftrace_kernel_reader *kernel)
{
	int i;
	char buf[PATH_MAX];
	enum kbuffer_endian endian = KBUFFER_ENDIAN_LITTLE;
	enum kbuffer_long_size longsize = KBUFFER_LSIZE_8;
	struct dirent **list;

	kernel->pevent = pevent_alloc();
	if (kernel->pevent == NULL)
		return -1;

	trace_seq_init(&kernel->trace_buf);

	kernel->nr_cpus = scandir(kernel->dirname, &list, scandir_filter, scandir_sort);
	if (kernel->nr_cpus <= 0) {
		pr_out("cannot find kernel trace data\n");
		goto out;
	}

	if (load_kernel_files(kernel) < 0) {
		pr_out("cannot read kernel header: %m\n");
		goto out;
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

	if (pevent_is_file_bigendian(kernel->pevent))
		endian = KBUFFER_ENDIAN_BIG;
	if (pevent_get_long_size(kernel->pevent) == 4)
		longsize = KBUFFER_LSIZE_4;
	kernel->pagesize = pevent_get_page_size(kernel->pevent);

	for (i = 0; i < kernel->nr_cpus; i++) {
		struct stat stbuf;

		snprintf(buf, sizeof(buf), "%s/%s",
			 kernel->dirname, list[i]->d_name);
		free(list[i]);

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
		finish_kernel_data(kernel);
		return -1;
	}

	pevent_register_event_handler(kernel->pevent, -1, "ftrace", "funcgraph_entry",
				      funcgraph_entry_handler, kernel);
	pevent_register_event_handler(kernel->pevent, -1, "ftrace", "funcgraph_exit",
				      funcgraph_exit_handler, kernel);
	return 0;

out:
	pevent_free(kernel->pevent);
	kernel->pevent = NULL;
	return -1;
}

/**
 * finish_kernel_data - tear down data structures for kernel ftrace
 * @kernel - kernel ftrace handle
 *
 * This function destroys all data structures created by
 * setup_kernel_data().
 */
int finish_kernel_data(struct uftrace_kernel_reader *kernel)
{
	int i;

	if (kernel == NULL)
		return 0;

	for (i = 0; i < kernel->nr_cpus; i++) {
		close(kernel->fds[i]);

		if (!kernel->rstack_done[i])
			munmap(kernel->mmaps[i], kernel->pagesize);

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

	trace_seq_destroy(&kernel->trace_buf);
	pevent_free(kernel->pevent);
	kernel->pevent = NULL;

	return 0;
}

static int prepare_kbuffer(struct uftrace_kernel_reader *kernel, int cpu)
{
	kernel->mmaps[cpu] = mmap(NULL, kernel->pagesize, PROT_READ, MAP_PRIVATE,
				  kernel->fds[cpu], kernel->offsets[cpu]);
	if (kernel->mmaps[cpu] == MAP_FAILED) {
		pr_dbg("loading kbuffer for cpu %d (fd: %d, offset: %lu, pagesize: %zd) failed\n",
		       cpu, kernel->fds[cpu], kernel->offsets[cpu], kernel->pagesize);
		return -1;
	}

	kbuffer_load_subbuffer(kernel->kbufs[cpu], kernel->mmaps[cpu]);
	kernel->missed_events[cpu] = kbuffer_missed_events(kernel->kbufs[cpu]);

	return 0;
}

static int next_kbuffer_page(struct uftrace_kernel_reader *kernel, int cpu)
{
	munmap(kernel->mmaps[cpu], kernel->pagesize);
	kernel->mmaps[cpu] = NULL;

	kernel->offsets[cpu] += kernel->pagesize;

	if (kernel->offsets[cpu] >= (loff_t)kernel->sizes[cpu]) {
		kernel->rstack_done[cpu] = true;
		return -1;
	}

	return prepare_kbuffer(kernel, cpu);
}

struct uftrace_kfunc {
	struct rb_node	node;
	uint64_t	addr;
};

static void add_kfunc_addr(struct rb_root *root, uint64_t addr)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct uftrace_kfunc *iter, *kfunc;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_kfunc, node);

		if (iter->addr == addr)
			return;

		if (iter->addr > addr)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	kfunc = xmalloc(sizeof(*kfunc));
	kfunc->addr = addr;

	rb_link_node(&kfunc->node, parent, p);
	rb_insert_color(&kfunc->node, root);
}

static bool find_kfunc_addr(struct rb_root *root, uint64_t addr)
{
	struct rb_node *node = root->rb_node;
	struct uftrace_kfunc *iter;

	while (node) {
		iter = rb_entry(node, struct uftrace_kfunc, node);

		if (iter->addr == addr)
			return true;

		if (iter->addr > addr)
			node = node->rb_left;
		else
			node = node->rb_right;
	}
	return false;
}

static int
funcgraph_entry_handler(struct trace_seq *s, struct pevent_record *record,
			struct event_format *event, void *context)
{
	struct uftrace_kernel_reader *kernel = context;
	unsigned long long depth;
	unsigned long long addr;

	if (pevent_get_any_field_val(s, event, "depth", record, &depth, 1))
		return -1;

	if (pevent_get_any_field_val(s, event, "func", record, &addr, 1))
		return -1;

	kernel->trace_rec.type  = UFTRACE_ENTRY;
	kernel->trace_rec.time  = record->ts;
	kernel->trace_rec.addr  = addr;
	kernel->trace_rec.depth = depth;
	kernel->trace_rec.more  = 0;

	return 0;
}

static int
funcgraph_exit_handler(struct trace_seq *s, struct pevent_record *record,
		       struct event_format *event, void *context)
{
	struct uftrace_kernel_reader *kernel = context;
	unsigned long long depth;
	unsigned long long addr;

	if (pevent_get_any_field_val(s, event, "depth", record, &depth, 1))
		return -1;

	if (pevent_get_any_field_val(s, event, "func", record, &addr, 1))
		return -1;

	kernel->trace_rec.type  = UFTRACE_EXIT;
	kernel->trace_rec.time  = record->ts;
	kernel->trace_rec.addr  = addr;
	kernel->trace_rec.depth = depth;
	kernel->trace_rec.more  = 0;

	return 0;
}

static int
generic_event_handler(struct trace_seq *s, struct pevent_record *record,
		      struct event_format *event, void *context)
{
	struct uftrace_kernel_reader *kernel = context;

	kernel->trace_rec.type  = UFTRACE_EVENT;
	kernel->trace_rec.time  = record->ts;
	kernel->trace_rec.addr  = event->id;
	kernel->trace_rec.depth = 0;
	kernel->trace_rec.more  = 1;

	/* for trace_seq to be filled according to its print_fmt */
	return 1;
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
int read_kernel_cpu_data(struct uftrace_kernel_reader *kernel, int cpu)
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

	trace_seq_reset(&kernel->trace_buf);
	type = pevent_data_type(kernel->pevent, &record);
	if (type == 0)
		return -1; // padding

	event = pevent_find_event(kernel->pevent, type);
	if (event == NULL) {
		pr_dbg("cannot find event for type: %d\n", type);
		return -1;
	}

	/* this will call event handlers */
	pevent_event_info(&kernel->trace_buf, event, &record);

	kernel->tids[cpu] = pevent_data_pid(kernel->pevent, &record);
	memcpy(&kernel->rstacks[cpu], &kernel->trace_rec, sizeof(kernel->trace_rec));
	kernel->rstack_valid[cpu] = true;

	/*
	 * some event might be saved for unrelated task.  In this case
	 * pid for our child would be in a different field (not common_pid).
	 */
	if (kernel->trace_rec.type == UFTRACE_EVENT &&
	    get_task_handle(kernel->handle, kernel->tids[cpu]) == NULL) {
		unsigned long long tid;

		/* for sched_switch event */
		if (pevent_get_field_val(NULL, event, "next_pid",
					 &record, &tid, 0) == 0 &&
		    get_task_handle(kernel->handle, tid) != NULL)
			kernel->tids[cpu] = tid;
		/* for sched_wakeup event (or others) */
		else if (pevent_get_field_val(NULL, event, "pid",
					 &record, &tid, 0) == 0 &&
		    get_task_handle(kernel->handle, tid) != NULL)
			kernel->tids[cpu] = tid;
	}

	kbuffer_next_event(kernel->kbufs[cpu], NULL);

	return 0;
}

static int read_kernel_cpu(struct uftrace_data *handle, int cpu)
{
	struct uftrace_kernel_reader *kernel = handle->kernel;
	struct uftrace_rstack_list *rstack_list = &kernel->rstack_list[cpu];
	struct uftrace_record *curr;
	int tid, prev_tid = -1;

	if (rstack_list->count)
		goto out;

	/*
	 * read task (kernel) stack until it found an entry that exceeds
	 * the given time filter (-t option).
	 */
	while (read_kernel_cpu_data(kernel, cpu) == 0) {
		struct uftrace_session *sess = handle->sessions.first;
		struct uftrace_task_reader *task;
		struct uftrace_trigger tr = {};
		uint64_t real_addr;
		uint64_t time_filter = handle->time_filter;

		curr = &kernel->rstacks[cpu];

		/* prevent ustack from invalid access */
		kernel->rstack_valid[cpu] = false;

		tid = kernel->tids[cpu];
		task = get_task_handle(handle, tid);
		if (task == NULL)
			continue;

		if (!check_time_range(&handle->time_range, curr->time))
			continue;

		if (prev_tid == -1)
			prev_tid = tid;

		if (task->filter.time)
			time_filter = task->filter.time->threshold;

		/* filter match needs full (64-bit) address */
		real_addr = get_kernel_address(&sess->symtabs, curr->addr);
		/*
		 * it might set TRACE trigger, which shows
		 * function even if it's less than the time filter.
		 */
		uftrace_match_filter(real_addr, &sess->filters, &tr);

		if (curr->type == UFTRACE_ENTRY) {
			/* it needs to wait until matching exit found */
			add_to_rstack_list(rstack_list, curr, NULL);

			add_kfunc_addr(&kfunc_tree, real_addr);

			if (tr.flags & TRIGGER_FL_TIME_FILTER) {
				struct time_filter_stack *tfs;

				tfs = xmalloc(sizeof(*tfs));
				tfs->next = task->filter.time;
				tfs->depth = curr->depth;
				tfs->context = FSTACK_CTX_KERNEL;
				tfs->threshold = tr.time;

				task->filter.time = tfs;
			}

			/* XXX: handle scheduled task properly */
			if (tid != prev_tid)
				break;
		}
		else if (curr->type == UFTRACE_EXIT) {
			struct uftrace_rstack_list_node *last;
			uint64_t delta;
			int count;
			bool filtered = false;

			if (!find_kfunc_addr(&kfunc_tree, real_addr))
				continue;

			if (task->filter.time) {
				struct time_filter_stack *tfs;

				tfs = task->filter.time;
				if (tfs->depth == curr->depth &&
				    tfs->context == FSTACK_CTX_KERNEL) {
					/* discard stale filter */
					task->filter.time = tfs->next;
					free(tfs);
				}
			}

			if (rstack_list->count == 0 || tr.flags & TRIGGER_FL_TRACE) {
				/*
				 * it's already exceeded time filter or
				 * it might set TRACE trigger, just return.
				 */
				add_to_rstack_list(rstack_list, curr, NULL);
				break;
			}

			last = list_last_entry(&rstack_list->read,
					       typeof(*last), list);
			count = 1;

			/* skip EVENT records, if any*/
			while (last->rstack.type == UFTRACE_EVENT) {
				last = list_prev_entry(last, list);
				count++;
			}

			delta = curr->time - last->rstack.time;
			if (delta < time_filter)
				filtered = true;

			if (handle->caller_filter)
				filtered |= !(tr.flags & TRIGGER_FL_CALLER);

			if (filtered) {
				/* also delete matching entry (at the last) */
				while (count--)
					delete_last_rstack_list(rstack_list);

				/* XXX: handle scheduled task properly */
				if (tid != prev_tid)
					break;
			}
			else {
				/* found! process all existing rstacks in the list */
				add_to_rstack_list(rstack_list, curr, NULL);
				break;
			}
		}
		else if (curr->type == UFTRACE_EVENT) {
			struct fstack_arguments arg = {
				.data = kernel->trace_buf.buffer,
				.len  = kernel->trace_buf.len,
			};

			add_to_rstack_list(rstack_list, curr, &arg);

			/* XXX: handle scheduled task properly */
			if (tid != prev_tid)
				break;
		}
		else {
			/* TODO: handle LOST properly */
			add_to_rstack_list(rstack_list, curr, NULL);
			break;
		}

		prev_tid = tid;
	}

	if (rstack_list->count == 0) {
		if (!kernel->rstack_done[cpu]) {
			pr_dbg("XXX: still has unknown tracepoint?\n");
			kernel->rstack_done[cpu] = true;
		}

		return -1;
	}

out:
	kernel->rstack_valid[cpu] = true;
	curr = get_first_rstack_list(rstack_list);
	memcpy(&kernel->rstacks[cpu], curr, sizeof(*curr));
	return 0;
}

/**
 * read_kernel_event - read current kernel event of specific cpu
 * @handle - uftrace file handle
 * @cpu    - cpu number
 * @psize  - pointer to size
 *
 * This function returns current tracepoint event data in trace_seq.
 * The size of the event data will be saved in @size.  It returns a
 * pointer to event data if succeeded, NULL if current record is not a
 * tracepoint.
 */
void * read_kernel_event(struct uftrace_kernel_reader *kernel, int cpu, int *psize)
{
	struct uftrace_record *rstack = &kernel->rstacks[cpu];

	if (!rstack->more)
		return NULL;

	*psize = kernel->trace_buf.len;
	return kernel->trace_buf.buffer;
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
int read_kernel_stack(struct uftrace_data *handle,
		      struct uftrace_task_reader **taskp)
{
	int i;
	int first_cpu = -1;
	int first_tid = -1;
	uint64_t first_timestamp = 0;
	struct uftrace_kernel_reader *kernel = handle->kernel;
	struct uftrace_record *first_rstack;

retry:
	first_rstack = NULL;
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
	if (*taskp == NULL || (*taskp)->fp == NULL) {
		/* force re-read on that cpu */
		kernel->rstack_valid[first_cpu] = false;

		if (first_rstack->more) {
			struct uftrace_rstack_list_node *node;

			node = list_first_entry(&kernel->rstack_list[first_cpu].read,
						typeof(*node), list);
			free(node->args.data);
			node->args.data = NULL;
		}

		consume_first_rstack_list(&kernel->rstack_list[first_cpu]);
		goto retry;
	}

	memcpy(&(*taskp)->kstack, first_rstack, sizeof(*first_rstack));
	kernel->last_read_cpu = first_cpu;

	return first_cpu;
}

struct uftrace_record * get_kernel_record(struct uftrace_kernel_reader *kernel,
					  struct uftrace_task_reader *task,
					  int cpu)
{
	static struct uftrace_record lost_record;

	if (!kernel->missed_events[cpu])
		return &task->kstack;

	/* convert to ftrace_rstack */
	lost_record.time = 0;
	lost_record.type = UFTRACE_LOST;
	lost_record.addr = kernel->missed_events[cpu];
	lost_record.depth = task->kstack.depth;
	lost_record.magic = RECORD_MAGIC;
	lost_record.more = 0;

	/*
	 * NOTE: do not consume the kstack since we didn't
	 * read the first record yet.  Next read_kernel_stack()
	 * will return the first record.
	 */
	return &lost_record;
}

#ifdef UNIT_TEST

#include <sys/stat.h>

#define NUM_CPU     2
#define NUM_TASK    2
#define NUM_RECORD  4
#define NUM_EVENT   2

/* event id */
#define FUNCGRAPH_ENTRY  11
#define FUNCGRAPH_EXIT   10
#define TEST_EXAMPLE     100

static struct uftrace_data test_handle;
static struct uftrace_session test_sess;
static void kernel_test_finish_file(void);
static void kernel_test_finish_handle(void);

/* NOTE: assume 64-bit little-endian systems */
static const char test_kernel_header[] =
"PAGE_SIZE: 4096\n"
"LONG_SIZE: 8\n"
"ENDIAN: LE\n"
"TRACEFS: events/header_page: 205\n"
"\tfield: u64 timestamp;\toffset:0;\tsize:8;\tsigned:0;\n"
"\tfield: local_t commit;\toffset:8;\tsize:8;\tsigned:1;\n"
"\tfield: int overwrite;\toffset:8;\tsize:1;\tsigned:1;\n"
"\tfield: char data;\toffset:16;\tsize:4080;\tsigned:1;\n"
"TRACEFS: events/ftrace/funcgraph_entry/format: 438\n"
"name: funcgraph_entry\n"
"ID: 11\n"
"format:\n"
"\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n"
"\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n"
"\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n"
"\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n"
"\n"
"\tfield:unsigned long func;\toffset:8;\tsize:8;\tsigned:0;\n"
"\tfield:int depth;\toffset:16;\tsize:4;\tsigned:1;\n"
"\n"
"print fmt: \"--> %lx (%d)\", REC->func, REC->depth\n"
"TRACEFS: events/ftrace/funcgraph_exit/format: 700\n"
"name: funcgraph_exit\n"
"ID: 10\n"
"format:\n"
"\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n"
"\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n"
"\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n"
"\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n"
"\n"
"\tfield:unsigned long func;\toffset:8;\tsize:8;\tsigned:0;\n"
"\tfield:unsigned long long calltime;\toffset:24;\tsize:8;\tsigned:0;\n"
"\tfield:unsigned long long rettime;\toffset:32;\tsize:8;\tsigned:0;\n"
"\tfield:unsigned long overrun;	offset:16;\tsize:8;\tsigned:0;\n"
"\tfield:int depth;\toffset:40;\tsize:4;\tsigned:1;\n"
"\n"
"print fmt: \"<-- %lx (%d) (start: %llx  end: %llx) over: %d\", "
"REC->func, REC->depth, REC->calltime, REC->rettime, REC->depth\n";

static const char test_kernel_event[] =
"TRACEFS: events/test/example/format: 419\n"
"name: example\n"
"ID: 100\n"
"format:\n"
"\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n"
"\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n"
"\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n"
"\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n"
"\n"
"\tfield:int foo;\toffset:8;\tsize:4;\tsigned:0;\n"
"\tfield:int bar;\toffset:12;\tsize:4;\tsigned:1;\n"
"\n"
"print fmt: \"foo=%d, bar=0x%x\", REC->foo, REC->bar\n";

struct header_page {
	uint64_t timestamp;
	uint64_t commit;
};

struct type_len_ts {
	uint32_t type_len: 5;
	uint32_t ts: 27;
};

struct funcgraph_entry {
	unsigned short common_type;
	unsigned char  common_flags;
	unsigned char  common_preempt_count;
	int            common_pid;

	uint64_t       func;
	int            depth;
};

struct funcgraph_exit {
	unsigned short common_type;
	unsigned char  common_flags;
	unsigned char  common_preempt_count;
	int            common_pid;

	uint64_t       func;
	uint64_t       calltime;
	uint64_t       rettime;
	uint64_t       overrun;
	int            depth;
};

struct test_example {
	unsigned short common_type;
	unsigned char  common_flags;
	unsigned char  common_preempt_count;
	int            common_pid;

	int            foo;
	int            bar;
};

static int test_tids[NUM_TASK] = { 1234, 5678 };

static struct header_page header = { 0, 4096 };

static struct type_len_ts test_len_ts[NUM_CPU][NUM_RECORD] = {
	{
		{ sizeof(struct funcgraph_entry) / 4, 100 },
		{ sizeof(struct funcgraph_entry) / 4, 100 },
		{ sizeof(struct funcgraph_exit)  / 4, 100 },
		{ sizeof(struct funcgraph_exit)  / 4, 100 },
	},
	{
		{ sizeof(struct funcgraph_entry) / 4, 150 },
		{ sizeof(struct funcgraph_exit)  / 4, 100 },
		{ sizeof(struct funcgraph_entry) / 4, 100 },
		{ sizeof(struct funcgraph_exit)  / 4, 100 },
	}
};

/* NOTE: it's actually a mix of funcgraph_entry and funcgraph_exit */
static struct funcgraph_exit test_record[NUM_CPU][NUM_RECORD] = {
	{
		/* NOTE: entry->depth might not set on big-endian? */
		{ FUNCGRAPH_ENTRY, 0, 0, 1234, 0xffff1000, 0 },
		{ FUNCGRAPH_ENTRY, 0, 0, 1234, 0xffff2000, 1 },
		{ FUNCGRAPH_EXIT,  0, 0, 1234, 0xffff2000, 200, 300, 0, 1 },
		{ FUNCGRAPH_EXIT,  0, 0, 1234, 0xffff1000, 100, 400, 0, 0 },
	},
	{
		{ FUNCGRAPH_ENTRY, 0, 0, 1234, 0xffff3000, 0 },
		{ FUNCGRAPH_EXIT,  0, 0, 1234, 0xffff3000, 150, 250, 0, 0 },
		{ FUNCGRAPH_ENTRY, 0, 0, 5678, 0xffff4000, 1 },
		{ FUNCGRAPH_EXIT,  0, 0, 5678, 0xffff4000, 350, 450, 0, 1 },
	}
};

static struct type_len_ts test_event_len_ts[NUM_CPU][NUM_EVENT] = {
	{
		{ sizeof(struct test_example) / 4, 1000 },
		{ sizeof(struct test_example) / 4, 1000 },
	},
	{
		{ sizeof(struct test_example) / 4, 1500 },
		{ sizeof(struct test_example) / 4, 1000 },
	}
};

static struct test_example test_event[NUM_CPU][NUM_EVENT] = {
	{
		{ TEST_EXAMPLE, 0, 0, 1234, 1024, 1024 },
		{ TEST_EXAMPLE, 0, 0, 1234, 2048, 2048 },
	},
	{
		{ TEST_EXAMPLE, 0, 0, 5678, 100, 256 },
		{ TEST_EXAMPLE, 0, 0, 5678, 200, 512 },
	}
};

/* NOTE: we used struct funcgraph_exit even for UFTRACE_ENTRY */
static int record_size(struct funcgraph_exit *rec)
{
	return rec->common_type == FUNCGRAPH_ENTRY ?
		sizeof(struct funcgraph_entry) : sizeof(struct funcgraph_exit);
}

static int record_type(struct funcgraph_exit *rec)
{
	return rec->common_type == FUNCGRAPH_ENTRY ? UFTRACE_ENTRY : UFTRACE_EXIT;
}

static int record_depth(struct funcgraph_exit *rec)
{
	return rec->common_type == FUNCGRAPH_ENTRY ? rec->calltime : rec->depth;
}

/* fwrite with checking return value */
#define cwrite(bf)							\
	if (fwrite_all(&bf, sizeof(bf), fp) < 0) pr_dbg("write failed: %s\n", #bf)

#define cwrite2(bf, sz)							\
	if (fwrite_all(bf, sz, fp) < 0) pr_dbg("write failed: %s\n", #bf)

static int kernel_test_setup_file(struct uftrace_kernel_reader *kernel, bool event)
{
	int cpu, i;
	FILE *fp;
	char *filename;

	kernel->dirname = "kernel.dir";
	kernel->nr_cpus = NUM_CPU;

	if (mkdir(kernel->dirname, 0755) < 0) {
		if (errno != EEXIST) {
			pr_dbg("cannot create temp dir: %m\n");
			return -1;
		}
	}

	if (asprintf(&filename, "%s/kernel_header", kernel->dirname) < 0) {
		pr_dbg("cannot alloc filename: %s/kernel_header",
		       kernel->dirname);
		return -1;
	}

	fp = fopen(filename, "w");
	if (fp == NULL) {
		pr_dbg("file open failed: %m\n");
		free(filename);
		return -1;
	}

	cwrite2(test_kernel_header, strlen(test_kernel_header));
	if (event)
		cwrite2(test_kernel_event, strlen(test_kernel_event));

	free(filename);
	fclose(fp);

	for (cpu = 0; cpu < kernel->nr_cpus; cpu++) {
		if (asprintf(&filename, "%s/kernel-cpu%d.dat",
			     kernel->dirname, cpu) < 0) {
			pr_dbg("cannot alloc filename: %s/kernel-cpu%d.dat",
			       kernel->dirname, cpu);
			return -1;
		}

		fp = fopen(filename, "w");
		if (fp == NULL) {
			pr_dbg("file open failed: %m\n");
			free(filename);
			return -1;
		}

		cwrite(header);

		if (event) {
			for (i = 0; i < NUM_EVENT; i++) {
				cwrite(test_event_len_ts[cpu][i]);
				cwrite(test_event[cpu][i]);
			}
		}
		else {
			for (i = 0; i < NUM_RECORD; i++) {
				cwrite(test_len_ts[cpu][i]);
				cwrite2(&test_record[cpu][i],
					record_size(&test_record[cpu][i]));
			}
		}

		/* pad to page size */
		fallocate(fileno(fp), 0, 0, 4096);

		free(filename);
		fclose(fp);
	}

	kernel->handle = &test_handle;
	test_handle.kernel = kernel;
	atexit(kernel_test_finish_file);

	return setup_kernel_data(kernel);
}

#undef cwrite
#undef cwrite2

static int kernel_test_setup_handle(struct uftrace_kernel_reader *kernel,
				    struct uftrace_data *handle)
{
	int i;

	handle->nr_tasks = NUM_TASK;
	handle->tasks = xcalloc(sizeof(*handle->tasks), NUM_TASK);

	handle->time_range.start = handle->time_range.stop = 0;
	handle->time_filter = 0;

	for (i = 0; i < NUM_TASK; i++) {
		handle->tasks[i].tid = test_tids[i];
		handle->tasks[i].fp  = (void *)1;  /* prevent retry */
	}

	test_sess.symtabs.kernel_base = 0xffff0000UL;
	handle->sessions.first = &test_sess;

	atexit(kernel_test_finish_handle);

	return 0;
}

static void kernel_test_finish_file(void)
{
	int cpu;
	char *filename;
	struct uftrace_kernel_reader *kernel = test_handle.kernel;

	if (kernel == NULL)
		return;

	finish_kernel_data(kernel);

	for (cpu = 0; cpu < kernel->nr_cpus; cpu++) {
		if (asprintf(&filename, "%s/kernel-cpu%d.dat",
			     kernel->dirname, cpu) < 0)
			return;

		remove(filename);
		free(filename);
	}

	if (asprintf(&filename, "%s/kernel_header", kernel->dirname) < 0)
		return;

	remove(filename);
	free(filename);

	remove(kernel->dirname);
	kernel->dirname = NULL;

	free(kernel);
	test_handle.kernel = NULL;
}

static void kernel_test_finish_handle(void)
{
	struct uftrace_data *handle = &test_handle;

	free(handle->tasks);
	handle->tasks = NULL;
}

TEST_CASE(kernel_read)
{
	int cpu, i;
	int timestamp[NUM_CPU] = { };
	struct uftrace_data *handle = &test_handle;
	struct uftrace_kernel_reader *kernel = xzalloc(sizeof(*kernel));
	struct uftrace_task_reader *task;

	TEST_EQ(kernel_test_setup_file(kernel, false), 0);
	TEST_EQ(kernel_test_setup_handle(kernel, handle), 0);

	i = 0;
	while ((cpu = read_kernel_stack(handle, &task)) != -1) {
		struct funcgraph_exit *rec = &test_record[cpu][i / 2];
		struct uftrace_record *rstack = &task->kstack;

		timestamp[cpu] += test_len_ts[cpu][i / 2].ts;

		pr_dbg("[%d] read kernel record: type=%d, depth=%d, addr=%"PRIx64"\n",
		       i, rstack->type, rstack->depth, (uint64_t)rstack->addr);
		TEST_EQ((int)rstack->type, record_type(rec));
		TEST_EQ((int)rstack->time, timestamp[cpu]);
		TEST_EQ((uint64_t)rstack->addr, rec->func);
		TEST_EQ((int)rstack->depth, record_depth(rec));

		TEST_EQ(kernel->tids[cpu], rec->common_pid);

		consume_first_rstack_list(&kernel->rstack_list[cpu]);
		kernel->rstack_valid[cpu] = false;
		i++;
	}
	TEST_EQ(i, NUM_CPU * NUM_RECORD);

	return TEST_OK;
}

TEST_CASE(kernel_cpu_read)
{
	int cpu, i;
	int timestamp[NUM_CPU] = { };
	struct uftrace_kernel_reader *kernel = xzalloc(sizeof(*kernel));

	TEST_EQ(kernel_test_setup_file(kernel, false), 0);

	for (cpu = 0; cpu < NUM_CPU; cpu++) {
		for (i = 0; i < NUM_RECORD; i++) {
			struct funcgraph_exit *rec = &test_record[cpu][i];
			struct uftrace_record *rstack = &kernel->trace_rec;

			TEST_EQ(read_kernel_cpu_data(kernel, cpu), 0);

			timestamp[cpu] += test_len_ts[cpu][i].ts;

			pr_dbg("[%d] read cpu record: type=%d, depth=%d, addr=%"PRIx64"\n",
			       i, rstack->type, rstack->depth, (uint64_t)rstack->addr);
			TEST_EQ((int)rstack->type, record_type(rec));
			TEST_EQ((int)rstack->time, timestamp[cpu]);
			TEST_EQ((uint64_t)rstack->addr, rec->func);
			TEST_EQ((int)rstack->depth, record_depth(rec));

			TEST_EQ(kernel->tids[cpu], rec->common_pid);
		}
	}
	return TEST_OK;
}

TEST_CASE(kernel_event_read)
{
	int cpu, i;
	int timestamp[NUM_CPU] = { };
	struct uftrace_kernel_reader *kernel = xzalloc(sizeof(*kernel));

	pr_dbg("checking custom event format parsing\n");
	TEST_EQ(kernel_test_setup_file(kernel, true), 0);

	for (cpu = 0; cpu < NUM_CPU; cpu++) {
		for (i = 0; i < NUM_EVENT; i++) {
			struct test_example *rec = &test_event[cpu][i];
			struct uftrace_record *rstack = &kernel->trace_rec;
			char *data;
			int size;
			int foo, bar;

			TEST_EQ(read_kernel_cpu_data(kernel, cpu), 0);
			TEST_NE(data = read_kernel_event(kernel, cpu, &size), NULL);

			timestamp[cpu] += test_event_len_ts[cpu][i].ts;

			pr_dbg("[%d] read event record: type=%d, data=%s\n",
			       i, rstack->type, data);
			TEST_EQ((int)rstack->type, UFTRACE_EVENT);
			TEST_EQ((int)rstack->time, timestamp[cpu]);
			TEST_EQ((int)rstack->addr, TEST_EXAMPLE);
			TEST_EQ((int)rstack->depth, 0);

			TEST_EQ(kernel->tids[cpu], rec->common_pid);

			TEST_EQ(sscanf(data, "foo=%d, bar=%x", &foo, &bar), 2);
			TEST_EQ(foo, test_event[cpu][i].foo);
			TEST_EQ(bar, test_event[cpu][i].bar);
		}
	}
	return TEST_OK;
}

#endif /* UNIT_TEST */
