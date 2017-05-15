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

static size_t trace_pagesize;
static struct trace_seq trace_seq;
static struct uftrace_record trace_rstack = {
	.magic = RECORD_MAGIC,
};

static int prepare_kbuffer(struct uftrace_kernel *kernel, int cpu);

static int
funcgraph_entry_handler(struct trace_seq *s, struct pevent_record *record,
			struct event_format *event, void *context);
static int
funcgraph_exit_handler(struct trace_seq *s, struct pevent_record *record,
		       struct event_format *event, void *context);
static int
generic_event_handler(struct trace_seq *s, struct pevent_record *record,
		      struct event_format *event, void *context);

static int save_kernel_files(struct uftrace_kernel *kernel);
static int load_kernel_files(struct uftrace_kernel *kernel);

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

static int set_tracing_filter(struct uftrace_kernel *kernel)
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

	filter_file = "set_ftrace_filter";
	list_for_each_entry_safe(pos, tmp, &kernel->patches, list) {
		if (__write_tracing_file(filter_file, pos->name,
					 true, true) < 0)
			return -1;

		list_del(&pos->list);
		free(pos);
	}

	filter_file = "set_ftrace_notrace";
	list_for_each_entry_safe(pos, tmp, &kernel->nopatch, list) {
		if (__write_tracing_file(filter_file, pos->name,
					 true, true) < 0)
			return -1;

		list_del(&pos->list);
		free(pos);
	}

	return 0;
}

static int set_tracing_depth(struct uftrace_kernel *kernel)
{
	int ret = 0;
	char buf[32];

	snprintf(buf, sizeof(buf), "%d", kernel->depth);
	ret = write_tracing_file("max_graph_depth", buf);

	return ret;
}

static int set_tracing_bufsize(struct uftrace_kernel *kernel)
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
	/* it's not implemented yet */
	return true;
}

static void build_kernel_filter(struct uftrace_kernel *kernel, char *filter_str,
				struct list_head *filters,
				struct list_head *notrace)
{
	struct list_head *head;
	struct kfilter *kfilter;
	char *pos, *str, *name;

	if (filter_str == NULL)
		return;

	pos = str = xstrdup(filter_str);

	name = strtok(pos, ";");
	while (name) {
		pos = strchr(name, '@');
		if (!pos || strncasecmp(pos+1, "kernel", 6))
			goto next;
		*pos = '\0';

		if (name[0] == '!') {
			head = notrace;
			name++;
		}
		else
			head = filters;

		kfilter = xmalloc(sizeof(*kfilter) + strlen(name) + 1);
		strcpy(kfilter->name, name);
		list_add(&kfilter->list, head);

next:
		name = strtok(NULL, ";");
	}
	free(str);
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
	write_tracing_file("set_graph_notrace", " ");

	if (write_tracing_file("set_ftrace_filter", " ") < 0)
		return -1;

	if (write_tracing_file("set_ftrace_notrace", " ") < 0)
		return -1;

	if (write_tracing_file("max_graph_depth", "0") < 0)
		return -1;

	/* default kernel buffer size: 16384 * 88 / 1024 = 1408 */
	if (write_tracing_file("buffer_size_kb", "1408") < 0)
		return -1;

	kernel_tracing_enabled = false;
	return 0;
}

static int __setup_kernel_tracing(struct uftrace_kernel *kernel)
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

	/* disable tracing */
	if (write_tracing_file("tracing_on", "0") < 0)
		return -1;

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
 * @opts: option related to kernel tracing
 *
 * This function sets up all necessary data structures and configure
 * kernel ftrace subsystem.
 */
int setup_kernel_tracing(struct uftrace_kernel *kernel, struct opts *opts)
{
	int i, n;

	INIT_LIST_HEAD(&kernel->filters);
	INIT_LIST_HEAD(&kernel->notrace);
	INIT_LIST_HEAD(&kernel->patches);
	INIT_LIST_HEAD(&kernel->nopatch);

	build_kernel_filter(kernel, opts->filter,
			    &kernel->filters, &kernel->notrace);
	build_kernel_filter(kernel, opts->patch,
			    &kernel->patches, &kernel->nopatch);

	if (opts->kernel_skip_out) {
		/*
		 * Some (old) kernel and architecture doesn't support VDSO
		 * so there will be many sys_clock_gettime() in the output
		 * due to internal call in libmcount.  It'd be better
		 * ignoring them not to confuse users.  I think it does NOT
		 * affect to the output when VDSO is enabled.
		 *
		 * If an user wants to see them, give --kernel-full option.
		 */
		build_kernel_filter(kernel, "!sys_clock_gettime@kernel",
				    &kernel->filters, &kernel->notrace);
	}

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
int start_kernel_tracing(struct uftrace_kernel *kernel)
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
 * @sock - socket descriptor (for network transfer)
 *
 * This function read trace data for @cpu and save it to file.
 */
int record_kernel_trace_pipe(struct uftrace_kernel *kernel, int cpu, int sock)
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
int record_kernel_tracing(struct uftrace_kernel *kernel)
{
	ssize_t bytes = 0;
	ssize_t n;
	int i;

	if (!kernel_tracing_enabled)
		return -1;

	for (i = 0; i < kernel->nr_cpus; i++) {
		n = record_kernel_trace_pipe(kernel, i, -1);
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
int stop_kernel_tracing(struct uftrace_kernel *kernel)
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
int finish_kernel_tracing(struct uftrace_kernel *kernel)
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

	save_kernel_files(kernel);
	save_kernel_symbol(kernel->output_dir);

	reset_tracing_files();

	return 0;
}

static const char *get_endian_str(void)
{
	if (get_elf_endian() == ELFDATA2LSB)
		return "LE";
	else
		return "BE";
}

static int save_kernel_file(FILE *fp, const char *name)
{
	int fd;
	ssize_t len;
	char buf[4096];

	snprintf(buf, sizeof(buf), "%s/%s", TRACING_DIR, name);

	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, sizeof(buf));
	if (len < 0) {
		close(fd);
		return -1;
	}

	fprintf(fp, "TRACEFS: %s: %zd\n", name, len);
	fwrite(buf, len, 1, fp);

	close(fd);
	return 0;
}

static int save_event_files(struct uftrace_kernel *kernel, FILE *fp)
{
	int fd;
	int ret = -1;
	ssize_t len;
	char buf[4096];
	DIR *subsys, *event;
	struct dirent *sys, *name;

	snprintf(buf, sizeof(buf), "%s/events/enable", TRACING_DIR);

	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
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
		int sfd;

		if (sys->d_name[0] == '.' || sys->d_type != DT_DIR)
			continue;

		/* ftrace events are special - skip it */
		if (!strcmp(sys->d_name, "ftrace"))
			continue;

		snprintf(buf, sizeof(buf), "%s/events/%s/enable",
			 TRACING_DIR, sys->d_name);

		sfd = open(buf, O_RDONLY);
		if (sfd < 0)
			goto out;

		len = read(sfd, buf, sizeof(buf));
		if (len < 0)
			goto out;

		/* this subsystem has no events enabled */
		if (buf[0] == '0')
			goto next;

		snprintf(buf, sizeof(buf), "%s/events/%s",
			 TRACING_DIR, sys->d_name);

		event = opendir(buf);
		if (event == NULL)
			goto out;

		while ((name = readdir(event)) != NULL) {
			int efd;

			if (name->d_name[0] == '.' || name->d_type != DT_DIR)
				continue;

			snprintf(buf, sizeof(buf), "%s/events/%s/%s/enable",
				 TRACING_DIR, sys->d_name, name->d_name);

			efd = open(buf, O_RDONLY);
			if (efd < 0)
				goto out;

			len = read(efd, buf, sizeof(buf));
			if (len < 0)
				goto out;

			/* this event is not enabled */
			if (buf[0] == '0')
				continue;

			snprintf(buf, sizeof(buf), "events/%s/%s/format",
				 sys->d_name, name->d_name);

			if (save_kernel_file(fp, buf) < 0)
				goto out;

			close(efd);
		}
		closedir(event);

	next:
		close(sfd);
	}
	closedir(subsys);

	ret = 0;

out:
	close(fd);
	return ret;
}

static int save_kernel_files(struct uftrace_kernel *kernel)
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
static int load_current_kernel(struct uftrace_kernel *kernel)
{
	int fd;
	size_t len;
	char buf[4096];
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

static int load_kernel_files(struct uftrace_kernel *kernel)
{
	char *path = NULL;
	FILE *fp;
	char buf[4096];
	struct pevent *pevent = kernel->pevent;
	int ret = 0;

	xasprintf(&path, "%s/kernel_header", kernel->output_dir);

	fp = fopen(path, "r");
	if (fp == NULL)  /* old data doesn't have the kernel header */
		return load_current_kernel(kernel);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char name[128];
		size_t len;

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

		sscanf(buf, "TRACEFS: %[^:]: %zd\n", name, &len);

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
						      generic_event_handler, NULL);
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

/**
 * setup_kernel_data - prepare to read kernel ftrace data from files
 * @kernel - kernel ftrace handle
 *
 * This function initializes necessary data structures for reading
 * kernel ftrace data files.  It should be called in pair with
 * finish_kernel_data().
 */
int setup_kernel_data(struct uftrace_kernel *kernel)
{
	int i;
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

	if (load_kernel_files(kernel) < 0) {
		pr_out("cannot read kernel header: %m\n");
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

	if (pevent_is_file_bigendian(kernel->pevent))
		endian = KBUFFER_ENDIAN_BIG;
	if (pevent_get_long_size(kernel->pevent) == 4)
		longsize = KBUFFER_LSIZE_4;
	trace_pagesize = pevent_get_page_size(kernel->pevent);

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
int finish_kernel_data(struct uftrace_kernel *kernel)
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

static int prepare_kbuffer(struct uftrace_kernel *kernel, int cpu)
{
	kernel->mmaps[cpu] = mmap(NULL, trace_pagesize, PROT_READ, MAP_PRIVATE,
				  kernel->fds[cpu], kernel->offsets[cpu]);
	if (kernel->mmaps[cpu] == MAP_FAILED) {
		pr_dbg("loading kbuffer for cpu %d (fd: %d, offset: %lu, pagesize: %zd) failed\n",
		       cpu, kernel->fds[cpu], kernel->offsets[cpu], trace_pagesize);
		return -1;
	}

	kbuffer_load_subbuffer(kernel->kbufs[cpu], kernel->mmaps[cpu]);
	kernel->missed_events[cpu] = kbuffer_missed_events(kernel->kbufs[cpu]);

	return 0;
}

static int next_kbuffer_page(struct uftrace_kernel *kernel, int cpu)
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

	trace_rstack.type  = UFTRACE_ENTRY;
	trace_rstack.time  = record->ts;
	trace_rstack.addr  = addr;
	trace_rstack.depth = depth;
	trace_rstack.more  = 0;

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

	trace_rstack.type  = UFTRACE_EXIT;
	trace_rstack.time  = record->ts;
	trace_rstack.addr  = addr;
	trace_rstack.depth = depth;
	trace_rstack.more  = 0;

	return 0;
}

static int
generic_event_handler(struct trace_seq *s, struct pevent_record *record,
		      struct event_format *event, void *context)
{
	trace_rstack.type  = UFTRACE_EVENT;
	trace_rstack.time  = record->ts;
	trace_rstack.addr  = event->id;
	trace_rstack.depth = 0;
	trace_rstack.more  = 1;

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
int read_kernel_cpu_data(struct uftrace_kernel *kernel, int cpu)
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
	struct uftrace_kernel *kernel = &handle->kernel;
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
		struct ftrace_task_handle *task;
		struct ftrace_trigger tr = {};
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
		real_addr = get_real_address(curr->addr);
		/*
		 * it might set TRACE trigger, which shows
		 * function even if it's less than the time filter.
		 */
		uftrace_match_filter(real_addr, &sess->filters, &tr);

		if (curr->type == UFTRACE_ENTRY) {
			/* it needs to wait until matching exit found */
			add_to_rstack_list(rstack_list, curr, NULL);

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

			if (delta < time_filter) {
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
				.data = trace_seq.buffer,
				.len  = trace_seq.len,
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
void * read_kernel_event(struct uftrace_kernel *kernel, int cpu, int *psize)
{
	struct uftrace_record *rstack = &kernel->rstacks[cpu];

	if (!rstack->more)
		return NULL;

	*psize = trace_seq.len;
	return trace_seq.buffer;
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
	struct uftrace_kernel *kernel = &handle->kernel;
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
	if (*taskp == NULL) {
		/* force re-read on that cpu */
		kernel->rstack_valid[first_cpu] = false;
		goto retry;
	}

	memcpy(&(*taskp)->kstack, first_rstack, sizeof(*first_rstack));

	return first_cpu;
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

static struct ftrace_file_handle test_handle;
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
static struct type_len_ts padding = { KBUFFER_TYPE_PADDING, 0 };

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

static int kernel_test_setup_file(struct uftrace_kernel *kernel, bool event)
{
	int cpu, i;
	FILE *fp;
	char *filename;
	unsigned long pad;

	kernel->output_dir = "kernel.dir";
	kernel->nr_cpus    = NUM_CPU;

	if (mkdir(kernel->output_dir, 0755) < 0) {
		if (errno != EEXIST) {
			pr_dbg("cannot create temp dir: %m\n");
			return -1;
		}
	}

	if (asprintf(&filename, "%s/kernel_header", kernel->output_dir) < 0) {
		pr_dbg("cannot alloc filename: %s/kernel_header",
		       kernel->output_dir);
		return -1;
	}

	fp = fopen(filename, "w");
	if (fp == NULL) {
		pr_dbg("file open failed: %m\n");
		free(filename);
		return -1;
	}

	fwrite(test_kernel_header, 1, strlen(test_kernel_header), fp);
	if (event)
		fwrite(test_kernel_event, 1, strlen(test_kernel_event), fp);

	free(filename);
	fclose(fp);

	for (cpu = 0; cpu < kernel->nr_cpus; cpu++) {
		if (asprintf(&filename, "%s/kernel-cpu%d.dat",
			     kernel->output_dir, cpu) < 0) {
			pr_dbg("cannot alloc filename: %s/%d.dat",
			       kernel->output_dir, cpu);
			return -1;
		}

		fp = fopen(filename, "w");
		if (fp == NULL) {
			pr_dbg("file open failed: %m\n");
			free(filename);
			return -1;
		}

		fwrite(&header, 1, sizeof(header), fp);

		if (event) {
			for (i = 0; i < NUM_EVENT; i++) {
				fwrite(&test_event_len_ts[cpu][i], 1,
				       sizeof(test_event_len_ts[cpu][i]), fp);
				fwrite(&test_event[cpu][i], 1,
				       sizeof(test_event[cpu][i]), fp);
			}
		}
		else {
			for (i = 0; i < NUM_RECORD; i++) {
				fwrite(&test_len_ts[cpu][i], 1,
				       sizeof(test_len_ts[cpu][i]), fp);
				fwrite(&test_record[cpu][i], 1,
				       record_size(&test_record[cpu][i]), fp);
			}
		}

		/* pad to page size */
		fwrite(&padding, 1, sizeof(padding), fp);

		pad = 4096 - ftell(fp);
		fwrite(&pad, 1, sizeof(pad), fp);

		fallocate(fileno(fp), 0, 0, 4096);

		free(filename);
		fclose(fp);
	}

	atexit(kernel_test_finish_file);

	setup_kernel_data(kernel);
	return 0;
}

static int kernel_test_setup_handle(struct uftrace_kernel *kernel,
				    struct ftrace_file_handle *handle)
{
	int i;

	handle->nr_tasks = NUM_TASK;
	handle->tasks = xcalloc(sizeof(*handle->tasks), NUM_TASK);

	handle->time_range.start = handle->time_range.stop = 0;
	handle->time_filter = 0;

	for (i = 0; i < NUM_TASK; i++) {
		handle->tasks[i].tid = test_tids[i];
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
	struct uftrace_kernel *kernel = &test_handle.kernel;

	if (kernel->output_dir == NULL)
		return;

	finish_kernel_data(kernel);

	for (cpu = 0; cpu < kernel->nr_cpus; cpu++) {
		if (asprintf(&filename, "%s/kernel-cpu%d.dat",
			     kernel->output_dir, cpu) < 0)
			return;

		remove(filename);
		free(filename);
	}

	if (asprintf(&filename, "%s/kernel_header", kernel->output_dir) < 0)
		return;

	remove(filename);
	free(filename);

	remove(kernel->output_dir);
	kernel->output_dir = NULL;
}

static void kernel_test_finish_handle(void)
{
	struct ftrace_file_handle *handle = &test_handle;

	free(handle->tasks);
	handle->tasks = NULL;
}

TEST_CASE(kernel_read)
{
	int cpu, i;
	int timestamp[NUM_CPU] = { };
	struct ftrace_file_handle *handle = &test_handle;
	struct uftrace_kernel *kernel = &handle->kernel;
	struct ftrace_task_handle *task;

	TEST_EQ(kernel_test_setup_file(kernel, false), 0);
	TEST_EQ(kernel_test_setup_handle(kernel, handle), 0);

	i = 0;
	while ((cpu = read_kernel_stack(handle, &task)) != -1) {
		struct funcgraph_exit *rec = &test_record[cpu][i / 2];
		struct uftrace_record *rstack = &task->kstack;

		timestamp[cpu] += test_len_ts[cpu][i / 2].ts;

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
	struct uftrace_kernel *kernel = &test_handle.kernel;

	TEST_EQ(kernel_test_setup_file(kernel, false), 0);

	for (cpu = 0; cpu < NUM_CPU; cpu++) {
		for (i = 0; i < NUM_RECORD; i++) {
			struct funcgraph_exit *rec = &test_record[cpu][i];
			struct uftrace_record *rstack = &trace_rstack;

			TEST_EQ(read_kernel_cpu_data(kernel, cpu), 0);

			timestamp[cpu] += test_len_ts[cpu][i].ts;

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
	struct uftrace_kernel *kernel = &test_handle.kernel;

	TEST_EQ(kernel_test_setup_file(kernel, true), 0);

	for (cpu = 0; cpu < NUM_CPU; cpu++) {
		for (i = 0; i < NUM_EVENT; i++) {
			struct test_example *rec = &test_event[cpu][i];
			struct uftrace_record *rstack = &trace_rstack;
			char *data;
			int size;
			int foo, bar;

			TEST_EQ(read_kernel_cpu_data(kernel, cpu), 0);
			TEST_NE(data = read_kernel_event(kernel, cpu, &size), NULL);

			timestamp[cpu] += test_event_len_ts[cpu][i].ts;

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
