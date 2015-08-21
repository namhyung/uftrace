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

/* This should be defined before #include "utils.h" */
#define PR_FMT "kernel"

#include "utils.h"
#include "mcount.h"

#define TRACING_DIR  "/sys/kernel/debug/tracing"
#define FTRACE_TRACER  "function_graph"

static bool kernel_tracing_enabled;


static char *get_tracing_file(const char *name)
{
	char *file = NULL;

	if (asprintf(&file, "%s/%s", TRACING_DIR, name) < 0)
		return NULL;

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

	pr_dbg("%s '%s' to tracing/%s\n", append ? "appending" : "writing",
	       val, name);

	if (write(fd, val, size) == size)
		ret = 0;
	else
		pr_log("write '%s' to tracing/%s failed: %m\n", val, name);

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

static int set_tracing_filter(struct ftrace_kernel *kernel)
{
	const char *filter_file;

	if (kernel->filters) {
		char *pos = kernel->filters;
		char *tok;

		filter_file = "set_graph_function";

		tok = strtok(pos, ":");
		while (tok) {
			if (append_tracing_file(filter_file, tok) < 0)
				return -1;

			pos = NULL;
		}
	}

	if (kernel->notrace) {
		char *pos = kernel->notrace;
		char *tok;

		filter_file = "set_graph_notrace";

		tok = strtok(pos, ":");
		while (tok) {
			if (append_tracing_file(filter_file, tok) < 0)
				break; /* ignore error on old kernel */

			pos = NULL;
		}
	}

	return 0;
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
		pr_log("failed to reset tracing files\n");
		return -1;
	}

	/* reset ftrace buffer */
	if (write_tracing_file("trace", "0") < 0) {
		pr_log("failed to reset ftrace buffer\n");
		goto out;
	}

	if (set_tracing_clock() < 0) {
		pr_log("failed to set trace clock\n");
		goto out;
	}

	if (set_tracing_pid(kernel->pid) < 0) {
		pr_log("failed to set ftrace pid\n");
		goto out;
	}

	if (set_tracing_filter(kernel) < 0) {
		pr_log("failed to set ftrace filter\n");
		goto out;
	}

	if (write_tracing_file("current_tracer", FTRACE_TRACER) < 0) {
		pr_log("failed to set current_tracer\n");
		goto out;
	}

	kernel_tracing_enabled = true;
	return 0;

out:
	reset_tracing_files();
	return -1;
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
			pr_log("failed to open %s: %m\n", buf);
			goto out;
		}

		kernel->traces[i] = open(trace_file, O_RDONLY);
		saved_errno = errno;

		put_tracing_file(trace_file);

		if (kernel->traces[i] < 0) {
			errno = saved_errno;
			pr_log("failed to open %s: %m\n", buf);
			goto out;
		}

		fcntl(kernel->traces[i], F_SETFL, O_NONBLOCK);

		snprintf(buf, sizeof(buf), "%s/kernel-cpu%d.dat",
			 kernel->output_dir, i);

		kernel->fds[i] = open(buf, O_WRONLY | O_TRUNC | O_CREAT, 0600);
		if (kernel->fds[i] < 0) {
			pr_log("failed to open output file: %s: %m\n", buf);
			goto out;
		}
	}


	if (write_tracing_file("tracing_on", "1") < 0) {
		pr_log("can't enable tracing\n");
		goto out;
	}

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

	pr_dbg2("recording %zd bytes of kernel data\n", bytes);
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
