#ifndef UFTRACE_KERNEL_H
#define UFTRACE_KERNEL_H

#include "uftrace.h"
#include "utils/kernel-parser.h"
#include "utils/list.h"
#include "utils/utils.h"

#define KERNEL_NOP_TRACER "nop"
#define KERNEL_GRAPH_TRACER "function_graph"

struct uftrace_kernel_writer {
	int pid;
	int nr_cpus;
	int depth;
	unsigned long bufsize;
	char *tracer;
	int *traces;
	int *fds;
	char *output_dir;
	char *clock;
	struct list_head filters;
	struct list_head notrace;
	struct list_head patches;
	struct list_head nopatch;
	struct list_head events;
};

struct uftrace_kernel_reader {
	int nr_cpus;
	int last_read_cpu;
	bool skip_out;
	char *dirname;
	struct uftrace_data *handle;
	struct uftrace_kernel_parser parser;
	struct uftrace_record *rstacks;
	struct uftrace_rstack_list *rstack_list;
	bool *rstack_valid;
	bool *rstack_done;
	int *tids;
};

/* these functions will be used at record time */
int setup_kernel_tracing(struct uftrace_kernel_writer *kernel, struct uftrace_opts *opts);
int start_kernel_tracing(struct uftrace_kernel_writer *kernel);
int record_kernel_tracing(struct uftrace_kernel_writer *kernel);
int record_kernel_trace_pipe(struct uftrace_kernel_writer *kernel, int cpu, int sock);
int stop_kernel_tracing(struct uftrace_kernel_writer *kernel);
int finish_kernel_tracing(struct uftrace_kernel_writer *kernel);
void list_kernel_events(void);

/* these functions will be used at replay time */
int setup_kernel_data(struct uftrace_kernel_reader *kernel);
int read_kernel_stack(struct uftrace_data *handle, struct uftrace_task_reader **taskp);
int read_kernel_cpu_data(struct uftrace_kernel_reader *kernel, int cpu);
void *read_kernel_event(struct uftrace_kernel_reader *kernel, int cpu, int *psize);
struct uftrace_record *get_kernel_record(struct uftrace_kernel_reader *kernel,
					 struct uftrace_task_reader *task, int cpu);
int finish_kernel_data(struct uftrace_kernel_reader *kernel);

static inline bool has_kernel_data(struct uftrace_kernel_reader *kernel)
{
	return kernel && kparser_ready(&kernel->parser);
}

static inline bool has_kernel_event(char *events)
{
	return events && has_kernel_filter(events);
}

bool check_kernel_pid_filter(void);

#endif /* UFTRACE_KERNEL_H */
