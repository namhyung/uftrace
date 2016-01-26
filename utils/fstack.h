#ifndef __FTRACE_FSTACK_H__
#define __FTRACE_FSTACK_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "../ftrace.h"

#define FSTACK_MAX  1024

struct sym;
struct ftrace_trigger;

enum fstack_flag {
	FSTACK_FL_FILTERED	= (1U << 0),
	FSTACK_FL_NOTRACE	= (1U << 1),
	FSTACK_FL_NORECORD	= (1U << 2),
};

struct ftrace_task_handle {
	int tid;
	bool valid;
	bool done;
	bool lost_seen;
	FILE *fp;
	struct sym *func;
	struct ftrace_task *t;
	struct ftrace_file_handle *h;
	struct ftrace_ret_stack ustack;
	struct ftrace_ret_stack kstack;
	struct ftrace_ret_stack *rstack;
	int stack_count;
	int lost_count;
	struct filter {
		int	in_count;
		int	out_count;
		int	depth;
	} filter;
	struct fstack {
		unsigned long addr;
		bool valid;
		int orig_depth;
		unsigned long flags;
		uint64_t total_time;
		uint64_t child_time;
	} func_stack[FSTACK_MAX];
};

extern struct ftrace_task_handle *tasks;
extern int nr_tasks;
extern bool fstack_enabled;

struct ftrace_task_handle *get_task_handle(int tid);
void reset_task_handle(void);

int read_rstack(struct ftrace_file_handle *handle,
		struct ftrace_task_handle **task);
int peek_rstack(struct ftrace_file_handle *handle,
		struct ftrace_task_handle **task);

struct ftrace_ret_stack *
get_task_ustack(struct ftrace_file_handle *handle, int idx);
int read_task_ustack(struct ftrace_task_handle *handle);

void setup_task_filter(char *tid_filter, struct ftrace_file_handle *handle);
int setup_fstack_filters(char *filter_str, char *trigger_str,
			 struct symtabs *symtabs);

int fstack_entry(struct ftrace_task_handle *task,
		 struct ftrace_ret_stack *rstack,
		 struct ftrace_trigger *tr);
void fstack_exit(struct ftrace_task_handle *task);

#endif /* __FTRACE_FSTACK_H__ */
