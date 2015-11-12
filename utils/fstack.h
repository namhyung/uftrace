#ifndef __FTRACE_FSTACK_H__
#define __FTRACE_FSTACK_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "../ftrace.h"
#include "rbtree.h"

#define FSTACK_MAX  1024

struct sym;

struct ftrace_task_handle {
	int tid;
	bool valid;
	bool done;
	bool lost_seen;
	FILE *fp;
	struct sym *func;
	int filter_count;
	int filter_depth;
	struct ftrace_ret_stack ustack;
	struct ftrace_ret_stack kstack;
	struct ftrace_ret_stack *rstack;
	int stack_count;
	int lost_count;
	struct fstack {
		unsigned long addr;
		bool valid;
		int orig_depth;
		uint64_t total_time;
		uint64_t child_time;
	} func_stack[FSTACK_MAX];
};

struct ftrace_func_filter {
	bool has_filters;
	bool has_notrace;
	struct rb_root filters;
	struct rb_root notrace;
};

extern struct ftrace_task_handle *tasks;
extern int nr_tasks;

extern struct ftrace_func_filter filters;

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

int update_filter_count_entry(struct ftrace_task_handle *task,
			      unsigned long addr, int depth);
void update_filter_count_exit(struct ftrace_task_handle *task,
			      unsigned long addr, int depth);

#endif /* __FTRACE_FSTACK_H__ */
