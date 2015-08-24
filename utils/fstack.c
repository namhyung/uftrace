#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#include "../ftrace.h"
#include "../libmcount/mcount.h"
#include "utils.h"


#define FILTER_COUNT_NOTRACE  10000

struct ftrace_task_handle *tasks;
int nr_tasks;

struct ftrace_func_filter filters;

void reset_task_handle(void)
{
	int i;

	for (i = 0; i < nr_tasks; i++) {
		tasks[i].done = true;

		if (tasks[i].fp) {
			fclose(tasks[i].fp);
			tasks[i].fp = NULL;
		}
	}

	free(tasks);
	tasks = NULL;

	nr_tasks = 0;
}

void setup_task_filter(char *tid_filter, struct ftrace_file_handle *handle)
{
	int i, k;
	int nr_filters = 0;
	int *filter_tids = NULL;
	char *p = tid_filter;

	assert(tid_filter);

	do {
		int id;

		if (*p == ',' || *p == ':')
			p++;

		id = strtol(p, &p, 10);

		filter_tids = xrealloc(filter_tids, (nr_filters+1) * sizeof(int));
		filter_tids[nr_filters++] = id;

	} while (*p);

	nr_tasks = handle->info.nr_tid;
	tasks = xcalloc(sizeof(*tasks), nr_tasks);

	for (i = 0; i < nr_tasks; i++) {
		char *filename;
		bool found = false;
		int tid = handle->info.tids[i];

		tasks[i].tid = tid;

		for (k = 0; k < nr_filters; k++) {
			if (tid == filter_tids[k]) {
				found = true;
				break;
			}
		}

		if (!found) {
			tasks[i].done = true;
			continue;
		}

		if (asprintf(&filename, "%s/%d.dat", handle->dirname, tid) < 0)
			pr_err("cannot open task data file for %d", tid);

		tasks[i].fp = fopen(filename, "rb");
		if (tasks[i].fp == NULL)
			pr_err("cannot open task data file [%s]", filename);

		if (filters.has_filters)
			tasks[i].filter_count = 0;
		else
			tasks[i].filter_count = 1;

		pr_dbg("opening %s\n", filename);
		free(filename);
	}

	free(filter_tids);
}

void update_filter_count_entry(struct ftrace_task_handle *task,
			       unsigned long addr, int depth)
{
	if (filters.has_filters && ftrace_match_filter(&filters.filters, addr)) {
		task->filter_count++;
		task->func_stack[task->stack_count-1].orig_depth = task->filter_depth;
		task->filter_depth = depth;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	} else if (filters.has_notrace && ftrace_match_filter(&filters.notrace, addr)) {
		task->filter_count -= FILTER_COUNT_NOTRACE;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	}
}

void update_filter_count_exit(struct ftrace_task_handle *task,
			      unsigned long addr, int depth)
{
	if (filters.has_filters && ftrace_match_filter(&filters.filters, addr)) {
		task->filter_count--;
		task->filter_depth = task->func_stack[task->stack_count].orig_depth;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	} else if (filters.has_notrace && ftrace_match_filter(&filters.notrace, addr)) {
		task->filter_count += FILTER_COUNT_NOTRACE;
		pr_dbg("  [%5d] filter count: %d\n", task->tid, task->filter_count);
	}
}

int read_task_ustack(struct ftrace_task_handle *handle)
{
	FILE *fp = handle->fp;

	if (fread(&handle->ustack, sizeof(handle->ustack), 1, fp) != 1) {
		if (feof(fp))
			return -1;

		pr_log("error reading rstack: %s\n", strerror(errno));
		return -1;
	}

	if (handle->ustack.unused != FTRACE_UNUSED) {
		pr_log("invalid rstack read\n");
		return -1;
	}

	return 0;
}

struct ftrace_ret_stack *
get_task_ustack(struct ftrace_file_handle *handle, int idx)
{
	struct ftrace_task_handle *fth;
	char *filename;

	if (unlikely(idx >= nr_tasks)) {
		nr_tasks = idx + 1;
		tasks = xrealloc(tasks, sizeof(*tasks) * nr_tasks);

		memset(&tasks[idx], 0, sizeof(*tasks));

		if (asprintf(&filename, "%s/%d.dat",
			     handle->dirname, handle->info.tids[idx]) < 0)
			pr_err("cannot read task rstack for %d",
			       handle->info.tids[idx]);

		tasks[idx].tid = handle->info.tids[idx];
		tasks[idx].fp = fopen(filename, "rb");

		if (tasks[idx].fp == NULL) {
			pr_log("cannot open task data file [%s]\n", filename);
			tasks[idx].done = true;
			return NULL;
		}

		if (filters.has_filters)
			tasks[idx].filter_count = 0;
		else
			tasks[idx].filter_count = 1;

		tasks[idx].stack_count = 0;
		tasks[idx].filter_depth = handle->depth;

		pr_dbg("opening %s\n", filename);
		free(filename);
	}

	fth = &tasks[idx];

	if (fth->valid)
		return &fth->ustack;

	if (fth->done)
		return NULL;

	if (read_task_ustack(fth) < 0) {
		fth->done = true;
		fclose(fth->fp);
		fth->fp = NULL;
		return NULL;
	}

	if (fth->lost_seen) {
		int i;

		for (i = 0; i <= fth->ustack.depth; i++)
			fth->func_stack[i].valid = false;

		fth->lost_seen = false;
	}

	if (fth->ustack.type == FTRACE_ENTRY) {
		struct fstack *fstack = &fth->func_stack[fth->ustack.depth];

		fstack->total_time = fth->ustack.time;
		fstack->child_time = 0;
		fstack->valid = true;
		fstack->addr = fth->ustack.addr;

		fth->stack_count = fth->ustack.depth + 1;

	} else if (fth->ustack.type == FTRACE_EXIT) {
		uint64_t delta;
		struct fstack *fstack = &fth->func_stack[fth->ustack.depth];

		delta = fth->ustack.time - fstack->total_time;

		if (!fstack->valid)
			delta = 0UL;
		fstack->valid = false;

		fstack->total_time = delta;
		if (fstack->child_time > fstack->total_time)
			fstack->child_time = fstack->total_time;

		fth->stack_count = fth->ustack.depth;
		if (fth->stack_count > 0)
			fth->func_stack[fth->stack_count - 1].child_time += delta;

	} else if (fth->ustack.type == FTRACE_LOST) {
		fth->lost_seen = true;
	}

	fth->valid = true;
	return &fth->ustack;
}

struct ftrace_task_handle *get_task_handle(int tid)
{
	int i;

	for (i = 0; i < nr_tasks; i++) {
		if (tasks[i].tid == tid)
			return &tasks[i];
	}
	return NULL;
}

static int read_user_stack(struct ftrace_file_handle *handle,
			   struct ftrace_task_handle **task)
{
	int i, next_i = -1;
	uint64_t next_time;
	struct ftrace_ret_stack *tmp;

	for (i = 0; i < handle->info.nr_tid; i++) {
		tmp = get_task_ustack(handle, i);
		if (tmp == NULL)
			continue;

		if (next_i < 0 || tmp->time < next_time) {
			next_time = tmp->time;
			next_i = i;
		}
	}

	if (next_i < 0)
		return -1;

	*task = &tasks[next_i];

	return next_i;
}

static int __read_rstack(struct ftrace_file_handle *handle,
			 struct ftrace_task_handle **taskp,
			 bool invalidate)
{
	int u, k = -1;
	struct ftrace_task_handle *task = NULL;
	struct ftrace_kernel *kernel = handle->kern;
	struct mcount_ret_stack kstack;
	uint64_t ktime;

	u = read_user_stack(handle, taskp);
	if (kernel)
		k = read_kernel_stack(kernel, &kstack);

	if (u < 0 && k < 0)
		return -1;

	if (k < 0)
		goto user;
	if (u < 0)
		goto kernel;

	ktime = kstack.end_time ?: kstack.start_time;

	if ((*taskp)->ustack.time < ktime) {
user:
		task = *taskp;

		if (invalidate)
			task->valid = false;

		task->rstack = &task->ustack;
	}
	else {
kernel:
		task = get_task_handle(kstack.tid);
		if (task == NULL)
			pr_err_ns("cannot find task for tid %d\n", kstack.tid);

		/* convert to ftrace_rstack */
		task->kstack.time = kstack.end_time ?: kstack.start_time;
		task->kstack.type = kstack.end_time ? FTRACE_EXIT : FTRACE_ENTRY;
		task->kstack.addr = kstack.child_ip;
		task->kstack.depth = kstack.depth;
		task->kstack.unused = FTRACE_UNUSED;

		/* account current task stack depth */
		task->kstack.depth += task->stack_count;
		if (!task->done)
			task->kstack.depth++;

		if (invalidate)
			kernel->rstack_valid[k] = false;

		task->rstack = &task->kstack;

		if (task->rstack->type == FTRACE_ENTRY) {
			struct fstack *fstack = &task->func_stack[task->kstack.depth];

			fstack->valid = true;
			fstack->addr = kstack.child_ip;
			fstack->child_time = 0;
		}
		else if (task->rstack->type == FTRACE_EXIT) {
			struct fstack *fstack = &task->func_stack[task->kstack.depth];

			fstack->valid = false;
			fstack->addr = kstack.child_ip;
			fstack->total_time = kstack.end_time - kstack.start_time;

			if (task->kstack.depth > 0) {
				uint64_t child_time = fstack->total_time;

				fstack = &task->func_stack[task->kstack.depth - 1];
				fstack->child_time += child_time;
			}
		}
	}

	*taskp = task;
	return 0;
}

int read_rstack(struct ftrace_file_handle *handle,
		struct ftrace_task_handle **task)
{
	return __read_rstack(handle, task, true);
}

int peek_rstack(struct ftrace_file_handle *handle,
		struct ftrace_task_handle **task)
{
	return __read_rstack(handle, task, false);
}
