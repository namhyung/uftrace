#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT  "fstack"

#include "../ftrace.h"
#include "../libmcount/mcount.h"
#include "utils.h"
#include "filter.h"
#include "fstack.h"
#include "rbtree.h"


#define FILTER_COUNT_NOTRACE  10000

struct ftrace_task_handle *tasks;
int nr_tasks;

static struct rb_root fstack_filters = RB_ROOT;
static enum filter_mode fstack_filter_mode = FILTER_MODE_NONE;

struct ftrace_task_handle *get_task_handle(int tid)
{
	int i;

	for (i = 0; i < nr_tasks; i++) {
		if (tasks[i].tid == tid)
			return &tasks[i];
	}
	return NULL;
}

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

		xasprintf(&filename, "%s/%d.dat", handle->dirname, tid);

		tasks[i].fp = fopen(filename, "rb");
		if (tasks[i].fp == NULL)
			pr_err("cannot open task data file [%s]", filename);

		pr_dbg("opening %s\n", filename);
		free(filename);

		tasks[i].filter.depth = handle->depth;
	}

	free(filter_tids);
}

int setup_fstack_filter(char *filter_str, char *notrace_str,
			struct symtabs *symtabs)
{
	if (filter_str) {
		ftrace_setup_filter(filter_str, symtabs, NULL,
				    &fstack_filters, FILTER_MODE_IN);
		ftrace_setup_filter(filter_str, symtabs, "PLT",
				    &fstack_filters, FILTER_MODE_IN);
		ftrace_setup_filter(filter_str, symtabs, "kernel",
				    &fstack_filters, FILTER_MODE_IN);
		if (RB_EMPTY_ROOT(&fstack_filters))
			return -1;

		fstack_filter_mode = FILTER_MODE_IN;
	}

	if (notrace_str) {
		ftrace_setup_filter(notrace_str, symtabs, NULL,
				    &fstack_filters, FILTER_MODE_OUT);
		ftrace_setup_filter(notrace_str, symtabs, "PLT",
				    &fstack_filters, FILTER_MODE_OUT);
		ftrace_setup_filter(notrace_str, symtabs, "kernel",
				    &fstack_filters, FILTER_MODE_OUT);
		if (RB_EMPTY_ROOT(&fstack_filters))
			return -1;

		if (fstack_filter_mode == FILTER_MODE_NONE)
			fstack_filter_mode = FILTER_MODE_OUT;
	}

	return 0;
}

/**
 * fstack_entry - function entry handler
 * @task  - tracee task
 * @addr  - function address
 * @depth - default function filter depth if filter matched
 * @tr    - trigger data
 *
 * This function should be called when replaying a recorded session.
 * It updates function stack, filter status, trigger result and
 * determine how to react. Callers can do whatever they want based
 * on the trigger result.
 *
 * This function returns 1 if filter matched, 0 if not, and -1 if
 * it should be skipped.
 */
int fstack_entry(struct ftrace_task_handle *task, unsigned long addr,
		 int depth, struct ftrace_trigger *tr)
{
	int ret = 0;
	struct fstack *fstack;

	/* stack_count was increased in __read_rstack */
	fstack = &task->func_stack[task->stack_count - 1];

	pr_dbg2("ENTRY: [%5d] stack: %d, I: %d, O: %d, D: %d, flags = %lx\n",
		task->tid, task->stack_count-1, task->filter.in_count,
		task->filter.out_count, task->filter.depth, fstack->flags);

	fstack->orig_depth = task->filter.depth;
	fstack->flags = 0;

	if (task->filter.out_count > 0) {
		fstack->flags |= FSTACK_FL_NORECORD;
		return -1;
	}

	if (is_kernel_address(addr))
		addr = get_real_address(addr);

	ftrace_match_filter(&fstack_filters, addr, tr);

	if (tr->flags & TRIGGER_FL_FILTER) {
		if (tr->fmode == FILTER_MODE_IN) {
			task->filter.in_count++;
			fstack->flags |= FSTACK_FL_FILTERED;
			ret = 1;
		}
		else {
			task->filter.out_count++;
			fstack->flags |= FSTACK_FL_NOTRACE | FSTACK_FL_NORECORD;
			return -1;
		}

		task->filter.depth = depth;
	}
	else {
		if (fstack_filter_mode == FILTER_MODE_IN &&
		    task->filter.in_count == 0) {
			fstack->flags |= FSTACK_FL_NORECORD;
			return -1;
		}
	}

	if (tr->flags & TRIGGER_FL_DEPTH)
		task->filter.depth = tr->depth;

	if (task->filter.depth <= 0) {
		fstack->flags |= FSTACK_FL_NORECORD;
		return -1;
	}

	task->filter.depth--;

	return ret;
}

/**
 * fstack_exit - function exit handler
 * @task - tracee task
 *
 * This function should be paired with fstack_entry().
 */
void fstack_exit(struct ftrace_task_handle *task)
{
	struct fstack *fstack;

	fstack = &task->func_stack[task->stack_count];

	pr_dbg2("EXIT : [%5d] stack: %d, I: %d, O: %d, D: %d, flags = %lx\n",
		task->tid, task->stack_count, task->filter.in_count,
		task->filter.out_count, task->filter.depth, fstack->flags);

	if (fstack->flags & FSTACK_FL_FILTERED)
		task->filter.in_count--;
	else if (fstack->flags & FSTACK_FL_NOTRACE)
		task->filter.out_count--;

	fstack->flags = 0;
	task->filter.depth = fstack->orig_depth;
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

		xasprintf(&filename, "%s/%d.dat",
			  handle->dirname, handle->info.tids[idx]);

		tasks[idx].tid = handle->info.tids[idx];
		tasks[idx].fp = fopen(filename, "rb");

		if (tasks[idx].fp == NULL) {
			pr_log("cannot open task data file [%s]\n", filename);
			tasks[idx].done = true;
			return NULL;
		}

		tasks[idx].stack_count = 0;
		tasks[idx].filter.depth = handle->depth;

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

		pr_dbg("lost seen: invalidating existing stack..\n");
		fth->lost_seen = false;
	}

	fth->valid = true;
	return &fth->ustack;
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

		/* update stack count when the user stack is actually used */
		if (task->ustack.type == FTRACE_ENTRY) {
			struct fstack *fstack = &task->func_stack[task->ustack.depth];

			fstack->total_time = task->ustack.time;
			fstack->child_time = 0;
			fstack->valid = true;
			fstack->addr = task->ustack.addr;

			task->stack_count = task->rstack->depth + 1;
		} else if (task->ustack.type == FTRACE_EXIT) {
			uint64_t delta;
			struct fstack *fstack = &task->func_stack[task->ustack.depth];

			delta = task->ustack.time - fstack->total_time;

			if (!fstack->valid)
				delta = 0UL;
			fstack->valid = false;

			fstack->total_time = delta;
			if (fstack->child_time > fstack->total_time)
				fstack->child_time = fstack->total_time;

			task->stack_count = task->rstack->depth;
			if (task->stack_count > 0)
				fstack[-1].child_time += delta;

		} else if (task->ustack.type == FTRACE_LOST) {
			task->lost_seen = true;
		}

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
