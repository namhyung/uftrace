#include <stdio.h>
#include <string.h>

#include "uftrace.h"
#include "utils/report.h"
#include "utils/fstack.h"

static void init_time_stat(struct report_time_stat *ts)
{
	ts->min = -1ULL;
}

static void update_time_stat(struct report_time_stat *ts, uint64_t time_ns,
			     bool recursive)
{
	if (recursive)
		ts->rec += time_ns;
	else
		ts->sum += time_ns;

	if (ts->min > time_ns)
		ts->min = time_ns;
	if (ts->max < time_ns)
		ts->max = time_ns;
}

static void finish_time_stat(struct report_time_stat *ts, unsigned long call)
{
	ts->avg = (ts->sum + ts->rec) / call;
}

static struct uftrace_report_node *
find_or_create_node(struct rb_root *root, const char *name,
		    struct uftrace_report_node *node)
{
	struct uftrace_report_node *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		int cmp;

		parent = *p;
		iter = rb_entry(parent, typeof(*iter), link);

		cmp = strcmp(iter->name, name);
		if (cmp == 0)
			return iter;

		if (cmp > 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	if (node == NULL)
		return NULL;

	node->name = xstrdup(name);
	init_time_stat(&node->total);
	init_time_stat(&node->self);

	rb_link_node(&node->link, parent, p);
	rb_insert_color(&node->link, root);

	return node;
}

struct uftrace_report_node * report_find_node(struct rb_root *root,
					      const char *name)
{
	return find_or_create_node(root, name, NULL);
}

/* NOTE: actual allocation will be done by caller */
void report_add_node(struct rb_root *root, const char *name,
		     struct uftrace_report_node *node)
{
	find_or_create_node(root, name, node);
}

/* NOTE: this function does not free 'node' itself */
void report_delete_node(struct rb_root *root, struct uftrace_report_node *node)
{
	rb_erase(&node->link, root);
	free(node->name);
}

void report_update_node(struct uftrace_report_node *node,
			struct ftrace_task_handle *task)
{
	struct fstack *fstack = &task->func_stack[task->stack_count];
	uint64_t total_time = fstack->total_time;
	uint64_t self_time = fstack->total_time - fstack->child_time;
	bool recursive = false;
	int i;

	for (i = 0; i < task->stack_count; i++) {
		if (task->func_stack[i].addr == fstack->addr) {
			recursive = true;
			break;
		}
	}

	update_time_stat(&node->total, total_time, recursive);
	update_time_stat(&node->self, self_time, false);
	node->call++;
}

void report_calc_avg(struct rb_root *root)
{
	struct uftrace_report_node *node;
	struct rb_node *n = rb_first(root);

	while (n) {
		node = rb_entry(n, typeof(*node), link);

		finish_time_stat(&node->total, node->call);
		finish_time_stat(&node->self, node->call);

		n = rb_next(n);
	}
}
