#include <stdio.h>
#include <string.h>

#include "uftrace.h"
#include "utils/report.h"
#include "utils/fstack.h"
#include "utils/utils.h"

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

/* sort key support */
struct sort_key {
	const char *name;
	int (*cmp)(struct uftrace_report_node *a, struct uftrace_report_node *b);
	struct list_head list;
};

#define SORT_KEY(_name, _field)						\
static int cmp_##_name(struct uftrace_report_node *a,			\
		       struct uftrace_report_node *b)			\
{									\
	if (a->_field == b->_field)					\
		return 0;						\
	return a->_field > b->_field ? 1 : -1;				\
}									\
static struct sort_key sort_##_name = {					\
	.name = #_name,							\
	.cmp = cmp_##_name,						\
	.list = LIST_HEAD_INIT(sort_##_name.list),			\
}

SORT_KEY(total, total.sum);
SORT_KEY(total_avg, total.avg);
SORT_KEY(total_min, total.min);
SORT_KEY(total_max, total.max);
SORT_KEY(self, self.sum);
SORT_KEY(self_avg, self.avg);
SORT_KEY(self_min, self.min);
SORT_KEY(self_max, self.max);
SORT_KEY(call, call);

static struct sort_key * all_sort_keys[] = {
	&sort_total,
	&sort_total_avg,
	&sort_total_min,
	&sort_total_max,
	&sort_self,
	&sort_self_avg,
	&sort_self_min,
	&sort_self_max,
	&sort_call,
};

/* list of used sort keys */
static LIST_HEAD(sort_keys);

int report_setup_sort(const char *key_str)
{
	struct strv keys = STRV_INIT;
	char *k;
	unsigned i;
	int j;
	int count = 0;

	INIT_LIST_HEAD(&sort_keys);

	strv_split(&keys, key_str, ",");

	strv_for_each(&keys, k, j) {
		for (i = 0; i < ARRAY_SIZE(all_sort_keys); i++) {
			struct sort_key *sort_key = all_sort_keys[i];

			if (strcmp(k, sort_key->name))
				continue;

			list_add_tail(&sort_key->list, &sort_keys);
			count++;
			break;
		}

		if (i == ARRAY_SIZE(all_sort_keys))
			return -1;
	}
	strv_free(&keys);

	return count;
}

static int cmp_node(struct uftrace_report_node *a, struct uftrace_report_node *b)
{
	int ret;
	struct sort_key *key;

	list_for_each_entry(key, &sort_keys, list) {
		ret = key->cmp(a, b);
		if (ret)
			return ret;
	}
	return 0;
}

static void insert_node(struct rb_root *root, struct uftrace_report_node *node)
{
	struct uftrace_report_node *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, typeof(*iter), link);

		if (cmp_node(iter, node) < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&node->link, parent, p);
	rb_insert_color(&node->link, root);
}

void report_sort_nodes(struct rb_root *root)
{
	struct rb_root tmp = RB_ROOT;
	struct rb_node *n = rb_first(root);

	while (n && !uftrace_done) {
		struct uftrace_report_node *node;

		node = rb_entry(n, typeof(*node), link);
		rb_erase(n, root);

		insert_node(&tmp, node);
		n = rb_first(root);
	}

	*root = tmp;
}
