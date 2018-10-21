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

/* diff support */
struct uftrace_diff_policy diff_policy = {
	.absolute = true,
};

struct diff_key {
	const char *name;
	int (*cmp)(struct uftrace_report_node *a, struct uftrace_report_node *b,
		   int sort_column);
	struct list_head list;
};

#define DIFF_KEY(_name, _field)						\
static inline int cmp_field_##_name(struct uftrace_report_node *a,	\
				    struct uftrace_report_node *b)	\
{									\
	if (a->_field == b->_field)					\
		return 0;						\
	return a->_field > b->_field ? 1 : -1;				\
}									\
static inline int _cmp_diff_##_name(struct uftrace_report_node *a,	\
				    struct uftrace_report_node *b)	\
{									\
	int64_t diff_a = a->pair->_field - a->_field;			\
	int64_t diff_b = b->pair->_field - b->_field;			\
									\
	if (diff_a == diff_b)						\
		return 0;						\
									\
	if (diff_policy.absolute) {					\
		diff_a = (diff_a > 0) ? diff_a : -diff_a;		\
		diff_b = (diff_b > 0) ? diff_b : -diff_b;		\
	}								\
	return diff_a > diff_b ? 1: -1;					\
}									\
static inline int cmp_pcnt_##_name(struct uftrace_report_node *a,	\
				   struct uftrace_report_node *b)	\
{									\
	int64_t diff_a = a->pair->_field - a->_field;			\
	int64_t diff_b = b->pair->_field - b->_field;			\
	double pcnt_a = 0;						\
	double pcnt_b = 0;						\
									\
	if (a->_field)							\
		pcnt_a = 100.0 * (int64_t) diff_a / a->_field;		\
	if (b->_field)							\
		pcnt_b = 100.0 * (int64_t) diff_b / b->_field;		\
									\
	if (pcnt_a == pcnt_b)						\
		return 0;						\
									\
	if (diff_policy.absolute) {					\
		pcnt_a = (pcnt_a > 0) ? pcnt_a : -pcnt_a;		\
		pcnt_b = (pcnt_b > 0) ? pcnt_b : -pcnt_b;		\
	}								\
	return pcnt_a > pcnt_b ? 1: -1;					\
}									\
static int cmp_diff_##_name(struct uftrace_report_node *a,		\
			    struct uftrace_report_node *b,		\
			    int column)					\
{									\
	if (column != 2)						\
		return cmp_field_##_name(a, b);				\
									\
	if (diff_policy.percent)					\
		return cmp_pcnt_##_name(a, b);				\
									\
	return _cmp_diff_##_name(a, b);					\
}									\
static struct diff_key sort_diff_##_name = {				\
	.name = #_name,							\
	.cmp  = cmp_diff_##_name,					\
	.list = LIST_HEAD_INIT(sort_diff_##_name.list)			\
}

DIFF_KEY(total, total.sum);
DIFF_KEY(total_avg, total.avg);
DIFF_KEY(total_min, total.min);
DIFF_KEY(total_max, total.max);
DIFF_KEY(self, self.sum);
DIFF_KEY(self_avg, self.avg);
DIFF_KEY(self_min, self.min);
DIFF_KEY(self_max, self.max);
DIFF_KEY(call, call);

static struct diff_key * all_diff_keys[] = {
	&sort_diff_total,
	&sort_diff_total_avg,
	&sort_diff_total_min,
	&sort_diff_total_max,
	&sort_diff_self,
	&sort_diff_self_avg,
	&sort_diff_self_min,
	&sort_diff_self_max,
	&sort_diff_call,
};

/* list of used sort keys for diff */
static LIST_HEAD(diff_keys);

static struct uftrace_report_node dummy_node;

int report_setup_diff(const char *key_str)
{
	struct strv keys = STRV_INIT;
	char *k;
	unsigned i;
	int j;
	int count = 0;

	INIT_LIST_HEAD(&diff_keys);

	strv_split(&keys, key_str, ",");

	strv_for_each(&keys, k, j) {
		for (i = 0; i < ARRAY_SIZE(all_diff_keys); i++) {
			struct diff_key *sort_key = all_diff_keys[i];

			if (strcmp(k, sort_key->name))
				continue;

			list_add_tail(&sort_key->list, &diff_keys);
			count++;
			break;
		}

		if (i == ARRAY_SIZE(all_diff_keys))
			return -1;
	}
	strv_free(&keys);

	return count;
}

static int cmp_diff(struct uftrace_report_node *a, struct uftrace_report_node *b,
		    int diff_column)
{
	int ret;
	struct diff_key *key;

	list_for_each_entry(key, &diff_keys, list) {
		ret = key->cmp(a, b, diff_column);
		if (ret)
			return ret;
	}
	return 0;
}

static void insert_diff(struct rb_root *root, struct uftrace_report_node *node,
			int diff_column)
{
	struct uftrace_report_node *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, typeof(*iter), link);

		if (cmp_diff(iter, node, diff_column) < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&node->link, parent, p);
	rb_insert_color(&node->link, root);
}

void report_diff_nodes(struct rb_root *orig_root, struct rb_root *pair_root,
		       struct rb_root *diff_root, int diff_column)
{
	struct rb_node *n = rb_first(orig_root);

	*diff_root = RB_ROOT;

	while (n && !uftrace_done) {
		struct uftrace_report_node *iter, *pair, *node;

		iter = rb_entry(n, typeof(*iter), link);
		pair = report_find_node(pair_root, iter->name);

		if (pair == NULL)
			pair = &dummy_node;

		/* node->name is swallow-copied, do not free */
		node = xzalloc(sizeof(*node));
		memcpy(node, iter, sizeof(*node));
		node->pair = pair;
		/* mark used pair */
		pair->pair = node;

		insert_diff(diff_root, node, diff_column);
		n = rb_next(n);
	}

	/* add non-used pair nodes */
	n = rb_first(pair_root);
	while (n && !uftrace_done) {
		struct uftrace_report_node *iter, *node;

		iter = rb_entry(n, typeof(*iter), link);
		if (iter->pair == NULL) {
			/* node->name is swallow-copied, do not free */
			node = xzalloc(sizeof(*node));
			node->name = iter->name;
			node->pair = iter;

			insert_diff(diff_root, node, diff_column);
		}
		iter->pair = NULL;

		n = rb_next(n);
	}
}

void destroy_diff_nodes(struct rb_root *diff_root)
{
	struct rb_node *n = rb_first(diff_root);
	
	while (n) {
		struct uftrace_report_node *iter;

		rb_erase(n, diff_root);
		iter = rb_entry(n, typeof(*iter), link);
		free(iter);

		n = rb_first(diff_root);
	}
}

void apply_diff_policy(char *policy)
{
	struct strv strv = STRV_INIT;
	char *p;
	int i;

	strv_split(&strv, policy, ",");

	strv_for_each(&strv, p, i) {
		bool on = true;

		if (!strncmp(p, "no-", 3)) {
			on = false;
			p += 3;
		}

		if (!strncmp(p, "abs", 3))
			diff_policy.absolute = on;
		else if (!strncmp(p, "percent", 7))
			diff_policy.percent = on;
		else if (!strncmp(p, "full", 4))
			diff_policy.full = true;
		else if (!strncmp(p, "compact", 7))
			diff_policy.full = false;
	}
	strv_free(&strv);
}
