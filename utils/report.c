#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "uftrace.h"
#include "utils/field.h"
#include "utils/fstack.h"
#include "utils/report.h"
#include "utils/utils.h"

static void init_time_stat(struct report_time_stat *ts)
{
	ts->min = -1ULL;
}

static void update_time_stat(struct report_time_stat *ts, uint64_t time_ns, bool recursive)
{
	if (recursive) {
		ts->rec += time_ns;
		ts->rec_sq += time_ns * time_ns;
	}
	else {
		ts->sum += time_ns;
		ts->sum_sq += time_ns * time_ns;
	}

	if (ts->min > time_ns)
		ts->min = time_ns;
	if (ts->max < time_ns)
		ts->max = time_ns;
}

static void finish_time_stat(struct report_time_stat *ts, unsigned long call)
{
	double variance;

	ts->avg = (ts->sum + ts->rec) / call;

	variance = (ts->sum_sq + ts->rec_sq) / call;
	variance -= ts->avg * ts->avg;

	ts->stdv = sqrt(variance / call) * 100 / ts->avg;
}

static struct uftrace_report_node *find_or_create_node(struct rb_root *root, const char *name,
						       struct uftrace_report_node *node)
{
	struct uftrace_report_node *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		int cmp;

		parent = *p;
		iter = rb_entry(parent, typeof(*iter), name_link);

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
	node->loc = NULL;
	init_time_stat(&node->total);
	init_time_stat(&node->self);

	rb_link_node(&node->name_link, parent, p);
	rb_insert_color(&node->name_link, root);

	return node;
}

struct uftrace_report_node *report_find_node(struct rb_root *root, const char *name)
{
	return find_or_create_node(root, name, NULL);
}

/* NOTE: actual allocation will be done by caller */
void report_add_node(struct rb_root *root, const char *name, struct uftrace_report_node *node)
{
	find_or_create_node(root, name, node);
}

void report_delete_node(struct rb_root *root, struct uftrace_report_node *node)
{
	rb_erase(&node->name_link, root);
	free(node->name);
	free(node);
}

void report_update_node(struct uftrace_report_node *node, struct uftrace_task_reader *task,
			struct uftrace_dbg_loc *loc)
{
	struct uftrace_fstack *fstack;
	uint64_t total_time;
	uint64_t self_time;
	bool recursive = false;
	int i;

	fstack = fstack_get(task, task->stack_count);
	if (fstack == NULL)
		return;

	for (i = 0; i < task->stack_count; i++) {
		struct uftrace_fstack *check = fstack_get(task, i);
		if (check == NULL)
			break;

		if (check->addr == fstack->addr) {
			recursive = true;
			break;
		}
	}

	total_time = fstack->total_time;
	self_time = fstack->total_time - fstack->child_time;

	update_time_stat(&node->total, total_time, recursive);
	update_time_stat(&node->self, self_time, false);
	node->call++;
	node->loc = loc;
	if (task->func != NULL)
		node->size = task->func->size;
}

void report_calc_avg(struct rb_root *root)
{
	struct uftrace_report_node *node;
	struct rb_node *n = rb_first(root);

	while (n) {
		node = rb_entry(n, typeof(*node), name_link);

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

#define SORT_KEY(_name, _field)                                                                    \
	static int cmp_##_name(struct uftrace_report_node *a, struct uftrace_report_node *b)       \
	{                                                                                          \
		if (a->_field == b->_field)                                                        \
			return 0;                                                                  \
		return a->_field > b->_field ? 1 : -1;                                             \
	}                                                                                          \
	static struct sort_key sort_##_name = {                                                    \
		.name = #_name,                                                                    \
		.cmp = cmp_##_name,                                                                \
		.list = LIST_HEAD_INIT(sort_##_name.list),                                         \
	}

SORT_KEY(total, total.sum);
SORT_KEY(total_avg, total.avg);
SORT_KEY(total_min, total.min);
SORT_KEY(total_max, total.max);
SORT_KEY(total_stdv, total.stdv);
SORT_KEY(self, self.sum);
SORT_KEY(self_avg, self.avg);
SORT_KEY(self_min, self.min);
SORT_KEY(self_max, self.max);
SORT_KEY(self_stdv, self.stdv);
SORT_KEY(call, call);
SORT_KEY(size, size);

static int cmp_func(struct uftrace_report_node *a, struct uftrace_report_node *b)
{
	return strcmp(b->name, a->name);
}

static struct sort_key sort_func = {
	.name = "func",
	.cmp = cmp_func,
	.list = LIST_HEAD_INIT(sort_func.list),
};

static struct sort_key *all_sort_keys[] = {
	&sort_total,	&sort_total_avg,  &sort_total_min, &sort_total_max, &sort_self,
	&sort_self_avg, &sort_self_min,	  &sort_self_max,  &sort_call,	    &sort_func,
	&sort_size,	&sort_total_stdv, &sort_self_stdv,
};

/* list of used sort keys */
static LIST_HEAD(sort_keys);

char *convert_sort_keys(char *sort_keys, enum avg_mode avg_mode)
{
	const char *default_sort_key[] = { OPT_SORT_KEYS, "total_avg", "self_avg" };
	struct strv keys = STRV_INIT;
	char *new_keys;
	char *k;
	int i;

	if (sort_keys == NULL)
		return xstrdup(default_sort_key[avg_mode]);

	if (avg_mode == AVG_NONE) {
		char *s;

		s = new_keys = xstrdup(sort_keys);
		while (*s) {
			if (*s == '-')
				*s = '_';
			s++;
		}

		return new_keys;
	}

	strv_split(&keys, sort_keys, ",");

	strv_for_each(&keys, k, i) {
		if (!strcmp(k, "avg")) {
			strv_replace(&keys, i, avg_mode == AVG_TOTAL ? "total_avg" : "self_avg");
		}
		else if (!strcmp(k, "min")) {
			strv_replace(&keys, i, avg_mode == AVG_TOTAL ? "total_min" : "self_min");
		}
		else if (!strcmp(k, "max")) {
			strv_replace(&keys, i, avg_mode == AVG_TOTAL ? "total_max" : "self_max");
		}
		else if (!strcmp(k, "stdv")) {
			strv_replace(&keys, i, avg_mode == AVG_TOTAL ? "total_stdv" : "self_stdv");
		}
	}

	new_keys = strv_join(&keys, ",");
	strv_free(&keys);

	return new_keys;
}

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

		if (i == ARRAY_SIZE(all_sort_keys)) {
			count = -1;
			break;
		}
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
		iter = rb_entry(parent, typeof(*iter), sort_link);

		if (cmp_node(iter, node) < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&node->sort_link, parent, p);
	rb_insert_color(&node->sort_link, root);
}

void report_sort_nodes(struct rb_root *name_root, struct rb_root *sort_root)
{
	struct rb_node *n = rb_first(name_root);

	*sort_root = RB_ROOT;

	while (n && !uftrace_done) {
		struct uftrace_report_node *node;

		/* keep node in the name tree */
		node = rb_entry(n, typeof(*node), name_link);

		insert_node(sort_root, node);
		n = rb_next(n);
	}
}

/* diff support */
struct uftrace_diff_policy diff_policy = {
	.absolute = true,
};

struct diff_key {
	const char *name;
	int (*cmp)(struct uftrace_report_node *a, struct uftrace_report_node *b, int sort_column);
	struct list_head list;
};

#define DIFF_KEY(_name, _field)                                                                    \
	static inline int cmp_field_##_name(struct uftrace_report_node *a,                         \
					    struct uftrace_report_node *b)                         \
	{                                                                                          \
		if (a->_field == b->_field)                                                        \
			return 0;                                                                  \
		return a->_field > b->_field ? 1 : -1;                                             \
	}                                                                                          \
	static inline int _cmp_diff_##_name(struct uftrace_report_node *a,                         \
					    struct uftrace_report_node *b)                         \
	{                                                                                          \
		int64_t diff_a = a->pair->_field - a->_field;                                      \
		int64_t diff_b = b->pair->_field - b->_field;                                      \
                                                                                                   \
		if (diff_a == diff_b)                                                              \
			return 0;                                                                  \
                                                                                                   \
		if (diff_policy.absolute) {                                                        \
			diff_a = (diff_a > 0) ? diff_a : -diff_a;                                  \
			diff_b = (diff_b > 0) ? diff_b : -diff_b;                                  \
		}                                                                                  \
		return diff_a > diff_b ? 1 : -1;                                                   \
	}                                                                                          \
	static inline int cmp_pcnt_##_name(struct uftrace_report_node *a,                          \
					   struct uftrace_report_node *b)                          \
	{                                                                                          \
		int64_t diff_a = a->pair->_field - a->_field;                                      \
		int64_t diff_b = b->pair->_field - b->_field;                                      \
		double pcnt_a = 0;                                                                 \
		double pcnt_b = 0;                                                                 \
                                                                                                   \
		if (a->_field)                                                                     \
			pcnt_a = 100.0 * (int64_t)diff_a / a->_field;                              \
		if (b->_field)                                                                     \
			pcnt_b = 100.0 * (int64_t)diff_b / b->_field;                              \
                                                                                                   \
		if (pcnt_a == pcnt_b)                                                              \
			return 0;                                                                  \
                                                                                                   \
		if (diff_policy.absolute) {                                                        \
			pcnt_a = (pcnt_a > 0) ? pcnt_a : -pcnt_a;                                  \
			pcnt_b = (pcnt_b > 0) ? pcnt_b : -pcnt_b;                                  \
		}                                                                                  \
		return pcnt_a > pcnt_b ? 1 : -1;                                                   \
	}                                                                                          \
	static int cmp_diff_##_name(struct uftrace_report_node *a, struct uftrace_report_node *b,  \
				    int column)                                                    \
	{                                                                                          \
		if (column != 2)                                                                   \
			return cmp_field_##_name(a, b);                                            \
                                                                                                   \
		if (diff_policy.percent)                                                           \
			return cmp_pcnt_##_name(a, b);                                             \
                                                                                                   \
		return _cmp_diff_##_name(a, b);                                                    \
	}                                                                                          \
	static struct diff_key sort_diff_##_name = { .name = #_name,                               \
						     .cmp = cmp_diff_##_name,                      \
						     .list = LIST_HEAD_INIT(                       \
							     sort_diff_##_name.list) }

DIFF_KEY(total, total.sum);
DIFF_KEY(total_avg, total.avg);
DIFF_KEY(total_min, total.min);
DIFF_KEY(total_max, total.max);
DIFF_KEY(self, self.sum);
DIFF_KEY(self_avg, self.avg);
DIFF_KEY(self_min, self.min);
DIFF_KEY(self_max, self.max);
DIFF_KEY(call, call);
DIFF_KEY(size, size);

static int cmp_diff_func(struct uftrace_report_node *a, struct uftrace_report_node *b, int column)
{
	return strcmp(b->name, a->name);
}

static struct diff_key sort_diff_func = {
	.name = "func",
	.cmp = cmp_diff_func,
	.list = LIST_HEAD_INIT(sort_diff_func.list),
};

static struct diff_key *all_diff_keys[] = {
	&sort_diff_total, &sort_diff_total_avg, &sort_diff_total_min, &sort_diff_total_max,
	&sort_diff_self,  &sort_diff_self_avg,	&sort_diff_self_min,  &sort_diff_self_max,
	&sort_diff_call,  &sort_diff_func,	&sort_diff_size
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

		if (i == ARRAY_SIZE(all_diff_keys)) {
			count = -1;
			break;
		}
	}
	strv_free(&keys);

	return count;
}

static int cmp_diff(struct uftrace_report_node *a, struct uftrace_report_node *b, int diff_column)
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

static void insert_diff(struct rb_root *root, struct uftrace_report_node *node, int diff_column)
{
	struct uftrace_report_node *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, typeof(*iter), sort_link);

		if (cmp_diff(iter, node, diff_column) < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&node->sort_link, parent, p);
	rb_insert_color(&node->sort_link, root);
}

void report_diff_nodes(struct rb_root *orig_root, struct rb_root *pair_root,
		       struct rb_root *diff_root, int diff_column)
{
	struct rb_node *n = rb_first(orig_root);

	*diff_root = RB_ROOT;

	while (n && !uftrace_done) {
		struct uftrace_report_node *iter, *pair, *node;

		iter = rb_entry(n, typeof(*iter), name_link);
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

		iter = rb_entry(n, typeof(*iter), name_link);
		if (iter->pair == NULL) {
			/* node->name is swallow-copied, do not free */
			node = xzalloc(sizeof(*node));
			node->name = iter->name;
			node->pair = iter;

			insert_diff(diff_root, node, diff_column);
		}

		n = rb_next(n);
	}
}

void destroy_diff_nodes(struct rb_root *orig_root, struct rb_root *pair_root)
{
	struct rb_node *n;
	struct uftrace_report_node *iter;

	n = rb_first(orig_root);
	while (n) {
		iter = rb_entry(n, typeof(*iter), name_link);
		n = rb_next(n);

		/* name is already freed in print_and_delete */
		rb_erase(&iter->name_link, orig_root);
		free(iter);
	}

	n = rb_first(pair_root);
	while (n) {
		iter = rb_entry(n, typeof(*iter), name_link);
		n = rb_next(n);

		rb_erase(&iter->name_link, pair_root);
		/* if it has a pair, only base name was freed */
		if (iter->pair)
			free(iter->name);
		free(iter);
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

/* task sort key support */
struct sort_task_key {
	const char *name;
	int (*cmp)(struct uftrace_data *handle, struct uftrace_report_node *a,
		   struct uftrace_report_node *b);
	struct list_head list;
};

#define TASK_KEY(_name, _field)                                                                    \
	static int task_cmp_##_name(struct uftrace_data *handle, struct uftrace_report_node *a,    \
				    struct uftrace_report_node *b)                                 \
	{                                                                                          \
		if (a->_field == b->_field)                                                        \
			return 0;                                                                  \
		return a->_field > b->_field ? 1 : -1;                                             \
	}                                                                                          \
	static struct sort_task_key task_##_name = {                                               \
		.name = #_name,                                                                    \
		.cmp = task_cmp_##_name,                                                           \
		.list = LIST_HEAD_INIT(task_##_name.list),                                         \
	}

TASK_KEY(total, total.sum);
TASK_KEY(self, self.sum);
TASK_KEY(func, call);

static int cmp_task_tid(struct uftrace_data *handle, struct uftrace_report_node *a,
			struct uftrace_report_node *b)
{
	return strcmp(b->name, a->name);
}

static struct sort_task_key task_tid = {
	.name = "tid",
	.cmp = cmp_task_tid,
	.list = LIST_HEAD_INIT(task_tid.list),
};

static int cmp_task_name(struct uftrace_data *handle, struct uftrace_report_node *a,
			 struct uftrace_report_node *b)
{
	int tid_a = strtol(a->name, NULL, 0);
	int tid_b = strtol(b->name, NULL, 0);
	struct uftrace_task *task_a = find_task(&handle->sessions, tid_a);
	struct uftrace_task *task_b = find_task(&handle->sessions, tid_b);

	if (task_a == NULL || task_b == NULL)
		return !task_a ? (!task_b ? 0 : 1) : -1;

	return strcmp(task_b->comm, task_a->comm);
}

static struct sort_task_key task_name = {
	.name = "name",
	.cmp = cmp_task_name,
	.list = LIST_HEAD_INIT(task_name.list),
};

static struct sort_task_key *all_task_keys[] = {
	&task_total, &task_self, &task_tid, &task_func, &task_name,
};

/* list of used sort keys for diff */
static LIST_HEAD(task_keys);

int report_setup_task(const char *key_str)
{
	struct strv keys = STRV_INIT;
	char *k;
	unsigned i;
	int j;
	int count = 0;

	INIT_LIST_HEAD(&task_keys);

	strv_split(&keys, key_str, ",");

	strv_for_each(&keys, k, j) {
		for (i = 0; i < ARRAY_SIZE(all_task_keys); i++) {
			struct sort_task_key *sort_key = all_task_keys[i];

			if (strcmp(k, sort_key->name))
				continue;

			list_add_tail(&sort_key->list, &task_keys);
			count++;
			break;
		}

		if (i == ARRAY_SIZE(all_task_keys)) {
			count = -1;
			break;
		}
	}
	strv_free(&keys);

	return count;
}

static int cmp_task(struct uftrace_data *handle, struct uftrace_report_node *a,
		    struct uftrace_report_node *b)
{
	int ret;
	struct sort_task_key *key;

	list_for_each_entry(key, &task_keys, list) {
		ret = key->cmp(handle, a, b);
		if (ret)
			return ret;
	}
	return 0;
}

static void insert_task(struct uftrace_data *handle, struct rb_root *root,
			struct uftrace_report_node *node)
{
	struct uftrace_report_node *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, typeof(*iter), sort_link);

		if (cmp_task(handle, iter, node) < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&node->sort_link, parent, p);
	rb_insert_color(&node->sort_link, root);
}

void report_sort_tasks(struct uftrace_data *handle, struct rb_root *name_root,
		       struct rb_root *sort_root)
{
	struct rb_node *n = rb_first(name_root);

	*sort_root = RB_ROOT;

	while (n && !uftrace_done) {
		struct uftrace_report_node *node;

		/* keep node in the name tree */
		node = rb_entry(n, typeof(*node), name_link);

		insert_task(handle, sort_root, node);
		n = rb_next(n);
	}
}

#define FIELD_STRUCT(_id, _name, _func, _header, _length)                                          \
	static struct display_field field_##_func = { .id = _id,                                   \
						      .name = #_name,                              \
						      .header = _header,                           \
						      .length = _length,                           \
						      .print = print_##_func,                      \
						      .list = LIST_HEAD_INIT(                      \
							      field_##_func.list) };

#define FIELD_TIME(_id, _name, _field, _func, _header)                                             \
	static void print_##_func(struct field_data *fd)                                           \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		print_time_unit(node->_field);                                                     \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func, _header, 10)

#define FIELD_UINT(_id, _name, _field, _func, _header)                                             \
	static void print_##_func(struct field_data *fd)                                           \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		pr_out("%10" PRIu64 "", node->_field);                                             \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func, _header, 10)

#define FIELD_PERCENTAGE(_id, _name, _field, _func, _header)                                       \
	static void print_##_func(struct field_data *fd)                                           \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		pr_out("%9.2f%%", node->_field);                                                   \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func, _header, 10)

#define FIELD_TIME_DIFF(_id, _name, _field, _func, _header)                                        \
	static void print_##_func##_diff(struct field_data *fd)                                    \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		struct uftrace_report_node *pair = node->pair;                                     \
		if (diff_policy.percent) {                                                         \
			pr_out("   ");                                                             \
			print_diff_percent(node->_field, pair->_field);                            \
		}                                                                                  \
		else {                                                                             \
			print_diff_time_unit(node->_field, pair->_field);                          \
		}                                                                                  \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func##_diff, _header, 11)

#define FIELD_UINT_DIFF(_id, _name, _field, _func, _header)                                        \
	static void print_##_func##_diff(struct field_data *fd)                                    \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		struct uftrace_report_node *pair = node->pair;                                     \
		pr_out("  ");                                                                      \
		print_diff_count(node->_field, pair->_field);                                      \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func##_diff, _header, 11)

#define FIELD_PERCENT_DIFF(_id, _name, _field, _func, _header)                                     \
	static void print_##_func##_diff(struct field_data *fd)                                    \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		struct uftrace_report_node *pair = node->pair;                                     \
		pr_out(" ");                                                                       \
		print_diff_percent_point(node->_field, pair->_field);                              \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func##_diff, _header, 11)

#define FIELD_TIME_DIFF_FULL(_id, _name, _field, _func, _header)                                   \
	static void print_##_func##_diff_full(struct field_data *fd)                               \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		struct uftrace_report_node *pair = node->pair;                                     \
		print_time_or_dash(node->_field);                                                  \
		pr_out("  ");                                                                      \
		print_time_or_dash(pair->_field);                                                  \
		pr_out("  ");                                                                      \
		print_diff_time_unit(node->_field, pair->_field);                                  \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func##_diff_full, _header, 35)

#define FIELD_UINT_DIFF_FULL(_id, _name, _field, _func, _header)                                   \
	static void print_##_func(struct field_data *fd)                                           \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		struct uftrace_report_node *pair = node->pair;                                     \
		pr_out(" %9" PRIu64 "  %9" PRIu64, node->_field, pair->_field);                    \
		pr_out("  ");                                                                      \
		print_diff_count(node->_field, pair->_field);                                      \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func, _header, 32)

#define FIELD_PERCENT_DIFF_FULL(_id, _name, _field, _func, _header)                                \
	static void print_##_func##_diff_full(struct field_data *fd)                               \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		struct uftrace_report_node *pair = node->pair;                                     \
		pr_out("%9.2f%%", node->_field);                                                   \
		pr_out(" ");                                                                       \
		pr_out("%9.2f%%", pair->_field);                                                   \
		pr_out(" ");                                                                       \
		print_diff_percent_point(node->_field, pair->_field);                              \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func##_diff_full, _header, 32)

#define FIELD_TIME_DIFF_FULL_PCT(_id, _name, _field, _func, _header)                               \
	static void print_##_func##_diff_full_percent(struct field_data *fd)                       \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		struct uftrace_report_node *pair = node->pair;                                     \
		print_time_or_dash(node->_field);                                                  \
		pr_out("  ");                                                                      \
		print_time_or_dash(pair->_field);                                                  \
		pr_out("  ");                                                                      \
		print_diff_percent(node->_field, pair->_field);                                    \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func##_diff_full_percent, _header, 32)

#define FIELD_TID(_id, _name, _func, _header)                                                      \
	static void print_##_func(struct field_data *fd)                                           \
	{                                                                                          \
		struct uftrace_report_node *node = fd->arg;                                        \
		pr_out("%*d", TASK_ID_LEN, strtol(node->name, NULL, 10));                          \
	}                                                                                          \
	FIELD_STRUCT(_id, _name, _func, _header, TASK_ID_LEN)

#define NODATA "-"
static void print_time_or_dash(uint64_t time_nsec)
{
	if (time_nsec)
		print_time_unit(time_nsec);
	else
		pr_out("%10s", NODATA);
}

/* clang-format off */
FIELD_TIME(REPORT_F_TOTAL_TIME, total, total.sum, total, "Total time");
FIELD_TIME(REPORT_F_TOTAL_TIME_AVG, total-avg, total.avg, total_avg, "Total avg");
FIELD_TIME(REPORT_F_TOTAL_TIME_MIN, total-min, total.min, total_min, "Total min");
FIELD_TIME(REPORT_F_TOTAL_TIME_MAX, total-max, total.max, total_max, "Total max");
FIELD_TIME(REPORT_F_SELF_TIME, self, self.sum, self, "Self time");
FIELD_TIME(REPORT_F_SELF_TIME_AVG, self-avg, self.avg, self_avg, "Self avg");
FIELD_TIME(REPORT_F_SELF_TIME_MIN, self-min, self.min, self_min, "Self min");
FIELD_TIME(REPORT_F_SELF_TIME_MAX, self-max, self.max, self_max, "Self max");
FIELD_UINT(REPORT_F_CALL, call, call, call, "Calls");
FIELD_UINT(REPORT_F_SIZE, size, size, size, "Size");
FIELD_PERCENTAGE(REPORT_F_TOTAL_TIME_STDV, total-stdv, total.stdv, total_stdv, "Total stdv");
FIELD_PERCENTAGE(REPORT_F_SELF_TIME_STDV, self-stdv, self.stdv, self_stdv, "Self stdv");

FIELD_TIME_DIFF(REPORT_F_TOTAL_TIME, total, total.sum, total, "Total time");
FIELD_TIME_DIFF(REPORT_F_TOTAL_TIME_AVG, total-avg, total.avg, total_avg, "Total avg");
FIELD_TIME_DIFF(REPORT_F_TOTAL_TIME_MIN, total-min, total.min, total_min, "Total min");
FIELD_TIME_DIFF(REPORT_F_TOTAL_TIME_MAX, total-max, total.max, total_max, "Total max");
FIELD_TIME_DIFF(REPORT_F_SELF_TIME, self, self.sum, self, "Self time");
FIELD_TIME_DIFF(REPORT_F_SELF_TIME_AVG, self-avg, self.avg, self_avg, "Self avg");
FIELD_TIME_DIFF(REPORT_F_SELF_TIME_MIN, self-min, self.min, self_min, "Self min");
FIELD_TIME_DIFF(REPORT_F_SELF_TIME_MAX, self-max, self.max, self_max, "Self max");
FIELD_UINT_DIFF(REPORT_F_CALL, call, call, call, "Calls");
FIELD_UINT_DIFF(REPORT_F_SIZE, size, size, size, "Size");
FIELD_PERCENT_DIFF(REPORT_F_TOTAL_TIME_STDV, total-stdv, total.stdv, total_stdv, "Total stdv");
FIELD_PERCENT_DIFF(REPORT_F_SELF_TIME_STDV, self-stdv, self.stdv, self_stdv, "Self stdv");

FIELD_TIME_DIFF_FULL(REPORT_F_TOTAL_TIME, total, total.sum, total, "Total time (diff)");
FIELD_TIME_DIFF_FULL(REPORT_F_TOTAL_TIME_AVG, total-avg, total.avg, total_avg, "Total avg (diff)");
FIELD_TIME_DIFF_FULL(REPORT_F_TOTAL_TIME_MIN, total-min, total.min, total_min, "Total min (diff)");
FIELD_TIME_DIFF_FULL(REPORT_F_TOTAL_TIME_MAX, total-max, total.max, total_max, "Total max (diff)");
FIELD_TIME_DIFF_FULL(REPORT_F_SELF_TIME, self, self.sum, self, "Self time (diff)");
FIELD_TIME_DIFF_FULL(REPORT_F_SELF_TIME_AVG, self-avg, self.avg, self_avg, "Self avg (diff)");
FIELD_TIME_DIFF_FULL(REPORT_F_SELF_TIME_MIN, self-min, self.min, self_min, "Self min (diff)");
FIELD_TIME_DIFF_FULL(REPORT_F_SELF_TIME_MAX, self-max, self.max, self_max, "Self min (diff)");
FIELD_UINT_DIFF_FULL(REPORT_F_CALL, call, call, call_diff_full, "Calls (diff)");
FIELD_UINT_DIFF_FULL(REPORT_F_SIZE, size, size, size_diff_full, "Size (diff)");
FIELD_PERCENT_DIFF_FULL(REPORT_F_TOTAL_TIME_STDV, total-stdv, total.stdv, total_stdv, "Total stdv (diff)");
FIELD_PERCENT_DIFF_FULL(REPORT_F_SELF_TIME_STDV, self-stdv, self.stdv, self_stdv, "Self stdv (diff)");

FIELD_TIME_DIFF_FULL_PCT(REPORT_F_TOTAL_TIME, total, total.sum, total, "Total time (diff)");
FIELD_TIME_DIFF_FULL_PCT(REPORT_F_TOTAL_TIME_AVG, total-avg, total.avg, total_avg, "Total avg (diff)");
FIELD_TIME_DIFF_FULL_PCT(REPORT_F_TOTAL_TIME_MIN, total-min, total.min, total_min, "Total min (diff)");
FIELD_TIME_DIFF_FULL_PCT(REPORT_F_TOTAL_TIME_MAX, total-max, total.max, total_max, "Total max (diff)");
FIELD_TIME_DIFF_FULL_PCT(REPORT_F_SELF_TIME, self, self.sum, self, "Self time (diff)");
FIELD_TIME_DIFF_FULL_PCT(REPORT_F_SELF_TIME_AVG, self-avg, self.avg, self_avg, "Self avg (diff)");
FIELD_TIME_DIFF_FULL_PCT(REPORT_F_SELF_TIME_MIN, self-min, self.min, self_min, "Self min (diff)");
FIELD_TIME_DIFF_FULL_PCT(REPORT_F_SELF_TIME_MAX, self-max, self.max, self_max, "Self min (diff)");
FIELD_UINT_DIFF_FULL(REPORT_F_CALL, call, call, call_diff_full_percent, "Calls (diff)");
FIELD_UINT_DIFF_FULL(REPORT_F_SIZE, size, size, size_diff_full_percent, "Size (diff)");
// reused FIELD_PERCENT_DIFF_FULL for total-stdv and self-stdv

FIELD_TIME(REPORT_F_TASK_TOTAL_TIME, total, total.sum, task_total, "Total time");
FIELD_TIME(REPORT_F_TASK_SELF_TIME, self, self.sum, task_self, "Self time");
FIELD_TID(REPORT_F_TASK_TID, tid, task_tid, "TID");
FIELD_UINT(REPORT_F_TASK_NR_FUNC, func, call, task_nr_func, "Num funcs");
/* clang-format on */

/* index of this table should be matched to display_field_id */
static struct display_field *field_table[] = {
	&field_total, &field_total_avg, &field_total_min,  &field_total_max,
	&field_self,  &field_self_avg,	&field_self_min,   &field_self_max,
	&field_call,  &field_size,	&field_total_stdv, &field_self_stdv,
};

/* index of this table should be matched to display_field_id */
static struct display_field *field_diff_table[] = {
	&field_total_diff, &field_total_avg_diff, &field_total_min_diff,  &field_total_max_diff,
	&field_self_diff,  &field_self_avg_diff,  &field_self_min_diff,	  &field_self_max_diff,
	&field_call_diff,  &field_size_diff,	  &field_total_stdv_diff, &field_self_stdv_diff,
};

/* index of this table should be matched to display_field_id */
static struct display_field *field_diff_full_table[] = {
	&field_total_diff_full,	    &field_total_avg_diff_full,	 &field_total_min_diff_full,
	&field_total_max_diff_full, &field_self_diff_full,	 &field_self_avg_diff_full,
	&field_self_min_diff_full,  &field_self_max_diff_full,	 &field_call_diff_full,
	&field_size_diff_full,	    &field_total_stdv_diff_full, &field_self_stdv_diff_full,
};

/* index of this table should be matched to display_field_id */
static struct display_field *field_diff_full_percent_table[] = {
	&field_total_diff_full_percent,	    &field_total_avg_diff_full_percent,
	&field_total_min_diff_full_percent, &field_total_max_diff_full_percent,
	&field_self_diff_full_percent,	    &field_self_avg_diff_full_percent,
	&field_self_min_diff_full_percent,  &field_self_max_diff_full_percent,
	&field_call_diff_full_percent,	    &field_size_diff_full_percent,
	&field_total_stdv_diff_full,	    &field_self_stdv_diff_full,
};

/* index of this table should be matched to display_field_id */
static struct display_field *field_task_table[] = {
	&field_task_total,
	&field_task_self,
	&field_task_tid,
	&field_task_nr_func,
};

static void setup_default_field(struct list_head *fields, struct uftrace_opts *opts,
				struct display_field *p_field_table[])
{
	add_field(fields, p_field_table[REPORT_F_TOTAL_TIME]);
	add_field(fields, p_field_table[REPORT_F_SELF_TIME]);
	add_field(fields, p_field_table[REPORT_F_CALL]);
}

static void setup_avg_total_field(struct list_head *fields, struct uftrace_opts *opts,
				  struct display_field *p_field_table[])
{
	add_field(fields, p_field_table[REPORT_F_TOTAL_TIME_AVG]);
	add_field(fields, p_field_table[REPORT_F_TOTAL_TIME_MIN]);
	add_field(fields, p_field_table[REPORT_F_TOTAL_TIME_MAX]);
	add_field(fields, p_field_table[REPORT_F_TOTAL_TIME_STDV]);
}

static void setup_avg_self_field(struct list_head *fields, struct uftrace_opts *opts,
				 struct display_field *p_field_table[])
{
	add_field(fields, p_field_table[REPORT_F_SELF_TIME_AVG]);
	add_field(fields, p_field_table[REPORT_F_SELF_TIME_MIN]);
	add_field(fields, p_field_table[REPORT_F_SELF_TIME_MAX]);
	add_field(fields, p_field_table[REPORT_F_SELF_TIME_STDV]);
}

static void setup_default_task_field(struct list_head *fields, struct uftrace_opts *opts,
				     struct display_field *p_field_table[])
{
	add_field(fields, p_field_table[REPORT_F_TASK_TOTAL_TIME]);
	add_field(fields, p_field_table[REPORT_F_TASK_SELF_TIME]);
	add_field(fields, p_field_table[REPORT_F_TASK_TID]);
	add_field(fields, p_field_table[REPORT_F_TASK_NR_FUNC]);
}

void setup_report_field(struct list_head *output_fields, struct uftrace_opts *opts,
			enum avg_mode avg_mode)
{
	struct display_field **f_table;
	int table_size;
	setup_default_field_t fn[] = { &setup_default_field, &setup_avg_total_field,
				       &setup_avg_self_field };

	if (opts->show_task) {
		setup_field(output_fields, opts, setup_default_task_field, field_task_table,
			    ARRAY_SIZE(field_task_table));
		return;
	}

	if (opts->diff) {
		if (opts->diff_policy && diff_policy.full) {
			if (diff_policy.percent) {
				f_table = field_diff_full_percent_table;
				table_size = ARRAY_SIZE(field_diff_full_percent_table);
			}
			else {
				f_table = field_diff_full_table;
				table_size = ARRAY_SIZE(field_diff_full_table);
			}
		}
		else {
			f_table = field_diff_table;
			table_size = ARRAY_SIZE(field_diff_table);
		}
	}
	else {
		f_table = field_table;
		table_size = ARRAY_SIZE(field_table);
	}

	setup_field(output_fields, opts, fn[avg_mode], f_table, table_size);
}

#ifdef UNIT_TEST

#define TEST_NODES 3

TEST_CASE(report_find)
{
	struct rb_root root = RB_ROOT;
	struct rb_node *rbnode;
	struct uftrace_report_node *node;
	const char *test_name[TEST_NODES] = { "abc", "foo", "bar" };
	const char *name_sort[TEST_NODES] = { "abc", "bar", "foo" };
	int i;

	pr_dbg("add report node in an arbitrary order\n");
	for (i = 0; i < TEST_NODES; i++) {
		node = xzalloc(sizeof(*node));
		report_add_node(&root, test_name[i], node);
	}

	pr_dbg("find report node by name\n");
	for (i = 0; i < TEST_NODES; i++) {
		node = report_find_node(&root, test_name[i]);
		TEST_NE(node, NULL);
		TEST_STREQ(node->name, test_name[i]);
	}

	pr_dbg("check the tree was sorted by name\n");
	i = 0;
	while (!RB_EMPTY_ROOT(&root)) {
		rbnode = rb_first(&root);
		node = rb_entry(rbnode, typeof(*node), name_link);
		TEST_STREQ(node->name, name_sort[i++]);
		report_delete_node(&root, node);
	}
	TEST_EQ(i, 3);

	return TEST_OK;
}

TEST_CASE(report_sort)
{
	struct rb_root name_tree = RB_ROOT;
	struct rb_root sort_tree = RB_ROOT;
	struct rb_node *rbnode;
	struct uftrace_report_node *node;
	static struct uftrace_fstack fstack[TEST_NODES];
	struct uftrace_data handle = {
		.hdr = {
			.max_stack = TEST_NODES,
		},
		.nr_tasks = 1,
	};
	struct uftrace_task_reader task = {
		.h = &handle,
		.func_stack = fstack,
	};
	int i;

	const char *test_name[] = { "abc", "foo", "bar" };
	uint64_t total_times[TEST_NODES] = {
		1000,
		600,
		2300,
	};
	uint64_t child_times[TEST_NODES] = {
		700,
		0,
		2100,
	};
	int total_order[TEST_NODES] = { 2, 0, 1 };
	int self_order[TEST_NODES] = { 1, 0, 2 };

	pr_dbg("setup fstack manually\n");
	for (i = 0; i < TEST_NODES; i++) {
		fstack[i].addr = i;
		fstack[i].total_time = total_times[i];
		fstack[i].child_time = child_times[i];
	}

	for (i = 0; i < TEST_NODES; i++) {
		node = xzalloc(sizeof(*node));
		report_add_node(&name_tree, test_name[i], node);
		report_update_node(node, &task, NULL);
		task.stack_count++;
	}
	report_calc_avg(&name_tree);

	TEST_LT(report_setup_sort("foobar"), 0);
	TEST_EQ(report_setup_sort("total"), 1);
	report_sort_nodes(&name_tree, &sort_tree);
	pr_dbg("sort report result with: total\n");

	i = 0;
	rbnode = rb_first(&sort_tree);
	while (rbnode != NULL) {
		node = rb_entry(rbnode, typeof(*node), sort_link);

		TEST_STREQ(node->name, test_name[total_order[i]]);
		TEST_EQ(node->total.sum, total_times[total_order[i]]);
		TEST_EQ(node->call, 1);
		pr_dbg("[%d] %s: %5" PRIu64 ", %" PRIu64 "\n", i, node->name, node->total.sum,
		       node->call);

		rbnode = rb_next(rbnode);
		i++;
	}

	TEST_EQ(report_setup_sort("call,self_avg"), 2);
	report_sort_nodes(&name_tree, &sort_tree);
	pr_dbg("sort report result with: call, self_avg\n");

	i = 0;
	rbnode = rb_first(&sort_tree);
	while (rbnode != NULL) {
		int idx = self_order[i];
		uint64_t self_time = total_times[idx] - child_times[idx];

		node = rb_entry(rbnode, typeof(*node), sort_link);

		TEST_STREQ(node->name, test_name[idx]);
		TEST_EQ(node->self.avg, self_time);
		TEST_EQ(node->self.min, self_time);
		TEST_EQ(node->self.max, self_time);
		pr_dbg("[%d] %s: %" PRIu64 ", %5" PRIu64 "\n", i, node->name, node->call,
		       node->self.avg);

		rbnode = rb_next(rbnode);
		i++;
	}

	while (!RB_EMPTY_ROOT(&name_tree)) {
		rbnode = rb_first(&name_tree);
		node = rb_entry(rbnode, typeof(*node), name_link);

		rb_erase(&node->sort_link, &sort_tree);
		report_delete_node(&name_tree, node);
	}
	TEST_EQ(RB_EMPTY_ROOT(&sort_tree), true);

	return TEST_OK;
}

TEST_CASE(report_diff)
{
	struct rb_root orig_tree = RB_ROOT;
	struct rb_root pair_tree = RB_ROOT;
	struct rb_root diff_tree = RB_ROOT;
	struct rb_node *rbnode;
	struct uftrace_report_node *node;
	int i;

	struct uftrace_data handle = {
		.hdr = {
			.max_stack = TEST_NODES,
		},
		.nr_tasks = 2,
	};
	struct uftrace_fstack orig_fstack[TEST_NODES];
	struct uftrace_task_reader orig_task = {
		.h = &handle,
		.func_stack = orig_fstack,
	};
	struct uftrace_fstack pair_fstack[TEST_NODES];
	struct uftrace_task_reader pair_task = {
		.h = &handle,
		.func_stack = pair_fstack,
	};

	const char *orig_name[] = { "abc", "foo", "bar" };
	uint64_t orig_total_times[TEST_NODES] = {
		100,
		1600,
		2300,
	};
	uint64_t orig_child_times[TEST_NODES] = {
		50,
		800,
		2100,
	};
	const char *pair_name[] = { "xyz", "foo", "bar" };
	uint64_t pair_total_times[TEST_NODES] = {
		150,
		2500,
		2000,
	};
	uint64_t pair_child_times[TEST_NODES] = {
		70,
		1800,
		300,
	};
	int diff_order[] = { 1, -1, 0, 2 };
	int diff_total[] = { 900, 150, -100, -300 };

	TEST_EQ(diff_policy.absolute, true);

	pr_dbg("diff policy = %s\n", "no-abs, compact, no-percent");
	apply_diff_policy("no-abs,compact,no-percent");

	TEST_EQ(diff_policy.absolute, false);
	TEST_EQ(diff_policy.full, false);
	TEST_EQ(diff_policy.percent, false);

	TEST_EQ(report_setup_diff("total,self"), 2);
	pr_dbg("report diff sorted by: total, self\n");

	for (i = 0; i < TEST_NODES; i++) {
		orig_fstack[i].addr = i;
		orig_fstack[i].total_time = orig_total_times[i];
		orig_fstack[i].child_time = orig_child_times[i];

		node = xzalloc(sizeof(*node));
		report_add_node(&orig_tree, orig_name[i], node);
		report_update_node(node, &orig_task, NULL);
		orig_task.stack_count++;
	}
	report_calc_avg(&orig_tree);

	for (i = 0; i < TEST_NODES; i++) {
		pair_fstack[i].addr = i;
		pair_fstack[i].total_time = pair_total_times[i];
		pair_fstack[i].child_time = pair_child_times[i];

		node = xzalloc(sizeof(*node));
		report_add_node(&pair_tree, pair_name[i], node);
		report_update_node(node, &pair_task, NULL);
		pair_task.stack_count++;
	}
	report_calc_avg(&pair_tree);

	report_diff_nodes(&orig_tree, &pair_tree, &diff_tree, 2);
	TEST_EQ(RB_EMPTY_ROOT(&diff_tree), false);

	i = 0;
	rbnode = rb_first(&diff_tree);
	while (rbnode != NULL) {
		int idx = diff_order[i];

		node = rb_entry(rbnode, typeof(*node), sort_link);
		rbnode = rb_next(rbnode);

		if (idx >= 0)
			TEST_STREQ(node->name, orig_name[idx]);
		else
			TEST_STREQ(node->name, pair_name[-idx - 1]);

		TEST_EQ(node->pair->total.sum - node->total.sum, diff_total[i]);
		pr_dbg("[%d] %s, %5" PRId64 "\n", i, node->name, diff_total[i]);

		rb_erase(&node->sort_link, &diff_tree);
		free(node->name);
		free(node);

		i++;
	}
	TEST_EQ(i, 4);

	destroy_diff_nodes(&orig_tree, &pair_tree);
	TEST_EQ(RB_EMPTY_ROOT(&orig_tree), true);
	TEST_EQ(RB_EMPTY_ROOT(&pair_tree), true);
	TEST_EQ(RB_EMPTY_ROOT(&diff_tree), true);

	return TEST_OK;
}

#endif /* UNIT_TEST */
