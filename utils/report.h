#ifndef UFTRACE_REPORT_H
#define UFTRACE_REPORT_H

#include <stdint.h>
#include <stdbool.h>

#include "uftrace.h"
#include "utils/rbtree.h"

struct sym;

struct report_time_stat {
	uint64_t	sum;
	uint64_t	rec;  /* time in recursive call */
	uint64_t	avg;
	uint64_t	min;
	uint64_t	max;
};

struct uftrace_report_node {
	char				*name;
	struct report_time_stat 	total;
	struct report_time_stat 	self;
	struct debug_location		*loc;
	uint64_t			call;
	struct rb_node			name_link;
	struct rb_node			sort_link;

	/* used by diff */
	struct uftrace_report_node	*pair;
};

struct uftrace_diff_policy {
	/* show percentage rather than value of diff */
	bool percent;

	/* calculate diff using absolute values */
	bool absolute;

	/* show original data as well as difference */
	bool full;
};

extern struct uftrace_diff_policy diff_policy;

struct uftrace_report_node * report_find_node(struct rb_root *root,
					      const char *name);
void report_add_node(struct rb_root *root, const char *name,
		     struct uftrace_report_node *node);
void report_update_node(struct uftrace_report_node *node,
			struct uftrace_task_reader *task,
			struct debug_location *loc);
void report_calc_avg(struct rb_root *root);
void report_delete_node(struct rb_root *root, struct uftrace_report_node *node);

int report_setup_sort(const char *sort_keys);
void report_sort_nodes(struct rb_root *name_root, struct rb_root *sort_root);

int report_setup_diff(const char *key_str);
void report_diff_nodes(struct rb_root *orig_root, struct rb_root *pair_root,
		       struct rb_root *diff_root, int diff_column);
void destroy_diff_nodes(struct rb_root *diff_root);
void apply_diff_policy(char *policy);

int report_setup_task(const char *key_str);
void report_sort_tasks(struct uftrace_data *handle, struct rb_root *name_root,
		       struct rb_root *sort_root);

#endif /* UFTRACE_REPORT_H */
