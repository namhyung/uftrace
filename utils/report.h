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
	unsigned long			call;
	struct rb_node			link;
};

struct uftrace_report_node * report_find_node(struct rb_root *root,
					      const char *name);
void report_add_node(struct rb_root *root, const char *name,
		     struct uftrace_report_node *node);
void report_update_node(struct uftrace_report_node *node,
			struct ftrace_task_handle *task);
void report_calc_avg(struct rb_root *root);
void report_delete_node(struct rb_root *root, struct uftrace_report_node *node);

int report_setup_sort(const char *sort_keys);
void report_sort_nodes(struct rb_root *root);

#endif /* UFTRACE_REPORT_H */
