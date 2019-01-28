#ifndef UFTRACE_AUTO_ARGS_H
#define UFTRACE_AUTO_ARGS_H

#include "utils/list.h"
#include "utils/rbtree.h"

struct enum_def {
	char *name;
	struct list_head vals;
	struct rb_node node;
};

struct enum_val {
	struct list_head list;
	char *str;
	long val;
};

#endif
