#ifndef __FTRACE_FILTER_H__
#define __FTRACE_FILTER_H__

#include "rbtree.h"
#include "list.h"

/**
 * REGEX_CHARS: characters for regex matching.
 *
 * When one of these characters is in filter strings,
 * treat them as regex expressions.
 */
#define REGEX_CHARS  ".?*+-^$|()[]{}"

enum trigger_flag {
	TRIGGER_FL_DEPTH	= (1U << 0),
	TRIGGER_FL_FILTER	= (1U << 1),
	TRIGGER_FL_BACKTRACE	= (1U << 2),
	TRIGGER_FL_TRACE_ON	= (1U << 3),
	TRIGGER_FL_TRACE_OFF	= (1U << 4),
	TRIGGER_FL_ARGUMENT	= (1U << 5),
};

enum filter_mode {
	FILTER_MODE_NONE,
	FILTER_MODE_IN,
	FILTER_MODE_OUT,
};

struct ftrace_arg_spec {
	struct list_head	list;
	int			idx;
};

struct ftrace_trigger {
	unsigned long		flags;
	int			depth;
	enum filter_mode	fmode;
	struct list_head	*pargs;
};

struct ftrace_filter {
	struct rb_node		node;
	char 			*name;
	unsigned long		start;
	unsigned long		end;
	struct list_head	args;
	struct ftrace_trigger	trigger;
};

typedef void (*trigger_fn_t)(struct ftrace_trigger *tr, void *arg);

void ftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			 char *module, struct rb_root *root,
			 enum filter_mode *mode);
void ftrace_setup_trigger(char *trigger_str, struct symtabs *symtabs,
			  char *module, struct rb_root *root);
void ftrace_setup_argument(char *trigger_str, struct symtabs *symtabs,
			   char *module, struct rb_root *root);

struct ftrace_filter *ftrace_match_filter(struct rb_root *root, unsigned long ip,
			struct ftrace_trigger *tr);
void ftrace_cleanup_filter(struct rb_root *root);
void ftrace_print_filter(struct rb_root *root);

#endif /* __FTRACE_FILTER_H__ */
