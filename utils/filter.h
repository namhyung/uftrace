#ifndef __FTRACE_FILTER_H__
#define __FTRACE_FILTER_H__

#include "rbtree.h"

/**
 * REGEX_CHARS: characters for regex matching.
 *
 * When one of these characters is in filter strings,
 * treat them as regex expressions.
 */
#define REGEX_CHARS  ".?*+-^$|()[]{}"

enum trigger_flag {
	TRIGGER_FL_DEPTH	= (1U << 0),
};

struct ftrace_trigger {
	unsigned long		flags;
	int			depth;
};

struct ftrace_filter {
	struct rb_node		node;
	struct sym		*sym;
	char 			*name;
	unsigned long		start;
	unsigned long		end;
	struct ftrace_trigger	trigger;
};

typedef void (*trigger_fn_t)(struct ftrace_trigger *tr, void *arg);

void ftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			 char *module, struct rb_root *root);
int ftrace_match_filter(struct rb_root *root, unsigned long ip,
			struct ftrace_trigger *tr);
void ftrace_cleanup_filter(struct rb_root *root);
void ftrace_print_filter(struct rb_root *root);

#endif /* __FTRACE_FILTER_H__ */
