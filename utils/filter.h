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

struct ftrace_filter {
	struct rb_node		node;
	struct sym		*sym;
	char 			*name;
	unsigned long		start;
	unsigned long		end;
};

void ftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			 char *module, struct rb_root *root);
int ftrace_match_filter(struct rb_root *root, unsigned long ip);
void ftrace_cleanup_filter(struct rb_root *root);
void ftrace_print_filter(struct rb_root *root);

#endif /* __FTRACE_FILTER_H__ */
