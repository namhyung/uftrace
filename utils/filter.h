#ifndef __FTRACE_FILTER_H__
#define __FTRACE_FILTER_H__

#include <stdint.h>

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
	TRIGGER_FL_TRACE	= (1U << 3),
	TRIGGER_FL_TRACE_ON	= (1U << 4),
	TRIGGER_FL_TRACE_OFF	= (1U << 5),
	TRIGGER_FL_ARGUMENT	= (1U << 6),
	TRIGGER_FL_RECOVER	= (1U << 7),
	TRIGGER_FL_RETVAL	= (1U << 8),
	TRIGGER_FL_COLOR	= (1U << 9),
	TRIGGER_FL_TIME_FILTER	= (1U << 10),
};

enum filter_mode {
	FILTER_MODE_NONE,
	FILTER_MODE_IN,
	FILTER_MODE_OUT,
};

enum ftrace_arg_format {
	ARG_FMT_AUTO,
	ARG_FMT_SINT,
	ARG_FMT_UINT,
	ARG_FMT_HEX,
	ARG_FMT_STR,
	ARG_FMT_CHAR,
	ARG_FMT_FLOAT,
	ARG_FMT_STD_STRING,
};

#define ARG_TYPE_INDEX  0
#define ARG_TYPE_FLOAT  1
#define ARG_TYPE_REG    2
#define ARG_TYPE_STACK  3

/* should match with ftrace_arg_format above */
#define ARG_SPEC_CHARS  "diuxscf"

/**
 * ftrace_arg_spec contains arguments and return value info.
 *
 * If idx is zero, it means the recorded data is return value.
 *
 * If idx is not zero, it means the recorded data is arguments
 * and idx shows the sequence order of arguments.
 */
#define RETVAL_IDX 0

struct ftrace_arg_spec {
	struct list_head	list;
	int			idx;
	enum ftrace_arg_format	fmt;
	int			size;
	bool			exact;
	unsigned char		type;
	union {
		short		reg_idx;
		short		stack_ofs;
	};
};

struct ftrace_trigger {
	enum trigger_flag	flags;
	int			depth;
	char			color;
	uint64_t		time;
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

struct filter_module {
	struct list_head	list;
	char			name[];
};

typedef void (*trigger_fn_t)(struct ftrace_trigger *tr, void *arg);

void ftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			 struct rb_root *root, enum filter_mode *mode);
void ftrace_setup_trigger(char *trigger_str, struct symtabs *symtabs,
			  struct rb_root *root);
void ftrace_setup_argument(char *trigger_str, struct symtabs *symtabs,
			   struct rb_root *root);
void ftrace_setup_retval(char *trigger_str, struct symtabs *symtabs,
			 struct rb_root *root);

void ftrace_setup_filter_module(char *trigger_str, struct list_head *head,
				const char *modname);
void ftrace_cleanup_filter_module(struct list_head *head);

struct ftrace_filter *uftrace_match_filter(uint64_t ip, struct rb_root *root,
					   struct ftrace_trigger *tr);
void ftrace_cleanup_filter(struct rb_root *root);
void ftrace_print_filter(struct rb_root *root);

char * uftrace_clear_kernel(char *filter_str);

#endif /* __FTRACE_FILTER_H__ */
