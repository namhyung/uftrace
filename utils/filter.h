#ifndef UFTRACE_FILTER_H
#define UFTRACE_FILTER_H

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
	TRIGGER_FL_READ		= (1U << 11),
	TRIGGER_FL_FINISH	= (1U << 13),
	TRIGGER_FL_AUTO_ARGS	= (1U << 14),
};

enum filter_mode {
	FILTER_MODE_NONE,
	FILTER_MODE_IN,
	FILTER_MODE_OUT,
};

enum uftrace_arg_format {
	ARG_FMT_AUTO,
	ARG_FMT_SINT,
	ARG_FMT_UINT,
	ARG_FMT_HEX,
	ARG_FMT_STR,
	ARG_FMT_CHAR,
	ARG_FMT_FLOAT,
	ARG_FMT_STD_STRING,
	ARG_FMT_FUNC_PTR,
	ARG_FMT_ENUM,
};

enum trigger_read_type {
	TRIGGER_READ_NONE         = 0,
	TRIGGER_READ_PROC_STATM   = 1,
	TRIGGER_READ_PAGE_FAULT   = 2,
	TRIGGER_READ_PMU_CYCLE    = 4,
};

#define ARG_TYPE_INDEX  0
#define ARG_TYPE_FLOAT  1
#define ARG_TYPE_REG    2
#define ARG_TYPE_STACK  3

/* should match with ftrace_arg_format above */
#define ARG_SPEC_CHARS  "diuxscfSpe"

/**
 * ftrace_arg_spec contains arguments and return value info.
 *
 * If idx is zero, it means the recorded data is return value.
 *
 * If idx is not zero, it means the recorded data is arguments
 * and idx shows the sequence order of arguments.
 */
#define RETVAL_IDX 0

struct uftrace_arg_spec {
	struct list_head	list;
	int			idx;
	enum uftrace_arg_format	fmt;
	int			size;
	bool			exact;
	unsigned char		type;
	union {
		short		reg_idx;
		short		stack_ofs;
		char		*enum_str;
	};
};

struct uftrace_trigger {
	enum trigger_flag	flags;
	int			depth;
	char			color;
	uint64_t		time;
	enum filter_mode	fmode;
	enum trigger_read_type	read;
	struct list_head	*pargs;
};

struct uftrace_filter {
	struct rb_node		node;
	char 			*name;
	unsigned long		start;
	unsigned long		end;
	struct list_head	args;
	struct uftrace_trigger	trigger;
};

/* please see man proc(5) for /proc/[pid]/statm */
struct uftrace_proc_statm {
	uint64_t		vmsize;  /* total program size in KB */
	uint64_t		vmrss;   /* resident set size in KB */
	uint64_t		shared;  /* shared rss in KB (Rssfile + RssShmem) */
};

struct uftrace_page_fault {
	uint64_t		major;
	uint64_t		minor;
};

struct uftrace_pmu_cycle {
	uint64_t		cycles;  /* cpu cycles */
	uint64_t		instrs;  /* cpu instructions */
};

typedef void (*trigger_fn_t)(struct uftrace_trigger *tr, void *arg);

struct symtabs;

void uftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			  struct rb_root *root, enum filter_mode *mode,
			  bool allow_kernel);
void uftrace_setup_trigger(char *trigger_str, struct symtabs *symtabs,
			   struct rb_root *root, enum filter_mode *mode,
			   bool allow_kernel);
void uftrace_setup_argument(char *trigger_str, struct symtabs *symtabs,
			    struct rb_root *root, bool auto_args);
void uftrace_setup_retval(char *trigger_str, struct symtabs *symtabs,
			  struct rb_root *root, bool auto_args);

struct uftrace_filter *uftrace_match_filter(uint64_t ip, struct rb_root *root,
					    struct uftrace_trigger *tr);
void uftrace_cleanup_filter(struct rb_root *root);
void uftrace_print_filter(struct rb_root *root);

char * uftrace_clear_kernel(char *filter_str);

void setup_auto_args(void);
void setup_auto_args_str(char *args, char *rets, char *enums);
void finish_auto_args(void);
struct uftrace_filter * find_auto_argspec(char *name);
struct uftrace_filter * find_auto_retspec(char *name);
char *get_auto_argspec_str(void);
char *get_auto_retspec_str(void);
char *get_auto_enum_str(void);
int extract_trigger_args(char **pargs, char **prets, char *trigger);
int parse_enum_string(char *enum_str);
char *get_enum_string(char *name, long val);

#endif /* UFTRACE_FILTER_H */
