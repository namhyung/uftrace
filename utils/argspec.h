#ifndef UFTRACE_ARGSPEC_H
#define UFTRACE_ARGSPEC_H

#include "utils/list.h"
#include "utils/rbtree.h"
#include <stdbool.h>
#include <stdio.h>

enum uftrace_arg_format {
	ARG_FMT_AUTO,
	ARG_FMT_SINT,
	ARG_FMT_UINT,
	ARG_FMT_HEX,
	ARG_FMT_OCT,
	ARG_FMT_STR,
	ARG_FMT_CHAR,
	ARG_FMT_FLOAT,
	ARG_FMT_STD_STRING,
	ARG_FMT_PTR,
	ARG_FMT_ENUM,
	ARG_FMT_STRUCT,
	ARG_FMT_INT_PTR
};

#define ARG_TYPE_INDEX 0
#define ARG_TYPE_FLOAT 1
#define ARG_TYPE_REG 2
#define ARG_TYPE_STACK 3

/* should match with uftrace_arg_format above */
#define ARG_SPEC_CHARS "diuxoscfSpet"

/**
 * uftrace_arg_spec contains arguments and return value info.
 *
 * If idx is zero, it means the recorded data is return value.
 *
 * If idx is not zero, it means the recorded data is arguments
 * and idx shows the sequence order of arguments.
 */
#define RETVAL_IDX 0

struct uftrace_arg_spec {
	struct list_head list;  
	int idx; // ok
	enum uftrace_arg_format fmt; // ok
	int size; // ok
	bool exact;
	unsigned char type; // ok
	short struct_reg_cnt;
	union {
		short reg_idx;  // ok
		short stack_ofs;
	};
	char *type_name;  // ok
	short struct_regs[4];
	// adding address of struct; 
	int is_ptr; 
	struct resolved_struct_type *resolved_struct;
};

struct uftrace_filter_setting;

struct uftrace_arg_spec *parse_argspec(char *str, struct uftrace_filter_setting *setting);

void setup_auto_args(struct uftrace_filter_setting *setting);
void setup_auto_args_str(char *args, char *rets, char *enums,
			 struct uftrace_filter_setting *setting);
void finish_auto_args(void);

void free_arg_spec(struct uftrace_arg_spec *arg);

struct uftrace_dbg_info;
struct uftrace_filter;
struct uftrace_trigger;

struct uftrace_filter *find_auto_argspec(struct uftrace_filter *filter, struct uftrace_trigger *tr,
					 struct uftrace_dbg_info *dinfo,
					 struct uftrace_filter_setting *setting);
struct uftrace_filter *find_auto_retspec(struct uftrace_filter *filter, struct uftrace_trigger *tr,
					 struct uftrace_dbg_info *dinfo,
					 struct uftrace_filter_setting *setting);
char *get_auto_argspec_str(void);
char *get_auto_retspec_str(void);
char *get_auto_enum_str(void);
int extract_trigger_args(char **pargs, char **prets, char *trigger);
int parse_enum_string(char *enum_str, struct rb_root *root);
char *get_enum_string(struct rb_root *root, char *name, long val);
void save_enum_def(struct rb_root *root, FILE *fp);
void release_enum_def(struct rb_root *root);

extern struct rb_root dwarf_enum;

#endif /* UFTRACE_ARGSPEC_H */
