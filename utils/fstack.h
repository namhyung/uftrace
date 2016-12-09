#ifndef __FTRACE_FSTACK_H__
#define __FTRACE_FSTACK_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "../uftrace.h"

struct sym;
struct ftrace_trigger;

enum fstack_flag {
	FSTACK_FL_FILTERED	= (1U << 0),
	FSTACK_FL_NOTRACE	= (1U << 1),
	FSTACK_FL_NORECORD	= (1U << 2),
	FSTACK_FL_EXEC		= (1U << 3),
	FSTACK_FL_LONGJMP	= (1U << 4),
};

enum context {
	FSTACK_CTX_UNKNOWN	= 0,
	FSTACK_CTX_USER		= 1,
	FSTACK_CTX_KERNEL	= 2,
};

struct time_filter_stack {
	struct time_filter_stack *next;
	uint64_t threshold;
	int depth;
	enum context context;
};

struct ftrace_task_handle {
	int tid;
	bool valid;
	bool done;
	bool lost_seen;
	bool display_depth_set;
	FILE *fp;
	struct sym *func;
	struct ftrace_task *t;
	struct ftrace_file_handle *h;
	struct ftrace_ret_stack ustack;
	struct ftrace_ret_stack kstack;
	struct ftrace_ret_stack *rstack;
	struct uftrace_rstack_list rstack_list;
	int stack_count;
	int lost_count;
	int user_stack_count;
	int display_depth;
	int user_display_depth;
	int column_index;
	enum context ctx;
	uint64_t timestamp;
	struct filter {
		int	in_count;
		int	out_count;
		int	depth;
		struct time_filter_stack *time;
	} filter;
	struct fstack {
		unsigned long addr;
		bool valid;
		int orig_depth;
		unsigned long flags;
		uint64_t total_time;
		uint64_t child_time;
	} *func_stack;
	struct fstack_arguments args;
};

enum argspec_string_bits {
	/* bit index */
	NEEDS_PAREN_BIT,
	NEEDS_SEMI_COLON_BIT,
	HAS_MORE_BIT,
	IS_RETVAL_BIT,
	NEEDS_ASSIGNMENT_BIT,
	NEEDS_ESCAPE_BIT,

	/* bit mask */
	NEEDS_PAREN		= (1U << NEEDS_PAREN_BIT),
	NEEDS_SEMI_COLON	= (1U << NEEDS_SEMI_COLON_BIT),
	HAS_MORE		= (1U << HAS_MORE_BIT),
	IS_RETVAL		= (1U << IS_RETVAL_BIT),
	NEEDS_ASSIGNMENT	= (1U << NEEDS_ASSIGNMENT_BIT),
	NEEDS_ESCAPE		= (1U << NEEDS_ESCAPE_BIT),
};

extern bool fstack_enabled;

void setup_task_handle(struct ftrace_file_handle *handle,
		       struct ftrace_task_handle *task, int tid);
struct ftrace_task_handle *get_task_handle(struct ftrace_file_handle *handle,
					   int tid);
void reset_task_handle(struct ftrace_file_handle *handle);

int read_rstack(struct ftrace_file_handle *handle,
		struct ftrace_task_handle **task);
int peek_rstack(struct ftrace_file_handle *handle,
		struct ftrace_task_handle **task);
void fstack_consume(struct ftrace_file_handle *handle,
		    struct ftrace_task_handle *task);

struct ftrace_ret_stack *
get_task_ustack(struct ftrace_file_handle *handle, int idx);
int read_task_ustack(struct ftrace_file_handle *handle,
		     struct ftrace_task_handle *task);
int read_task_args(struct ftrace_task_handle *task,
		   struct ftrace_ret_stack *rstack,
		   bool is_retval);

void setup_task_filter(char *tid_filter, struct ftrace_file_handle *handle);
int setup_fstack_filters(char *filter_str, char *trigger_str);
void setup_fstack_args(char *argspec);
void fstack_prepare_fixup(void);
int fstack_setup_filters(struct opts *opts, struct ftrace_file_handle *handle);

int fstack_entry(struct ftrace_task_handle *task,
		 struct ftrace_ret_stack *rstack,
		 struct ftrace_trigger *tr);
void fstack_exit(struct ftrace_task_handle *task);
int fstack_update(int type, struct ftrace_task_handle *task,
		  struct fstack *fstack);
struct ftrace_task_handle *fstack_skip(struct ftrace_file_handle *handle,
				       struct ftrace_task_handle *task,
				       int curr_depth);
bool fstack_check_filter(struct ftrace_task_handle *task);
void get_argspec_string(struct ftrace_task_handle *task,
		        char *args, size_t len,
		        enum argspec_string_bits str_mode);

#endif /* __FTRACE_FSTACK_H__ */
