#ifndef UFTRACE_FILTER_H
#define UFTRACE_FILTER_H

#include <regex.h>
#include <stdint.h>
#include <stdio.h>

#include "utils/arch.h"
#include "utils/argspec.h"
#include "utils/list.h"
#include "utils/rbtree.h"

/**
 * REGEX_CHARS: characters for regex matching.
 *
 * When one of these characters is in filter strings,
 * treat them as regex expressions.
 */
#define REGEX_CHARS ".?*+-^$|()[]{}"

enum trigger_flag {
	TRIGGER_FL_DEPTH = (1U << 0),
	TRIGGER_FL_FILTER = (1U << 1),
	TRIGGER_FL_BACKTRACE = (1U << 2),
	TRIGGER_FL_TRACE = (1U << 3),
	TRIGGER_FL_TRACE_ON = (1U << 4),
	TRIGGER_FL_TRACE_OFF = (1U << 5),
	TRIGGER_FL_ARGUMENT = (1U << 6),
	TRIGGER_FL_RECOVER = (1U << 7),
	TRIGGER_FL_RETVAL = (1U << 8),
	TRIGGER_FL_COLOR = (1U << 9),
	TRIGGER_FL_TIME_FILTER = (1U << 10),
	TRIGGER_FL_READ = (1U << 11),
	TRIGGER_FL_FINISH = (1U << 13),
	TRIGGER_FL_AUTO_ARGS = (1U << 14),
	TRIGGER_FL_CALLER = (1U << 15),
	TRIGGER_FL_SIGNAL = (1U << 16),
	TRIGGER_FL_HIDE = (1U << 17),
	TRIGGER_FL_LOC = (1U << 18),
	TRIGGER_FL_SIZE_FILTER = (1U << 19),
	TRIGGER_FL_CLEAR = (1U << 20), /* Reverse other flags when set */
};

/**
 * filter_mode - opt-in or opt-out mode
 *
 * When in opt-in mode, only trace functions that have an explicit filter. When
 * in opt-out mode, trace all but explicitly excluded functions.

 * @FILTER_MODE_NONE is neutral and is only used for initialization in the
 * location filter.
 */
enum filter_mode {
	FILTER_MODE_NONE,
	FILTER_MODE_IN,
	FILTER_MODE_OUT,
};

enum trigger_read_type {
	TRIGGER_READ_NONE = 0,
	TRIGGER_READ_PROC_STATM = 1,
	TRIGGER_READ_PAGE_FAULT = 2,
	TRIGGER_READ_PMU_CYCLE = 4,
	TRIGGER_READ_PMU_CACHE = 8,
	TRIGGER_READ_PMU_BRANCH = 16,
};

enum filter_cond_op {
	FILTER_OP_EQ,
	FILTER_OP_NE,
	FILTER_OP_GT,
	FILTER_OP_GE,
	FILTER_OP_LT,
	FILTER_OP_LE,
};

struct uftrace_filter_cond {
	int idx; /* argument index, 0 if disabled */
	enum filter_cond_op op;
	long val;
};

struct uftrace_trigger {
	enum trigger_flag flags;
	enum trigger_flag clear_flags;
	int depth;
	char color;
	uint64_t time;
	unsigned size;
	enum filter_mode fmode;
	enum filter_mode lmode;
	enum trigger_read_type read;
	struct uftrace_filter_cond cond;
	struct list_head *pargs;
};

struct uftrace_filter {
	struct rb_node node;
	char *name;
	uint64_t start;
	uint64_t end;
	struct list_head args;
	struct uftrace_trigger trigger;
};

enum uftrace_pattern_type {
	PATT_NONE,
	PATT_SIMPLE,
	PATT_REGEX,
	PATT_GLOB,
};

struct uftrace_pattern {
	enum uftrace_pattern_type type;
	char *patt;
	regex_t re;
};

enum uftrace_trace_state {
	TRACE_STATE_NONE,
	TRACE_STATE_OFF,
	TRACE_STATE_ON,
};

struct uftrace_filter_setting {
	enum uftrace_pattern_type ptype;
	enum uftrace_cpu_arch arch;
	bool auto_args;
	bool allow_kernel;
	bool lp64;
	bool plt_only;
	/* caller-defined data */
	void *info_str;
};

struct uftrace_triggers_info {
	/* filters, trigger actions, arg/retval specs */
	/* container type: struct uftrace_filter */
	struct rb_root root;

	/* count of registered opt-in filters (-F) */
	int filter_count;
	/* count of registered caller filters */
	int caller_count;
	/* count of registered opt-in location filters (-L) */
	int loc_count;
};

typedef void (*trigger_fn_t)(struct uftrace_trigger *tr, void *arg);

struct uftrace_sym_info;

void uftrace_setup_filter(const char *filter_str, struct uftrace_sym_info *sinfo,
			  struct uftrace_triggers_info *triggers,
			  struct uftrace_filter_setting *setting);
void uftrace_setup_trigger(const char *trigger_str, struct uftrace_sym_info *sinfo,
			   struct uftrace_triggers_info *triggers,
			   struct uftrace_filter_setting *setting);
void uftrace_setup_argument(const char *args_str, struct uftrace_sym_info *sinfo,
			    struct uftrace_triggers_info *triggers,
			    struct uftrace_filter_setting *setting);
void uftrace_setup_retval(const char *retval_str, struct uftrace_sym_info *sinfo,
			  struct uftrace_triggers_info *triggers,
			  struct uftrace_filter_setting *setting);
void uftrace_setup_caller_filter(const char *filter_str, struct uftrace_sym_info *sinfo,
				 struct uftrace_triggers_info *triggers,
				 struct uftrace_filter_setting *setting);
void uftrace_setup_hide_filter(const char *filter_str, struct uftrace_sym_info *sinfo,
			       struct uftrace_triggers_info *triggers,
			       struct uftrace_filter_setting *setting);
void uftrace_setup_loc_filter(const char *filter_str, struct uftrace_sym_info *sinfo,
			      struct uftrace_triggers_info *triggers,
			      struct uftrace_filter_setting *setting);

struct uftrace_triggers_info uftrace_deep_copy_triggers(struct uftrace_triggers_info *src);
struct uftrace_filter *uftrace_match_filter(uint64_t ip, struct uftrace_triggers_info *filters,
					    struct uftrace_trigger *tr);
void uftrace_cleanup_filter(struct uftrace_triggers_info *filters);
void uftrace_cleanup_triggers(struct uftrace_triggers_info *triggers);
void uftrace_print_filter(struct uftrace_triggers_info *filters);
int uftrace_count_filter(struct uftrace_triggers_info *filters, unsigned long flag);

bool uftrace_eval_cond(struct uftrace_filter_cond *cond, long val);

void init_filter_pattern(enum uftrace_pattern_type type, struct uftrace_pattern *p, char *str);
bool match_filter_pattern(struct uftrace_pattern *p, char *name);
void free_filter_pattern(struct uftrace_pattern *p);
enum uftrace_pattern_type parse_filter_pattern(const char *str);
const char *get_filter_pattern(enum uftrace_pattern_type ptype);

char *uftrace_clear_kernel(char *filter_str);

int setup_trigger_action(char *str, struct uftrace_trigger *tr, char **module,
			 unsigned long orig_flags, struct uftrace_filter_setting *setting);

#endif /* UFTRACE_FILTER_H */
