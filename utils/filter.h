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
};

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

struct uftrace_trigger {
	enum trigger_flag flags;
	int depth;
	char color;
	uint64_t time;
	unsigned size;
	enum filter_mode fmode;
	enum filter_mode lmode;
	enum trigger_read_type read;
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

typedef void (*trigger_fn_t)(struct uftrace_trigger *tr, void *arg);

struct uftrace_sym_info;

void uftrace_setup_filter(char *filter_str, struct uftrace_sym_info *sinfo, struct rb_root *root,
			  enum filter_mode *mode, struct uftrace_filter_setting *setting);
void uftrace_setup_trigger(char *trigger_str, struct uftrace_sym_info *sinfo, struct rb_root *root,
			   enum filter_mode *mode, struct uftrace_filter_setting *setting);
void uftrace_setup_argument(char *trigger_str, struct uftrace_sym_info *sinfo, struct rb_root *root,
			    struct uftrace_filter_setting *setting);
void uftrace_setup_retval(char *trigger_str, struct uftrace_sym_info *sinfo, struct rb_root *root,
			  struct uftrace_filter_setting *setting);
void uftrace_setup_caller_filter(char *filter_str, struct uftrace_sym_info *sinfo,
				 struct rb_root *root, struct uftrace_filter_setting *setting);
void uftrace_setup_hide_filter(char *filter_str, struct uftrace_sym_info *sinfo,
			       struct rb_root *root, struct uftrace_filter_setting *setting);
void uftrace_setup_loc_filter(char *filter_str, struct uftrace_sym_info *sinfo,
			      struct rb_root *root, enum filter_mode *mode,
			      struct uftrace_filter_setting *setting);

struct rb_root uftrace_deep_copy_triggers(struct rb_root *src);
struct uftrace_filter *uftrace_match_filter(uint64_t ip, struct rb_root *root,
					    struct uftrace_trigger *tr);
void uftrace_cleanup_filter(struct rb_root *root);
void uftrace_print_filter(struct rb_root *root);
int uftrace_count_filter(struct rb_root *root, unsigned long flag);

void init_filter_pattern(enum uftrace_pattern_type type, struct uftrace_pattern *p, char *str);
bool match_filter_pattern(struct uftrace_pattern *p, char *name);
void free_filter_pattern(struct uftrace_pattern *p);
enum uftrace_pattern_type parse_filter_pattern(const char *str);
const char *get_filter_pattern(enum uftrace_pattern_type ptype);

char *uftrace_clear_kernel(char *filter_str);

void add_trigger(struct uftrace_filter *filter, struct uftrace_trigger *tr, bool exact_match);
int setup_trigger_action(char *str, struct uftrace_trigger *tr, char **module,
			 unsigned long orig_flags, struct uftrace_filter_setting *setting);

#endif /* UFTRACE_FILTER_H */
