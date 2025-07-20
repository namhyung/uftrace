#include <fnmatch.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "filter"
#define PR_DOMAIN DBG_FILTER

#include "libmcount/mcount.h"
#include "uftrace.h"
#include "utils/dwarf.h"
#include "utils/filter.h"
#include "utils/list.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"
#include "utils/utils.h"

static void snprintf_trigger_read(char *buf, size_t len, enum trigger_read_type type)
{
	buf[0] = '\0';

	if (type == TRIGGER_READ_NONE)
		snprintf(buf, len, "none");

	if (type & TRIGGER_READ_PROC_STATM)
		snprintf(buf, len, "%s%s", buf[0] ? "|" : "", "proc/statm");
	if (type & TRIGGER_READ_PAGE_FAULT)
		snprintf(buf, len, "%s%s", buf[0] ? "|" : "", "page-fault");
	if (type & TRIGGER_READ_PMU_CYCLE)
		snprintf(buf, len, "%s%s", buf[0] ? "|" : "", "pmu-cycle");
	if (type & TRIGGER_READ_PMU_CACHE)
		snprintf(buf, len, "%s%s", buf[0] ? "|" : "", "pmu-cache");
	if (type & TRIGGER_READ_PMU_BRANCH)
		snprintf(buf, len, "%s%s", buf[0] ? "|" : "", "pmu-branch");
}

static void snprintf_trigger_cond(char *buf, size_t len, struct uftrace_filter_cond *cond)
{
	const char *op_str[] = { "==", "!=", ">", ">=", "<", "<=" };

	snprintf(buf, len, "arg%d %s %ld", cond->idx, op_str[cond->op], cond->val);
}

static void print_trigger(struct uftrace_trigger *tr)
{
	if (tr->flags & TRIGGER_FL_CLEAR)
		pr_dbg("\ttriggers: clear=%#x\n", tr->clear_flags);
	if (tr->flags & TRIGGER_FL_DEPTH)
		pr_dbg("\ttrigger: depth %d\n", tr->depth);
	if (tr->flags & TRIGGER_FL_FILTER) {
		if (tr->fmode == FILTER_MODE_IN)
			pr_dbg("\ttrigger: filter IN");
		else if (tr->fmode == FILTER_MODE_OUT)
			pr_dbg("\ttrigger: filter OUT");

		if (tr->cond.idx) {
			char buf[64];

			snprintf_trigger_cond(buf, sizeof(buf), &tr->cond);
			pr_dbg("\tif %s", buf);
		}
		pr_dbg("\n");
	}
	if (tr->flags & TRIGGER_FL_LOC) {
		if (tr->lmode == FILTER_MODE_IN)
			pr_dbg("\ttrigger: location filter IN\n");
		else
			pr_dbg("\ttrigger: location filter OUT\n");
	}
	if (tr->flags & TRIGGER_FL_BACKTRACE)
		pr_dbg("\ttrigger: backtrace\n");
	if (tr->flags & TRIGGER_FL_TRACE)
		pr_dbg("\ttrigger: trace\n");
	if (tr->flags & TRIGGER_FL_TRACE_ON)
		pr_dbg("\ttrigger: trace_on\n");
	if (tr->flags & TRIGGER_FL_TRACE_OFF)
		pr_dbg("\ttrigger: trace_off\n");
	if (tr->flags & TRIGGER_FL_RECOVER)
		pr_dbg("\ttrigger: recover\n");
	if (tr->flags & TRIGGER_FL_FINISH)
		pr_dbg("\ttrigger: finish\n");

	if (tr->flags & TRIGGER_FL_ARGUMENT) {
		struct uftrace_arg_spec *arg;

		pr_dbg("\ttrigger: argument\n");
		list_for_each_entry(arg, tr->pargs, list) {
			if (arg->idx == RETVAL_IDX)
				continue;
			pr_dbg("\t\t arg%d: %c%d\n", arg->idx, ARG_SPEC_CHARS[arg->fmt],
			       arg->size * 8);
		}
	}
	if (tr->flags & TRIGGER_FL_RETVAL) {
		struct uftrace_arg_spec *arg;

		pr_dbg("\ttrigger: return value\n");
		list_for_each_entry(arg, tr->pargs, list) {
			if (arg->idx != RETVAL_IDX)
				continue;
			pr_dbg("\t\t retval%d: %c%d\n", arg->idx, ARG_SPEC_CHARS[arg->fmt],
			       arg->size * 8);
		}
	}

	if (tr->flags & TRIGGER_FL_COLOR)
		pr_dbg("\ttrigger: color '%c'\n", tr->color);
	if (tr->flags & TRIGGER_FL_TIME_FILTER)
		pr_dbg("\ttrigger: time filter %" PRIu64 "\n", tr->time);
	if (tr->flags & TRIGGER_FL_CALLER)
		pr_dbg("\ttrigger: caller filter\n");
	if (tr->flags & TRIGGER_FL_SIZE_FILTER)
		pr_dbg("\ttrigger: size filter %u\n", tr->size);

	if (tr->flags & TRIGGER_FL_READ) {
		char buf[1024];

		snprintf_trigger_read(buf, sizeof(buf), tr->read);
		pr_dbg("\ttrigger: read (%s)\n", buf);
	}
}

/**
 * uftrace_count_filter - count matching filters in @root
 * @filters - filter information
 * @flag - filter flag to match
 */
int uftrace_count_filter(struct uftrace_triggers_info *filters, unsigned long flag)
{
	struct rb_node *entry;
	struct uftrace_filter *iter;
	int count = 0;

	entry = rb_first(&filters->root);
	while (entry) {
		iter = rb_entry(entry, struct uftrace_filter, node);

		if (iter->trigger.flags & flag)
			count++;

		entry = rb_next(entry);
	}
	return count;
}

static bool match_ip(struct uftrace_filter *filter, uint64_t addr)
{
	return filter->start <= addr && addr < filter->end;
}

/**
 * uftrace_match_filter - try to match @ip with filters in @root
 * @addr - instruction address to match
 * @filters - filter information
 * @tr   - trigger data
 */
struct uftrace_filter *uftrace_match_filter(uint64_t addr, struct uftrace_triggers_info *filters,
					    struct uftrace_trigger *tr)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &filters->root.rb_node;
	struct uftrace_filter *iter;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_filter, node);

		if (match_ip(iter, addr)) {
			*tr = iter->trigger;

			pr_dbg2("filter match: %s\n", iter->name);
			if (dbg_domain[DBG_FILTER] >= 3)
				print_trigger(tr);
			return iter;
		}

		if (iter->start > addr)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	return NULL;
}

static void add_arg_spec(struct list_head *arg_list, struct uftrace_arg_spec *arg, bool exact_match)
{
	bool found = false;
	struct uftrace_arg_spec *oarg, *narg;

	list_for_each_entry(oarg, arg_list, list) {
		if (arg->type != oarg->type)
			continue;

		switch (arg->type) {
		case ARG_TYPE_INDEX:
		case ARG_TYPE_FLOAT:
			if (arg->idx == oarg->idx)
				found = true;
			break;
		case ARG_TYPE_REG:
			if (arg->reg_idx == oarg->reg_idx)
				found = true;
			break;
		case ARG_TYPE_STACK:
			if (arg->stack_ofs == oarg->stack_ofs)
				found = true;
			break;
		}

		if (found)
			break;
	}

	if (found) {
		/* do not overwrite exact match by regex match */
		if (exact_match || !oarg->exact) {
			free(oarg->type_name);
			oarg->type_name = NULL;

			oarg->fmt = arg->fmt;
			oarg->size = arg->size;
			oarg->exact = exact_match;
			oarg->type = arg->type;
			oarg->reg_idx = arg->reg_idx;
			oarg->struct_reg_cnt = arg->struct_reg_cnt;

			if (arg->type_name)
				oarg->type_name = xstrdup(arg->type_name);

			if (arg->struct_reg_cnt) {
				memcpy(oarg->struct_regs, arg->struct_regs,
				       sizeof(arg->struct_regs));
			}
		}
	}
	else {
		narg = xmalloc(sizeof(*narg));
		narg->idx = arg->idx;
		narg->fmt = arg->fmt;
		narg->size = arg->size;
		narg->exact = exact_match;
		narg->type = arg->type;
		narg->reg_idx = arg->reg_idx;
		narg->struct_reg_cnt = arg->struct_reg_cnt;

		if (arg->type_name)
			narg->type_name = xstrdup(arg->type_name);
		else
			narg->type_name = NULL;

		if (arg->struct_reg_cnt) {
			memcpy(narg->struct_regs, arg->struct_regs, sizeof(arg->struct_regs));
		}

		list_add_tail(&narg->list, &oarg->list);
	}
}

/**
 * update_trigger - update the trigger flags and related filter data
 * @filter - trigger tree entry holding filter parameters
 * @tr - trigger flags to apply
 * @exact_match - if symbol is exact or regex match (exact match has precedence)
 */
void update_trigger(struct uftrace_filter *filter, struct uftrace_trigger *tr, bool exact_match)
{
	filter->trigger.flags |= tr->flags;

	if (tr->flags & TRIGGER_FL_CLEAR) {
		filter->trigger.flags &= ~tr->clear_flags;
		if (tr->clear_flags & TRIGGER_FL_FILTER) {
			tr->fmode = filter->trigger.fmode; /* read from tree before deleting */
			memset(&filter->trigger.cond, 0, sizeof(tr->cond));
		}
	}

	if (tr->flags & TRIGGER_FL_DEPTH)
		filter->trigger.depth = tr->depth;
	if (tr->flags & TRIGGER_FL_FILTER) {
		filter->trigger.fmode = tr->fmode;
		memcpy(&filter->trigger.cond, &tr->cond, sizeof(tr->cond));
	}
	if (tr->flags & TRIGGER_FL_LOC)
		filter->trigger.lmode = tr->lmode;

	if (tr->flags & TRIGGER_FL_TRACE_ON)
		filter->trigger.flags &= ~TRIGGER_FL_TRACE_OFF;
	if (tr->flags & TRIGGER_FL_TRACE_OFF)
		filter->trigger.flags &= ~TRIGGER_FL_TRACE_ON;

	if (tr->flags & (TRIGGER_FL_ARGUMENT | TRIGGER_FL_RETVAL)) {
		struct uftrace_arg_spec *arg;

		list_for_each_entry(arg, tr->pargs, list)
			add_arg_spec(&filter->args, arg, exact_match);
	}

	if (tr->flags & TRIGGER_FL_COLOR)
		filter->trigger.color = tr->color;
	if (tr->flags & TRIGGER_FL_TIME_FILTER)
		filter->trigger.time = tr->time;
	if (tr->flags & TRIGGER_FL_READ)
		filter->trigger.read |= tr->read;
	if (tr->flags & TRIGGER_FL_SIZE_FILTER)
		filter->trigger.size = tr->size;
}

bool uftrace_eval_cond(struct uftrace_filter_cond *cond, long val)
{
	switch (cond->op) {
	case FILTER_OP_EQ:
		return val == cond->val;
	case FILTER_OP_NE:
		return val != cond->val;
	case FILTER_OP_GT:
		return val > cond->val;
	case FILTER_OP_GE:
		return val >= cond->val;
	case FILTER_OP_LT:
		return val < cond->val;
	case FILTER_OP_LE:
		return val <= cond->val;
	default:
		return false;
	}
}

/**
 * prune_void_filter - remove filters without trigger flags from the tree
 * @node - filter node to check
 * @root - root of the rbtree
 */
static void prune_void_filter(struct rb_node *node, struct rb_root *root)
{
	struct uftrace_filter *iter = rb_entry(node, struct uftrace_filter, node);
	if (!iter->trigger.flags) {
		rb_erase(node, root);
		pr_dbg3("prune void filter %s\n", iter->name);
	}
}

/**
 * update_filter - add, change or remove registered filter
 * @root - registered filters RB tree
 * @filter - filter tree node to update
 * @tr - trigger flags and data to apply
 * @exact_match - if symbol name is exact or regex match (exact precedes)
 * @dinfo - debug information
 * @return - status: 1 when update is made, 0 otherwise
 */
static int update_filter(struct rb_root *root, struct uftrace_filter *filter,
			 struct uftrace_trigger *tr, struct uftrace_mmap *map, bool exact_match,
			 struct uftrace_dbg_info *dinfo, struct uftrace_filter_setting *setting)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct uftrace_filter *iter, *new;
	struct uftrace_filter *auto_arg = NULL;
	struct uftrace_filter *auto_ret = NULL;
	unsigned long orig_flags = tr->flags;

	if ((tr->flags & TRIGGER_FL_ARGUMENT) && list_empty(tr->pargs)) {
		auto_arg = find_auto_argspec(filter, tr, dinfo, setting);
		if (auto_arg == NULL)
			tr->flags &= ~TRIGGER_FL_ARGUMENT;
	}
	if ((tr->flags & TRIGGER_FL_RETVAL) && list_empty(tr->pargs)) {
		auto_ret = find_auto_retspec(filter, tr, dinfo, setting);
		if (auto_ret == NULL)
			tr->flags &= ~TRIGGER_FL_RETVAL;
	}

	/* remove unnecessary filters might be set by --auto-args */
	if (tr->flags == TRIGGER_FL_AUTO_ARGS) {
		/* restored for regex filter */
		tr->flags = orig_flags;
		return 0;
	}

	pr_dbg2("add filter for %s (flags = %x)\n", filter->name, tr->flags);
	if (dbg_domain[DBG_FILTER] >= 3)
		print_trigger(tr);

	filter->start += map->start;
	filter->end += map->start;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_filter, node);

		if (iter->start == filter->start) {
			unsigned long args_flags = tr->flags;

			args_flags &= ~TRIGGER_FL_AUTO_ARGS;

			/* ignore auto-args if it already has argspec */
			if ((tr->flags & TRIGGER_FL_AUTO_ARGS) &&
			    (iter->trigger.flags & args_flags)) {
				tr->flags = orig_flags;
				return 0;
			}

			update_trigger(iter, tr, exact_match);
			if (auto_arg)
				update_trigger(iter, &auto_arg->trigger, exact_match);
			if (auto_ret)
				update_trigger(iter, &auto_ret->trigger, exact_match);
			tr->flags = orig_flags;
			if (tr->flags & TRIGGER_FL_CLEAR)
				prune_void_filter(parent, root);
			return 1;
		}

		if (iter->start > filter->start)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	new = xmalloc(sizeof(*new));
	memcpy(new, filter, sizeof(*new));
	new->trigger.flags = 0;
	new->trigger.read = 0;
	INIT_LIST_HEAD(&new->args);
	new->trigger.pargs = &new->args;

	update_trigger(new, tr, exact_match);
	if (auto_arg)
		update_trigger(new, &auto_arg->trigger, exact_match);
	if (auto_ret)
		update_trigger(new, &auto_ret->trigger, exact_match);
	tr->flags = orig_flags;

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);
	return 1;
}

struct {
	enum uftrace_pattern_type type;
	const char *name;
} filter_patterns[] = {
	{ PATT_SIMPLE, "simple" },
	{ PATT_REGEX, "regex" },
	{ PATT_GLOB, "glob" },
};

void init_locfilter_pattern(enum uftrace_pattern_type type, struct uftrace_pattern *p, char *str)
{
	char *converted;

	if (strpbrk(str, REGEX_CHARS) == NULL) {
		/* remove trailing '/' */
		if (str[strlen(str) - 1] == '/')
			str[strlen(str) - 1] = '\0';

		/* remove preceding '/' */
		if (str[0] == '/')
			str += 1;

		xasprintf(&converted, "%s%s%s", "((.*/)*)", str, "($|(/.*))");

		p->type = PATT_REGEX;
		p->patt = converted;
	}
	else {
		/* remaining PATT_REGEX and PATT_GLOB cases */
		p->type = type;
		p->patt = xstrdup(str);
	}

	if (p->type == PATT_REGEX) {
		/* to handle full demangled operator new and delete specially */
		const char *str_operator = "operator ";
		if (!strncmp(p->patt, str_operator, 9)) {
			p->type = PATT_SIMPLE;
		}
		else if (regcomp(&p->re, p->patt, REG_NOSUB | REG_EXTENDED)) {
			pr_dbg("regex pattern failed: %s\n", p->patt);
			p->type = PATT_SIMPLE;
		}
	}
}

void init_filter_pattern(enum uftrace_pattern_type type, struct uftrace_pattern *p, char *str)
{
	if (strpbrk(str, REGEX_CHARS) == NULL)
		type = PATT_SIMPLE;

	p->type = type;
	p->patt = xstrdup(str);

	if (type == PATT_REGEX) {
		/* to handle full demangled operator new and delete specially */
		const char *str_operator = "operator ";
		if (!strncmp(str, str_operator, 9)) {
			p->type = PATT_SIMPLE;
		}
		else if (regcomp(&p->re, str, REG_NOSUB | REG_EXTENDED)) {
			pr_dbg("regex pattern failed: %s\n", str);
			p->type = PATT_SIMPLE;
		}
	}
}

bool match_filter_pattern(struct uftrace_pattern *p, char *name)
{
	switch (p->type) {
	case PATT_SIMPLE:
		return !strcmp(p->patt, name);
	case PATT_REGEX:
		return !regexec(&p->re, name, 0, NULL, 0);
	case PATT_GLOB:
		return !fnmatch(p->patt, name, 0);
	default:
		return false;
	}
}

bool match_location_filter(struct uftrace_pattern *p, struct uftrace_dbg_info *dinfo,
			   size_t loc_idx)
{
	char *loc;

	if (!dinfo || loc_idx >= dinfo->nr_locs || !dinfo->locs[loc_idx].file)
		return false;

	loc = dinfo->locs[loc_idx].file->name;

	return match_filter_pattern(p, loc);
}

void free_filter_pattern(struct uftrace_pattern *p)
{
	free(p->patt);
	p->patt = NULL;

	if (p->type == PATT_REGEX)
		regfree(&p->re);

	p->type = PATT_NONE;
}

enum uftrace_pattern_type parse_filter_pattern(const char *str)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(filter_patterns); i++) {
		if (!strcmp(str, filter_patterns[i].name))
			return filter_patterns[i].type;
	}

	return PATT_NONE;
}

const char *get_filter_pattern(enum uftrace_pattern_type ptype)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(filter_patterns); i++) {
		if (filter_patterns[i].type == ptype)
			return filter_patterns[i].name;
	}

	return "none";
}

/* argument_spec = arg1/i32,arg2/x64%reg,arg3%stack+1,... */
static int parse_argument_spec(char *str, struct uftrace_trigger *tr,
			       struct uftrace_filter_setting *setting)
{
	struct uftrace_arg_spec *arg;

	if (!isdigit(str[3])) {
		pr_use("skipping invalid argument: %s\n", str);
		return -1;
	}

	arg = parse_argspec(str, setting);
	if (arg == NULL)
		return -1;

	tr->flags |= TRIGGER_FL_ARGUMENT;
	list_add_tail(&arg->list, tr->pargs);

	return 0;
}
/* argument_spec = retval/i32 or retval/x64 ... */
static int parse_retval_spec(char *str, struct uftrace_trigger *tr,
			     struct uftrace_filter_setting *setting)
{
	struct uftrace_arg_spec *arg;

	arg = parse_argspec(str, setting);
	if (arg == NULL)
		return -1;

	tr->flags |= TRIGGER_FL_RETVAL;
	list_add_tail(&arg->list, tr->pargs);

	return 0;
}

/* argument_spec = fparg1/32,fparg2/64%stack+1,... */
static int parse_float_argument_spec(char *str, struct uftrace_trigger *tr,
				     struct uftrace_filter_setting *setting)
{
	struct uftrace_arg_spec *arg;

	if (!isdigit(str[5])) {
		pr_use("skipping invalid argument: %s\n", str);
		return -1;
	}

	arg = parse_argspec(str, setting);
	if (arg == NULL)
		return -1;

	tr->flags |= TRIGGER_FL_ARGUMENT;
	list_add_tail(&arg->list, tr->pargs);

	return 0;
}

static int parse_depth_action(char *action, struct uftrace_trigger *tr,
			      struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_DEPTH;
	tr->depth = strtoul(action + 6, NULL, 10);

	if (tr->depth < 0 || tr->depth > MCOUNT_RSTACK_MAX) {
		pr_use("skipping invalid trigger depth: %d\n", tr->depth);
		return -1;
	}
	return 0;
}

static int parse_time_action(char *action, struct uftrace_trigger *tr,
			     struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_TIME_FILTER;
	tr->time = parse_time(action + 5, 3);
	return 0;
}

static int parse_size_action(char *action, struct uftrace_trigger *tr,
			     struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_SIZE_FILTER;
	tr->size = strtoul(action + 5, NULL, 10);
	return 0;
}

static int parse_read_action(char *action, struct uftrace_trigger *tr,
			     struct uftrace_filter_setting *setting)
{
	const char *target = action + 5;

	if (!strcmp(target, "proc/statm"))
		tr->read |= TRIGGER_READ_PROC_STATM;
	if (!strcmp(target, "page-fault"))
		tr->read |= TRIGGER_READ_PAGE_FAULT;
	if (!strcmp(target, "pmu-cycle"))
		tr->read |= TRIGGER_READ_PMU_CYCLE;
	if (!strcmp(target, "pmu-cache"))
		tr->read |= TRIGGER_READ_PMU_CACHE;
	if (!strcmp(target, "pmu-branch"))
		tr->read |= TRIGGER_READ_PMU_BRANCH;

	/* set READ flag only if valid type set */
	if (tr->read)
		tr->flags |= TRIGGER_FL_READ;

	return 0;
}

static int parse_color_action(char *action, struct uftrace_trigger *tr,
			      struct uftrace_filter_setting *setting)
{
	const char *color = action + 6;

	if (!strcmp(color, "red"))
		tr->color = COLOR_CODE_RED;
	else if (!strcmp(color, "green"))
		tr->color = COLOR_CODE_GREEN;
	else if (!strcmp(color, "blue"))
		tr->color = COLOR_CODE_BLUE;
	else if (!strcmp(color, "yellow"))
		tr->color = COLOR_CODE_YELLOW;
	else if (!strcmp(color, "magenta"))
		tr->color = COLOR_CODE_MAGENTA;
	else if (!strcmp(color, "cyan"))
		tr->color = COLOR_CODE_CYAN;
	else if (!strcmp(color, "bold"))
		tr->color = COLOR_CODE_BOLD;
	else if (!strcmp(color, "gray"))
		tr->color = COLOR_CODE_GRAY;
	else {
		pr_use("ignoring invalid color: %s\n", color);
		return 0;
	}

	tr->flags |= TRIGGER_FL_COLOR;
	return 0;
}

static int parse_trace_action(char *action, struct uftrace_trigger *tr,
			      struct uftrace_filter_setting *setting)
{
	action += 5;
	if (*action == '_' || *action == '-')
		action++;

	if (*action == '\0')
		tr->flags |= TRIGGER_FL_TRACE;
	else if (!strcasecmp(action, "on"))
		tr->flags |= TRIGGER_FL_TRACE_ON;
	else if (!strcasecmp(action, "off"))
		tr->flags |= TRIGGER_FL_TRACE_OFF;
	else
		pr_use("skipping invalid trace action: %s\n", action);

	return 0;
}

static int parse_backtrace_action(char *action, struct uftrace_trigger *tr,
				  struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_BACKTRACE;
	return 0;
}

static int parse_recover_action(char *action, struct uftrace_trigger *tr,
				struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_RECOVER;
	return 0;
}

static int parse_finish_action(char *action, struct uftrace_trigger *tr,
			       struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_FINISH;
	return 0;
}

static int parse_filter_action(char *action, struct uftrace_trigger *tr,
			       struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_FILTER;
	tr->fmode = FILTER_MODE_IN;
	return 0;
}

static int parse_notrace_action(char *action, struct uftrace_trigger *tr,
				struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_FILTER;
	tr->fmode = FILTER_MODE_OUT;
	return 0;
}

static int parse_auto_args_action(char *action, struct uftrace_trigger *tr,
				  struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_ARGUMENT | TRIGGER_FL_RETVAL;
	return 0;
}

static int parse_caller_action(char *action, struct uftrace_trigger *tr,
			       struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_CALLER;
	return 0;
}

static int parse_hide_action(char *action, struct uftrace_trigger *tr,
			     struct uftrace_filter_setting *setting)
{
	tr->flags |= TRIGGER_FL_HIDE;
	return 0;
}

/* if:arg1==1234, single condition only */
static int parse_cond_action(char *action, struct uftrace_trigger *tr,
			     struct uftrace_filter_setting *setting)
{
	const char *op_str[] = { "==", "!=", ">", ">=", "<", "<=" };
	char *expr = action + 3;
	char *pos;
	int idx;
	int op = -1;
	long val;

	if (strncmp(expr, "arg", 3)) {
		pr_use("ignoring invalid arg: %s\n", expr);
		return -1;
	}

	idx = strtol(expr + 3, &pos, 0);
	if (idx < 1 || idx > 6) { /* don't support retval */
		pr_use("only support up to 6 argument for now\n");
		return -1;
	}

	while (*pos == ' ')
		pos++;

	/* reverse order match to find "<=" before "<" */
	for (size_t k = ARRAY_SIZE(op_str) - 1; k < ARRAY_SIZE(op_str); k--) {
		if (strncmp(pos, op_str[k], strlen(op_str[k])))
			continue;

		op = k;
		pos += strlen(op_str[k]);
		break;
	}
	if (op == -1) {
		pr_use("ignoring invalid op: %.3s\n", pos);
		return -1;
	}

	while (*pos == ' ')
		pos++;

	val = strtol(pos, NULL, 0);

	tr->cond.idx = idx;
	tr->cond.op = op;
	tr->cond.val = val;

	return 0;
}

static int parse_clear_action(char *action, struct uftrace_trigger *tr,
			      struct uftrace_filter_setting *setting)
{
	struct strv acts = STRV_INIT;
	char *pos = NULL;
	int j;

	tr->flags |= TRIGGER_FL_CLEAR;

	if (strlen(action) == 5) {
		tr->clear_flags = ~0;
		return 0;
	}

	if (action[5] != '=') {
		pr_use("skipping invalid action: %s\n", action);
		return -1;
	}

	/* action = "clear=act1+act2+..." */
	pos = action + 6;
	strv_split(&acts, pos, "+");
	strv_for_each(&acts, pos, j) {
		if (!strcmp(pos, "arg") || !strcmp(pos, "fparg"))
			tr->clear_flags |= TRIGGER_FL_ARGUMENT;
		else if (!strcmp(pos, "retval"))
			tr->clear_flags |= TRIGGER_FL_RETVAL;
		else if (!strcmp(pos, "filter") || !strcmp(pos, "notrace"))
			tr->clear_flags |= TRIGGER_FL_FILTER;
		else if (!strcmp(pos, "depth"))
			tr->clear_flags |= TRIGGER_FL_DEPTH;
		else if (!strcmp(pos, "time"))
			tr->clear_flags |= TRIGGER_FL_TIME_FILTER;
		else if (!strcmp(pos, "size"))
			tr->clear_flags |= TRIGGER_FL_SIZE_FILTER;
		else if (!strcmp(pos, "hide"))
			tr->clear_flags |= TRIGGER_FL_HIDE;
		else if (!strcmp(pos, "trace"))
			tr->clear_flags |= TRIGGER_FL_TRACE | TRIGGER_FL_TRACE_ON |
					   TRIGGER_FL_TRACE_OFF;
		else if (!strcmp(pos, "finish"))
			tr->clear_flags |= TRIGGER_FL_FINISH;
		else if (!strcmp(pos, "read"))
			tr->clear_flags |= TRIGGER_FL_READ;
		else if (!strcmp(pos, "color"))
			tr->clear_flags |= TRIGGER_FL_COLOR;
		else if (!strcmp(pos, "backtrace"))
			tr->clear_flags |= TRIGGER_FL_BACKTRACE;
		else if (!strcmp(pos, "recover"))
			tr->clear_flags |= TRIGGER_FL_RECOVER;
		else
			pr_use("skipping invalid clear argument: %s\n", pos);
	}

	strv_free(&acts);
	return 0;
}

struct trigger_action_parser {
	const char *name;
	int (*parse)(char *action, struct uftrace_trigger *tr,
		     struct uftrace_filter_setting *setting);
	enum trigger_flag compat_flags; /* flags the action is restricted to */
};

static const struct trigger_action_parser actions[] = {
	{
		"arg",
		parse_argument_spec,
		TRIGGER_FL_ARGUMENT,
	},
	{
		"fparg",
		parse_float_argument_spec,
		TRIGGER_FL_ARGUMENT,
	},
	{
		"retval",
		parse_retval_spec,
		TRIGGER_FL_RETVAL,
	},
	{
		"filter",
		parse_filter_action,
		TRIGGER_FL_FILTER,
	},
	{
		"notrace",
		parse_notrace_action,
		TRIGGER_FL_FILTER,
	},
	{
		"depth=",
		parse_depth_action,
		TRIGGER_FL_FILTER,
	},
	{
		"time=",
		parse_time_action,
		TRIGGER_FL_FILTER,
	},
	{
		"size=",
		parse_size_action,
		TRIGGER_FL_FILTER,
	},
	{
		"caller",
		parse_caller_action,
		TRIGGER_FL_FILTER,
	},
	{
		"hide",
		parse_hide_action,
		TRIGGER_FL_FILTER,
	},
	{
		"trace",
		parse_trace_action,
		TRIGGER_FL_SIGNAL,
	},
	{
		"finish",
		parse_finish_action,
		TRIGGER_FL_SIGNAL,
	},
	{
		"read=",
		parse_read_action,
	},
	{
		"color=",
		parse_color_action,
	},
	{
		"backtrace",
		parse_backtrace_action,
	},
	{
		"recover",
		parse_recover_action,
	},
	{
		"auto-args",
		parse_auto_args_action,
	},
	{
		"clear",
		parse_clear_action,
		TRIGGER_FL_FILTER | TRIGGER_FL_CALLER,
	},
	{
		"if:",
		parse_cond_action,
		TRIGGER_FL_FILTER,
	},
};

int setup_trigger_action(char *str, struct uftrace_trigger *tr, char **module,
			 unsigned long orig_flags, struct uftrace_filter_setting *setting)
{
	char *pos = strchr(str, '@');
	struct strv acts = STRV_INIT;
	int ret = -1;
	size_t i;
	int j;

	if (module != NULL)
		*module = NULL;

	if (pos == NULL)
		return 0;

	*pos++ = '\0';
	strv_split(&acts, pos, ",");

	strv_for_each(&acts, pos, j) {
		for (i = 0; i < ARRAY_SIZE(actions); i++) {
			const struct trigger_action_parser *action = &actions[i];

			if (strncasecmp(pos, action->name, strlen(action->name)))
				continue;

			if (orig_flags && !(orig_flags & action->compat_flags))
				break; /* ignore incompatible actions */

			if (action->parse(pos, tr, setting) < 0)
				goto out;

			break;
		}

		/* if it's not an action, treat it as a module name */
		if (i == ARRAY_SIZE(actions) && module != NULL) {
			if (*module)
				pr_use("ignoring extra module: %s\n", pos);
			else
				*module = xstrdup(pos);
		}
	}
	if (tr->flags & TRIGGER_FL_CLEAR) {
		if (orig_flags)
			/* '@clear' suffix for options other then -T/--trigger */
			tr->clear_flags = orig_flags;
		else {
			/* preserve flag if set and cleared e.g. -T func@act,clear=act applies act */
			tr->clear_flags &= ~tr->flags;
		}
	}

	ret = 0;

out:
	if (ret < 0 && module != NULL)
		free(*module);

	strv_free(&acts);
	return ret;
}

/**
 * update_trigger_entry - match symbol names to update their filter
 * @root - RB tree of registered filters
 * @patt - matching pattern type
 * @tr - trigger data and flags to apply
 * @return - status: count of updated filters
 */
static int update_trigger_entry(struct rb_root *root, struct uftrace_pattern *patt,
				struct uftrace_trigger *tr, struct uftrace_mmap *map,
				struct uftrace_filter_setting *setting)
{
	struct uftrace_filter filter;
	struct uftrace_symtab *symtab = &map->mod->symtab;
	struct uftrace_dbg_info *dinfo = &map->mod->dinfo;
	struct uftrace_symbol *sym;
	size_t i;
	int ret = 0;

	for (i = 0; i < symtab->nr_sym; i++) {
		sym = &symtab->sym[i];

		if (tr->flags == TRIGGER_FL_LOC) {
			if (!match_location_filter(patt, dinfo, i))
				continue;
		}
		else {
			if (!match_filter_pattern(patt, sym->name))
				continue;
		}

		if (setting->plt_only && sym->type != ST_PLT_FUNC)
			continue;

		filter.name = sym->name;
		filter.start = sym->addr;
		filter.end = sym->addr + sym->size;

		ret += update_filter(root, &filter, tr, map, patt->type == PATT_SIMPLE, dinfo,
				     setting);
	}

	return ret;
}

/**
 * setup_trigger - register filter and set trigger data for matching entries
 * @filter_str - symbol and action specification
 * @sinfo      - symbol information to find symbol address
 * @triggers   - rbtree of registered filters and associated counters
 * @flags      - trigger flags to apply
 * @setting    - filter settings
 */
static void setup_trigger(const char *filter_str, struct uftrace_sym_info *sinfo,
			  struct uftrace_triggers_info *triggers, unsigned long flags,
			  struct uftrace_filter_setting *setting)
{
	struct strv filters = STRV_INIT;
	char *name;
	int j;

	if (filter_str == NULL)
		return;

	strv_split(&filters, filter_str, ";");

	strv_for_each(&filters, name, j) {
		LIST_HEAD(args);
		struct uftrace_trigger tr = {
			.flags = flags,
			.pargs = &args,
		};
		int ret = 0;
		char *module = NULL;
		struct uftrace_arg_spec *arg;
		struct uftrace_mmap *map;
		struct uftrace_pattern patt = {
			.type = PATT_NONE,
		};

		if (setup_trigger_action(name, &tr, &module, flags, setting) < 0)
			goto next;

		/* skip unintended kernel symbols */
		if (module && has_kernel_opt(module) && !setting->allow_kernel)
			goto next;

		if (flags & TRIGGER_FL_FILTER) {
			if (name[0] == '!') {
				tr.fmode = FILTER_MODE_OUT;
				name++;
			}
			else
				tr.fmode = FILTER_MODE_IN;
		}

		if (flags & TRIGGER_FL_LOC) {
			if (name[0] == '!') {
				tr.lmode = FILTER_MODE_OUT;
				name++;
			}
			else
				tr.lmode = FILTER_MODE_IN;
		}

		/* use demangled name for triggers (some auto-args need it) */
		name = demangle(name);

		if (flags & TRIGGER_FL_LOC)
			init_locfilter_pattern(setting->ptype, &patt, name);
		else
			init_filter_pattern(setting->ptype, &patt, name);
		free(name);

		if (module) {
			if (!strcasecmp(module, "PLT")) {
				setting->plt_only = true;
				ret += update_trigger_entry(&triggers->root, &patt, &tr,
							    sinfo->exec_map, setting);
				setting->plt_only = false;
			}
			else if (has_kernel_opt(module)) {
				struct uftrace_mmap kernel_map = {
					.mod = get_kernel_module(),
				};

				ret = update_trigger_entry(&triggers->root, &patt, &tr, &kernel_map,
							   setting);
			}
			else {
				map = find_map_by_name(sinfo, module);
				if (map && map->mod) {
					ret = update_trigger_entry(&triggers->root, &patt, &tr, map,
								   setting);
				}
			}
		}
		else {
			for_each_map(sinfo, map) {
				/* some modules don't have symbol table */
				if (map->mod == NULL)
					continue;

				ret += update_trigger_entry(&triggers->root, &patt, &tr, map,
							    setting);
			}
		}

		if (ret > 0 && (tr.flags & TRIGGER_FL_FILTER)) {
			if (tr.fmode == FILTER_MODE_IN) {
				if (tr.clear_flags & TRIGGER_FL_FILTER)
					triggers->filter_count -= ret;
				else
					triggers->filter_count += ret;
			}
			pr_dbg4("filter IN count: %d\n", triggers->filter_count);
		}

		if (ret > 0 && (tr.flags & TRIGGER_FL_LOC)) {
			if (tr.lmode == FILTER_MODE_IN)
				triggers->loc_count += ret;
		}

		if (ret > 0 && (tr.flags & TRIGGER_FL_CALLER)) {
			if (tr.clear_flags & TRIGGER_FL_CALLER)
				triggers->caller_count -= ret;
			else
				triggers->caller_count += ret;
			pr_dbg4("caller filter count: %d\n", triggers->caller_count);
		}

next:
		free_filter_pattern(&patt);
		free(module);

		while (!list_empty(&args)) {
			arg = list_first_entry(&args, typeof(*arg), list);
			list_del(&arg->list);
			free_arg_spec(arg);
		}
	}

	strv_free(&filters);
}

/**
 * uftrace_setup_filter - construct rbtree of filters
 * @filter_str - CSV of filter string
 * @sinfo      - symbol information to find symbol address
 * @triggers   - root of filters rbtree
 * @setting    - filter settings
 */
void uftrace_setup_filter(const char *filter_str, struct uftrace_sym_info *sinfo,
			  struct uftrace_triggers_info *triggers,
			  struct uftrace_filter_setting *setting)
{
	setup_trigger(filter_str, sinfo, triggers, TRIGGER_FL_FILTER, setting);
}

/**
 * uftrace_setup_trigger - construct rbtree of triggers
 * @trigger_str - CSV of trigger string (FUNC @ act)
 * @sinfo       - symbol information to find symbol address
 * @triggers    - root of resulting rbtree
 * @setting     - filter settings
 */
void uftrace_setup_trigger(const char *trigger_str, struct uftrace_sym_info *sinfo,
			   struct uftrace_triggers_info *triggers,
			   struct uftrace_filter_setting *setting)
{
	setup_trigger(trigger_str, sinfo, triggers, 0, setting);
}

/**
 * uftrace_setup_argument - construct rbtree of argument
 * @args_str   - CSV of argument string (FUNC @ arg)
 * @sinfo      - symbol information to find symbol address
 * @triggers   - root of resulting rbtree
 * @setting    - filter settings
 */
void uftrace_setup_argument(const char *args_str, struct uftrace_sym_info *sinfo,
			    struct uftrace_triggers_info *triggers,
			    struct uftrace_filter_setting *setting)
{
	unsigned long flags = TRIGGER_FL_ARGUMENT;

	if (setting->auto_args)
		flags |= TRIGGER_FL_AUTO_ARGS;

	setup_trigger(args_str, sinfo, triggers, flags, setting);
}

/**
 * uftrace_setup_retval - construct rbtree of retval
 * @retval_str - CSV of return value string (FUNC @ arg)
 * @sinfo      - symbol information to find symbol address
 * @triggers   - root of resulting rbtree
 * @setting    - filter settings
 */
void uftrace_setup_retval(const char *retval_str, struct uftrace_sym_info *sinfo,
			  struct uftrace_triggers_info *triggers,
			  struct uftrace_filter_setting *setting)
{
	unsigned long flags = TRIGGER_FL_RETVAL;

	if (setting->auto_args)
		flags |= TRIGGER_FL_AUTO_ARGS;

	setup_trigger(retval_str, sinfo, triggers, flags, setting);
}

/**
 * uftrace_setup_caller_filter - add caller filters to rbtree
 * @filter_str - CSV of filter string
 * @sinfo      - symbol information to find symbol address
 * @triggers   - root of resulting rbtree
 * @setting    - filter settings
 */
void uftrace_setup_caller_filter(const char *filter_str, struct uftrace_sym_info *sinfo,
				 struct uftrace_triggers_info *triggers,
				 struct uftrace_filter_setting *setting)
{
	setup_trigger(filter_str, sinfo, triggers, TRIGGER_FL_CALLER, setting);
}

/**
 * uftrace_setup_hide_filter - add hide filters to rbtree
 * @filter_str - CSV of filter string
 * @sinfo      - symbol information to find symbol address
 * @triggers   - root of resulting rbtree
 * @setting    - filter settings
 */
void uftrace_setup_hide_filter(const char *filter_str, struct uftrace_sym_info *sinfo,
			       struct uftrace_triggers_info *triggers,
			       struct uftrace_filter_setting *setting)
{
	setup_trigger(filter_str, sinfo, triggers, TRIGGER_FL_HIDE, setting);
}

/**
 * uftrace_setup_loc_filter - add source location filters to rbtree
 * @filter_str - CSV of filter string
 * @sinfo      - symbol information to find symbol address
 * @triggers   - root of resulting rbtree
 * @setting    - filter settings
 */
void uftrace_setup_loc_filter(const char *filter_str, struct uftrace_sym_info *sinfo,
			      struct uftrace_triggers_info *triggers,
			      struct uftrace_filter_setting *setting)
{
	setup_trigger(filter_str, sinfo, triggers, TRIGGER_FL_LOC, setting);
}

/**
 * deep_copy_filter - perform a deep of a filter structure
 * @old    - structure to copy
 * @return - allocated deep copy of @old
 */
static struct uftrace_filter *deep_copy_filter(struct uftrace_filter *old)
{
	struct uftrace_filter *new;
	struct uftrace_arg_spec *arg, *arg_copy;

	new = xmalloc(sizeof(*new));

	/* copy the whole structure */
	memcpy(new, old, sizeof(*old));

	/* deep copy nested argspec list */
	INIT_LIST_HEAD(&new->args);
	list_for_each_entry(arg, &old->args, list) {
		arg_copy = xmalloc(sizeof(*arg_copy));
		memcpy(arg_copy, arg, sizeof(*arg));
		if (arg->type_name)
			arg_copy->type_name = xstrdup(arg->type_name);
		list_add_tail(&arg_copy->list, &new->args);
	}

	/* deep copy nested trigger.pargs */
	new->trigger.pargs = &new->args;

	return new;
}

/**
 * deep_copy_triggers - recursively perform a deep copy of a rbtree with
 * 'struct uftrace_filter' nodes
 * @dest - pointer to the address of the copy (modified in place)
 * @src  - original rbtree
 */
static void deep_copy_triggers(struct rb_node **dest, struct rb_node *src)
{
	struct uftrace_filter *old, *new;

	if (!src) {
		*dest = NULL;
		return;
	}

	old = rb_entry(src, struct uftrace_filter, node);
	new = deep_copy_filter(old);
	*dest = &new->node;

	if (src->rb_left) {
		deep_copy_triggers(&(*dest)->rb_left, src->rb_left);
		(*dest)->rb_left->rb_parent_color = (unsigned long)new & ~1;
		(*dest)->rb_left->rb_parent_color |= rb_color(src->rb_left);
	}
	if (src->rb_right) {
		deep_copy_triggers(&(*dest)->rb_right, src->rb_right);
		(*dest)->rb_right->rb_parent_color = (unsigned long)new & ~1;
		(*dest)->rb_right->rb_parent_color |= rb_color(src->rb_right);
	}
}

/**
 * deep_copy_triggers - deep copy an rbtree containing filters
 * @src    - root of the rbtree to copy
 * @return - root of the deep copy
 */
struct uftrace_triggers_info uftrace_deep_copy_triggers(struct uftrace_triggers_info *src)
{
	struct uftrace_triggers_info new = *src;
	new.root = RB_ROOT;
	deep_copy_triggers(&new.root.rb_node, src->root.rb_node);
	return new;
}

/**
 * uftrace_cleanup_filter - delete filters in rbtree
 * @filters - filter information
 */
void uftrace_cleanup_filter(struct uftrace_triggers_info *filters)
{
	struct rb_root *root = &filters->root;
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_arg_spec *arg, *tmp;

	while (!RB_EMPTY_ROOT(root)) {
		node = rb_first(root);
		filter = rb_entry(node, struct uftrace_filter, node);

		rb_erase(node, root);

		list_for_each_entry_safe(arg, tmp, &filter->args, list) {
			list_del(&arg->list);
			free_arg_spec(arg);
		}
		free(filter);
	}
}

/**
 * uftrace_cleanup_triggers - delete filters and reset counters
 * @triggers - triggers info
 */
void uftrace_cleanup_triggers(struct uftrace_triggers_info *triggers)
{
	uftrace_cleanup_filter(triggers);
	triggers->filter_count = 0;
	triggers->caller_count = 0;
	triggers->loc_count = 0;
}

/**
 * uftrace_print_filter - print all filters in rbtree
 * @filters - filter information
 */
void uftrace_print_filter(struct uftrace_triggers_info *filters)
{
	struct rb_node *node;
	struct uftrace_filter *filter;

	node = rb_first(&filters->root);
	while (node) {
		filter = rb_entry(node, struct uftrace_filter, node);
		pr_dbg("%lx-%lx: %s\n", filter->start, filter->end, filter->name);
		print_trigger(&filter->trigger);

		node = rb_next(node);
	}
}

char *uftrace_clear_kernel(char *filter_str)
{
	struct strv filters = STRV_INIT;
	char *pos, *ret = NULL;
	int j;

	/* check filter string contains a kernel filter */
	if (filter_str == NULL)
		return NULL;

	if (has_kernel_filter(filter_str) == NULL)
		return xstrdup(filter_str);

	strv_split(&filters, filter_str, ";");

	strv_for_each(&filters, pos, j) {
		if (has_kernel_filter(pos) == NULL)
			ret = strjoin(ret, pos, ";");
	}
	strv_free(&filters);

	return ret;
}

#ifdef UNIT_TEST

static void filter_test_load_symtabs(struct uftrace_sym_info *sinfo)
{
	static struct uftrace_symbol syms[] = {
		{ 0x1000, 0x1000, ST_GLOBAL_FUNC, "foo::foo" },
		{ 0x2000, 0x1000, ST_GLOBAL_FUNC, "foo::bar" },
		{ 0x3000, 0x1000, ST_GLOBAL_FUNC, "foo::baz1" },
		{ 0x4000, 0x1000, ST_GLOBAL_FUNC, "foo::baz2" },
		{ 0x5000, 0x1000, ST_GLOBAL_FUNC, "foo::baz3" },
		{ 0x6000, 0x1000, ST_GLOBAL_FUNC, "foo::~foo" },
		{ 0x21000, 0x1000, ST_PLT_FUNC, "malloc" },
		{ 0x22000, 0x1000, ST_PLT_FUNC, "free" },
	};
	static struct uftrace_module mod = {
		.symtab = {
			.sym    = syms,
			.nr_sym = ARRAY_SIZE(syms),
		},
		.dinfo = {
			.loaded = true,
		}
	};
	static struct uftrace_mmap map = {
		.mod = &mod,
		.start = 0x0,
		.end = 0x24000,
	};

	mod.symtab.sym = syms;
	mod.symtab.nr_sym = ARRAY_SIZE(syms);

	sinfo->maps = &map;
	sinfo->exec_map = &map;
	sinfo->loaded = true;
}

enum filter_mode get_filter_mode(int count)
{
	return count > 0 ? FILTER_MODE_IN : FILTER_MODE_OUT;
}

TEST_CASE(filter_setup_simple)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_SIMPLE,
	};

	filter_test_load_symtabs(&sinfo);

	pr_dbg("checking simple match\n");
	uftrace_setup_filter("foo::bar", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::bar");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	uftrace_cleanup_filter(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("checking destructor match\n");
	uftrace_setup_filter("foo::~foo", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::~foo");
	TEST_EQ(filter->start, 0x6000UL);
	TEST_EQ(filter->end, 0x6000UL + 0x1000UL);

	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("checking unknown symbol\n");
	uftrace_setup_filter("invalid_name", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(filter_setup_regex)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_REGEX,
	};

	filter_test_load_symtabs(&sinfo);

	pr_dbg("try to match with regex pattern: ^foo::b\n");
	uftrace_setup_filter("^foo::b", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::bar");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz1");
	TEST_EQ(filter->start, 0x3000UL);
	TEST_EQ(filter->end, 0x3000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz2");
	TEST_EQ(filter->start, 0x4000UL);
	TEST_EQ(filter->end, 0x4000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz3");
	TEST_EQ(filter->start, 0x5000UL);
	TEST_EQ(filter->end, 0x5000UL + 0x1000UL);

	pr_dbg("found 4 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(filter_setup_glob)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_GLOB,
	};

	filter_test_load_symtabs(&sinfo);

	pr_dbg("try to match with glob pattern: foo::b*\n");
	uftrace_setup_filter("foo::b*", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::bar");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz1");
	TEST_EQ(filter->start, 0x3000UL);
	TEST_EQ(filter->end, 0x3000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz2");
	TEST_EQ(filter->start, 0x4000UL);
	TEST_EQ(filter->end, 0x4000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz3");
	TEST_EQ(filter->start, 0x5000UL);
	TEST_EQ(filter->end, 0x5000UL + 0x1000UL);

	pr_dbg("found 4 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(filter_setup_notrace)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
		.filter_count = 0,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_GLOB,
	};

	filter_test_load_symtabs(&sinfo);

	pr_dbg("setup inclusive filter for foo::*\n");
	uftrace_setup_filter("foo::*", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);
	TEST_EQ(get_filter_mode(triggers.filter_count), FILTER_MODE_IN);

	pr_dbg("add/replace exclusive filter for foo::foo\n");
	uftrace_setup_filter("!foo::foo", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);
	TEST_EQ(get_filter_mode(triggers.filter_count),
		FILTER_MODE_IN); /* overall filter mode doesn't change */

	pr_dbg("foo:foo should have OUT filter mode\n");
	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::foo");
	TEST_EQ(filter->trigger.flags, TRIGGER_FL_FILTER);
	TEST_EQ(filter->trigger.fmode, FILTER_MODE_OUT);

	pr_dbg("foo:bar should have IN filter mode\n");
	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::bar");
	TEST_EQ(filter->trigger.flags, TRIGGER_FL_FILTER);
	TEST_EQ(filter->trigger.fmode, FILTER_MODE_IN);

	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(filter_match)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
		.filter_count = 0,
	};
	struct uftrace_trigger tr;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_REGEX,
	};

	filter_test_load_symtabs(&sinfo);

	pr_dbg("check filter address match with foo::foo at 0x1000-0x1fff\n");
	uftrace_setup_filter("foo::foo", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);
	TEST_EQ(get_filter_mode(triggers.filter_count), FILTER_MODE_IN);

	pr_dbg("check addresses inside the symbol\n");
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x1000, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_FILTER);
	TEST_EQ(tr.fmode, FILTER_MODE_IN);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x1fff, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_FILTER);
	TEST_EQ(tr.fmode, FILTER_MODE_IN);

	pr_dbg("addresses out of the symbol should not have FILTER flags\n");
	memset(&tr, 0, sizeof(tr));
	TEST_EQ(uftrace_match_filter(0xfff, &triggers, &tr), NULL);
	TEST_NE(tr.flags, TRIGGER_FL_FILTER);

	memset(&tr, 0, sizeof(tr));
	TEST_EQ(uftrace_match_filter(0x2000, &triggers, &tr), NULL);
	TEST_NE(tr.flags, TRIGGER_FL_FILTER);

	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(trigger_setup_actions)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct uftrace_trigger tr;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_REGEX,
		.lp64 = host_is_lp64(),
	};

	filter_test_load_symtabs(&sinfo);

	pr_dbg("checking depth trigger\n");
	uftrace_setup_trigger("foo::bar@depth=2", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x2500, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_DEPTH);
	TEST_EQ(tr.depth, 2);

	pr_dbg("checking backtrace trigger\n");
	uftrace_setup_trigger("foo::bar@backtrace", &sinfo, &triggers, &setting);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x2500, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_DEPTH | TRIGGER_FL_BACKTRACE);

	pr_dbg("checking trace-on trigger\n");
	uftrace_setup_trigger("foo::baz1@traceon", &sinfo, &triggers, &setting);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x3000, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_TRACE_ON);

	pr_dbg("checking trace-off trigger and overwrite the depth\n");
	uftrace_setup_trigger("foo::baz3@trace_off,depth=1", &sinfo, &triggers, &setting);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x5000, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_TRACE_OFF | TRIGGER_FL_DEPTH);
	TEST_EQ(tr.depth, 1);

	pr_dbg("checking caller trigger\n");
	uftrace_setup_trigger("foo::baz2@caller", &sinfo, &triggers, &setting);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x4200, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_CALLER);

	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(trigger_setup_filters)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
		.filter_count = 0,
	};
	struct uftrace_trigger tr;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_REGEX,
		.lp64 = host_is_lp64(),
	};

	filter_test_load_symtabs(&sinfo);

	pr_dbg("setup notrace filter with trigger action\n");
	uftrace_setup_trigger("foo::bar@depth=2,notrace", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);
	TEST_EQ(get_filter_mode(triggers.filter_count), FILTER_MODE_OUT);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x2500, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_DEPTH | TRIGGER_FL_FILTER);
	TEST_EQ(tr.depth, 2);
	TEST_EQ(tr.fmode, FILTER_MODE_OUT);

	pr_dbg("compare regular filter setting with trigger\n");
	uftrace_setup_filter("foo::baz1", &sinfo, &triggers, &setting);
	TEST_EQ(get_filter_mode(triggers.filter_count), FILTER_MODE_IN);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x3000, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_FILTER);
	TEST_EQ(tr.fmode, FILTER_MODE_IN);

	uftrace_setup_trigger("foo::baz2@notrace", &sinfo, &triggers, &setting);
	TEST_EQ(get_filter_mode(triggers.filter_count), FILTER_MODE_IN);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x4100, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_FILTER);
	TEST_EQ(tr.fmode, FILTER_MODE_OUT);

	pr_dbg("check caller filter setting\n");
	uftrace_setup_caller_filter("foo::baz3", &sinfo, &triggers, &setting);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x5000, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_CALLER);

	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

/* same node tests as filter_setup_glob */
TEST_CASE(filter_rbtree_deep_copy)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info orig = {
		.root = RB_ROOT,
	};
	struct uftrace_triggers_info copy = {
		.root = RB_ROOT,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_GLOB,
	};

	filter_test_load_symtabs(&sinfo);

	uftrace_setup_filter("foo::b*", &sinfo, &orig, &setting);
	pr_dbg("checking filter deep copy\n");
	copy = uftrace_deep_copy_triggers(&orig);
	uftrace_cleanup_filter(&orig);

	TEST_EQ(RB_EMPTY_ROOT(&copy.root), false);

	node = rb_first(&copy.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::bar");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz1");
	TEST_EQ(filter->start, 0x3000UL);
	TEST_EQ(filter->end, 0x3000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz2");
	TEST_EQ(filter->start, 0x4000UL);
	TEST_EQ(filter->end, 0x4000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz3");
	TEST_EQ(filter->start, 0x5000UL);
	TEST_EQ(filter->end, 0x5000UL + 0x1000UL);

	uftrace_cleanup_filter(&copy);
	TEST_EQ(RB_EMPTY_ROOT(&copy.root), true);

	return TEST_OK;
}

TEST_CASE(trigger_setup_args)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct uftrace_trigger tr;
	struct uftrace_arg_spec *spec;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_REGEX,
		.lp64 = host_is_lp64(),
		.arch = UFT_CPU_X86_64,
	};
	int count;

	filter_test_load_symtabs(&sinfo);

	pr_dbg("check regular argument setting\n");
	uftrace_setup_argument("foo::bar@arg1", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x2500, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_ARGUMENT);
	TEST_NE(tr.pargs, NULL);

	pr_dbg("compare argument setting via trigger\n");
	uftrace_setup_trigger("foo::bar@arg2/s", &sinfo, &triggers, &setting);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x2500, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_ARGUMENT);
	TEST_NE(tr.pargs, NULL);

	count = 0;
	list_for_each_entry(spec, tr.pargs, list) {
		count++;
		pr_dbg("arg%d: fmt = %d, type = %d\n", spec->idx, spec->fmt, spec->type);

		if (count == 1) {
			TEST_EQ(spec->idx, 1);
			TEST_EQ(spec->fmt, ARG_FMT_AUTO);
			TEST_EQ(spec->type, ARG_TYPE_INDEX);
		}
		else if (count == 2) {
			TEST_EQ(spec->idx, 2);
			TEST_EQ(spec->fmt, ARG_FMT_STR);
			TEST_EQ(spec->type, ARG_TYPE_INDEX);
		}
	}
	TEST_EQ(count, 2);

	pr_dbg("check argument format, type and size\n");
	uftrace_setup_argument("foo::baz1@arg1/i32,arg2/x64,fparg1/32,fparg2", &sinfo, &triggers,
			       &setting);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x3999, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_ARGUMENT);

	count = 0;
	list_for_each_entry(spec, tr.pargs, list) {
		pr_dbg("arg%d: fmt = %d, type = %d, size = %d\n", spec->idx, spec->fmt, spec->type,
		       spec->size);

		switch (++count) {
		case 1:
			TEST_EQ(spec->idx, 1);
			TEST_EQ(spec->fmt, ARG_FMT_SINT);
			TEST_EQ(spec->type, ARG_TYPE_INDEX);
			TEST_EQ(spec->size, 4);
			break;
		case 2:
			TEST_EQ(spec->idx, 2);
			TEST_EQ(spec->fmt, ARG_FMT_HEX);
			TEST_EQ(spec->type, ARG_TYPE_INDEX);
			TEST_EQ(spec->size, 8);
			break;
		case 3:
			TEST_EQ(spec->idx, 1);
			TEST_EQ(spec->fmt, ARG_FMT_FLOAT);
			TEST_EQ(spec->type, ARG_TYPE_FLOAT);
			TEST_EQ(spec->size, 4);
			break;
		case 4:
			TEST_EQ(spec->idx, 2);
			TEST_EQ(spec->fmt, ARG_FMT_FLOAT);
			TEST_EQ(spec->type, ARG_TYPE_FLOAT);
			TEST_EQ(spec->size, 8);
			break;
		default:
			/* should not reach here */
			TEST_EQ(spec->idx, -1);
			break;
		}
	}
	TEST_EQ(count, 4);

	pr_dbg("check argument location\n");
	uftrace_setup_trigger("foo::baz2@arg1/c,arg2/x32%rdi,arg3%stack+4,retval/f64", &sinfo,
			      &triggers, &setting);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x4000, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_ARGUMENT | TRIGGER_FL_RETVAL);

	count = 0;
	list_for_each_entry(spec, tr.pargs, list) {
		pr_dbg("arg%d: fmt = %d, type = %d, size = %d\n", spec->idx, spec->fmt, spec->type,
		       spec->size);

		switch (++count) {
		case 1:
			TEST_EQ(spec->idx, 1);
			TEST_EQ(spec->fmt, ARG_FMT_CHAR);
			TEST_EQ(spec->type, ARG_TYPE_INDEX);
			TEST_EQ(spec->size, 1);
			break;
		case 2:
			TEST_EQ(spec->idx, 2);
			TEST_EQ(spec->fmt, ARG_FMT_HEX);
			TEST_EQ(spec->type, ARG_TYPE_REG);
			TEST_EQ(spec->size, 4);
			TEST_EQ(spec->reg_idx, 1);
			break;
		case 3:
			TEST_EQ(spec->idx, 3);
			TEST_EQ(spec->fmt, ARG_FMT_AUTO);
			TEST_EQ(spec->type, ARG_TYPE_STACK);
			TEST_EQ(spec->size, (int)sizeof(long));
			TEST_EQ(spec->stack_ofs, 4);
			break;
		case 4:
			TEST_EQ(spec->idx, 0);
			TEST_EQ(spec->fmt, ARG_FMT_FLOAT);
			TEST_EQ(spec->type, ARG_TYPE_FLOAT);
			TEST_EQ(spec->size, 8);
			break;
		default:
			/* should not reach here */
			TEST_EQ(spec->idx, -1);
			break;
		}
	}
	TEST_EQ(count, 4);

	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

static struct uftrace_mmap *locfilter_test_load_mmap(void)
{
	static struct uftrace_symbol syms[] = {
		{ 0x1000, 0x1000, ST_GLOBAL_FUNC, "command_dump" },
		{ 0x2000, 0x1000, ST_GLOBAL_FUNC, "command_replay" },
		{ 0x3000, 0x1000, ST_GLOBAL_FUNC, "command_report" },
		{ 0x4000, 0x1000, ST_GLOBAL_FUNC, "command_foo" },
	};

	static struct uftrace_dbg_file dfiles[] = {
		{ .name = "uftrace/cmds/dump.c" },
		{ .name = "uftrace/cmds/replay.c" },
		{ .name = "uftrace/cmds/report.c" },
		{ .name = "uftrace/cmds1/foo.c" },
	};
	static struct uftrace_dbg_loc locs[] = {
		{ .file = &dfiles[0] },
		{ .file = &dfiles[1] },
		{ .file = &dfiles[2] },
		{ .file = &dfiles[3] },
	};

	static struct uftrace_module mod = {
		.symtab = {
			.sym    = syms,
			.nr_sym = ARRAY_SIZE(syms),
		},
		.dinfo = {
			.locs = locs,
			.nr_locs = ARRAY_SIZE(locs),
			.loaded = true,
		}
	};
	static struct uftrace_mmap map = {
		.mod = &mod,
		.start = 0x0,
		.end = 0x6000,
	};

	mod.symtab.sym = syms;
	mod.symtab.nr_sym = ARRAY_SIZE(syms);

	return &map;
}

static struct uftrace_mmap *locfilter_test_load_mmap2(void)
{
	static struct uftrace_symbol syms2[] = {
		{ 0xa000, 0x1000, ST_GLOBAL_FUNC, "util_fstack" },
		{ 0xb000, 0x1000, ST_GLOBAL_FUNC, "util_report" },
	};

	static struct uftrace_dbg_file dfiles2[] = {
		{ .name = "uftrace/utils/fstack.c" },
		{ .name = "uftrace/utils/report.c" },
	};
	static struct uftrace_dbg_loc locs2[] = {
		{ .file = &dfiles2[0] },
		{ .file = &dfiles2[1] },
	};

	static struct uftrace_module mod2 = {
		.symtab = {
			.sym    = syms2,
			.nr_sym = ARRAY_SIZE(syms2),
		},
		.dinfo = {
			.locs = locs2,
			.nr_locs = ARRAY_SIZE(locs2),
			.loaded = true,
		}
	};
	static struct uftrace_mmap map2 = {
		.mod = &mod2,
		.start = 0x0,
		.end = 0xe000,
	};

	mod2.symtab.sym = syms2;
	mod2.symtab.nr_sym = ARRAY_SIZE(syms2);

	return &map2;
}

static void locfilter_test_load_symtabs(struct uftrace_sym_info *sinfo)
{
	struct uftrace_mmap *map = locfilter_test_load_mmap();
	struct uftrace_mmap *map2 = locfilter_test_load_mmap2();

	sinfo->maps = map;
	sinfo->exec_map = map;
	sinfo->loaded = true;

	sinfo->maps->next = map2;
}

/* Simple pattern arguments are treated as regex after conversion. */
TEST_CASE(locfilter_setup_simple)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_REGEX,
	};

	locfilter_test_load_symtabs(&sinfo);

	pr_dbg("checking simple match\n");
	uftrace_setup_loc_filter("uftrace/cmds/replay.c", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_replay");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("checking base name match\n");
	uftrace_setup_loc_filter("dump.c", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_dump");
	TEST_EQ(filter->start, 0x1000UL);
	TEST_EQ(filter->end, 0x1000UL + 0x1000UL);
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("checking unknown symbol\n");
	uftrace_setup_loc_filter("invalid_name", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(locfilter_setup_regex)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_REGEX,
	};

	locfilter_test_load_symtabs(&sinfo);

	pr_dbg("try to match with regex pattern: re.*\n");
	uftrace_setup_loc_filter("re.*", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_replay");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_report");
	TEST_EQ(filter->start, 0x3000UL);
	TEST_EQ(filter->end, 0x3000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "util_report");
	TEST_EQ(filter->start, 0xb000UL);
	TEST_EQ(filter->end, 0xb000UL + 0x1000UL);

	TEST_EQ(rb_next(node), NULL);

	pr_dbg("found 3 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(locfilter_setup_glob)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_GLOB,
	};

	locfilter_test_load_symtabs(&sinfo);

	pr_dbg("try to match with glob pattern: *re*\n");
	uftrace_setup_loc_filter("*re*", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_replay");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_report");
	TEST_EQ(filter->start, 0x3000UL);
	TEST_EQ(filter->end, 0x3000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "util_report");
	TEST_EQ(filter->start, 0xb000UL);
	TEST_EQ(filter->end, 0xb000UL + 0x1000UL);

	TEST_EQ(rb_next(node), NULL);

	pr_dbg("found 3 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

/* Simple pattern arguments are treated as regex after conversion. */
TEST_CASE(locfilter_setup_dir_simple)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_REGEX,
	};

	locfilter_test_load_symtabs(&sinfo);

	pr_dbg("try to match directory with pattern: cmds\n");
	uftrace_setup_loc_filter("cmds", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_dump");
	TEST_EQ(filter->start, 0x1000UL);
	TEST_EQ(filter->end, 0x1000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_replay");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_report");
	TEST_EQ(filter->start, 0x3000UL);
	TEST_EQ(filter->end, 0x3000UL + 0x1000UL);

	TEST_EQ(rb_next(node), NULL);

	pr_dbg("found 3 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("try to match directory with pattern: /cmds\n");
	uftrace_setup_loc_filter("/cmds", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_dump");
	TEST_EQ(filter->start, 0x1000UL);
	TEST_EQ(filter->end, 0x1000UL + 0x1000UL);

	TEST_NE(node = rb_next(node), NULL);
	TEST_NE(node = rb_next(node), NULL);
	TEST_EQ(node = rb_next(node), NULL);

	pr_dbg("found 3 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("try to match directory with pattern: cmds/\n");
	uftrace_setup_loc_filter("cmds/", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_dump");
	TEST_EQ(filter->start, 0x1000UL);
	TEST_EQ(filter->end, 0x1000UL + 0x1000UL);

	TEST_NE(node = rb_next(node), NULL);
	TEST_NE(node = rb_next(node), NULL);
	TEST_EQ(node = rb_next(node), NULL);

	pr_dbg("found 3 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("try to match directory with pattern: /uftrace/cmds/\n");
	uftrace_setup_loc_filter("/uftrace/cmds/", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_dump");
	TEST_EQ(filter->start, 0x1000UL);
	TEST_EQ(filter->end, 0x1000UL + 0x1000UL);

	TEST_NE(node = rb_next(node), NULL);
	TEST_NE(node = rb_next(node), NULL);
	TEST_EQ(node = rb_next(node), NULL);

	pr_dbg("found 3 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("try to match directory with pattern: uftrace/cmds/\n");
	uftrace_setup_loc_filter("uftrace/cmds", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_dump");
	TEST_EQ(filter->start, 0x1000UL);
	TEST_EQ(filter->end, 0x1000UL + 0x1000UL);

	TEST_NE(node = rb_next(node), NULL);
	TEST_NE(node = rb_next(node), NULL);
	TEST_EQ(node = rb_next(node), NULL);

	pr_dbg("found 3 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("try to match directory with pattern: /uftrace\n");
	uftrace_setup_loc_filter("/uftrace", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_dump");
	TEST_EQ(filter->start, 0x1000UL);
	TEST_EQ(filter->end, 0x1000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_replay");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_report");
	TEST_EQ(filter->start, 0x3000UL);
	TEST_EQ(filter->end, 0x3000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_foo");
	TEST_EQ(filter->start, 0x4000UL);
	TEST_EQ(filter->end, 0x4000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "util_fstack");
	TEST_EQ(filter->start, 0xa000UL);
	TEST_EQ(filter->end, 0xa000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "util_report");
	TEST_EQ(filter->start, 0xb000UL);
	TEST_EQ(filter->end, 0xb000UL + 0x1000UL);

	pr_dbg("found 6 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("checking invalid directory match\n");
	uftrace_setup_loc_filter("youftrace", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(locfilter_setup_dir_regex)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_REGEX,
	};

	locfilter_test_load_symtabs(&sinfo);

	pr_dbg("try to match directory with regex pattern: cmds/.*\n");
	uftrace_setup_loc_filter("cmds/.*", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_dump");
	TEST_EQ(filter->start, 0x1000UL);
	TEST_EQ(filter->end, 0x1000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_replay");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_report");
	TEST_EQ(filter->start, 0x3000UL);
	TEST_EQ(filter->end, 0x3000UL + 0x1000UL);

	TEST_EQ(rb_next(node), NULL);

	pr_dbg("found 3 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	pr_dbg("checking invalid directory match\n");
	uftrace_setup_loc_filter("cmd/.*", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(locfilter_setup_dir_glob)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct rb_node *node;
	struct uftrace_filter *filter;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_GLOB,
	};

	locfilter_test_load_symtabs(&sinfo);

	pr_dbg("try to match with glob pattern: *cmds/*\n");
	uftrace_setup_loc_filter("*cmds/*", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);

	node = rb_first(&triggers.root);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_dump");
	TEST_EQ(filter->start, 0x1000UL);
	TEST_EQ(filter->end, 0x1000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_replay");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct uftrace_filter, node);
	TEST_STREQ(filter->name, "command_report");
	TEST_EQ(filter->start, 0x3000UL);
	TEST_EQ(filter->end, 0x3000UL + 0x1000UL);

	TEST_EQ(rb_next(node), NULL);

	pr_dbg("found 3 symbols. done\n");
	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(locfilter_match)
{
	struct uftrace_sym_info sinfo = {
		.loaded = false,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
		.loc_count = 0,
	};
	struct uftrace_trigger tr;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_REGEX,
	};

	locfilter_test_load_symtabs(&sinfo);

	pr_dbg("check filter address match with re.* at 0x2000-0x2fff\n");
	uftrace_setup_filter("re.*", &sinfo, &triggers, &setting);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), false);
	TEST_EQ(get_filter_mode(triggers.filter_count), FILTER_MODE_IN);

	pr_dbg("check addresses inside the symbol\n");
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x2000, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_FILTER);
	TEST_EQ(tr.fmode, FILTER_MODE_IN);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x2fff, &triggers, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_FILTER);
	TEST_EQ(tr.fmode, FILTER_MODE_IN);

	pr_dbg("addresses out of the symbol should not have FILTER flags\n");
	memset(&tr, 0, sizeof(tr));
	TEST_EQ(uftrace_match_filter(0x1fff, &triggers, &tr), NULL);
	TEST_NE(tr.flags, TRIGGER_FL_FILTER);

	memset(&tr, 0, sizeof(tr));
	TEST_EQ(uftrace_match_filter(0xa000, &triggers, &tr), NULL);
	TEST_NE(tr.flags, TRIGGER_FL_FILTER);

	uftrace_cleanup_triggers(&triggers);
	TEST_EQ(RB_EMPTY_ROOT(&triggers.root), true);

	return TEST_OK;
}

TEST_CASE(filter_setup_cond)
{
	struct uftrace_trigger tr = {};
	struct uftrace_filter_setting setting = {};
	char val_str_ok1[] = "foo@filter,if:arg1==1234";
	char val_str_ok2[] = "foo@filter,if:arg2 !=100";
	char val_str_ok3[] = "foo@filter,if:arg3>= 5678";
	char val_str_ok4[] = "foo@filter,if:arg4 < 9876";
	char val_str_ng1[] = "foo@filter,if:name==1234"; /* named arg not supported */
	char val_str_ng2[] = "foo@filter,if:fparg1==1234"; /* fparg not supported */
	char val_str_ng3[] = "foo@filter,if:arg1~=1234"; /* op not supported */
	char val_str_ng4[] = "foo@value,if:arg-1==1234"; /* negative arg index */
	FILE *null_fp = fopen("/dev/null", "w");
	FILE *saved_fp = outfp;

	pr_dbg("check filter cond: %s\n", val_str_ok1);
	TEST_EQ(setup_trigger_action(val_str_ok1, &tr, NULL, 0, &setting), 0);
	TEST_EQ(tr.cond.idx, 1);
	TEST_EQ(tr.cond.op, FILTER_OP_EQ);
	TEST_EQ(tr.cond.val, 1234);

	pr_dbg("check filter cond: %s\n", val_str_ok2);
	TEST_EQ(setup_trigger_action(val_str_ok2, &tr, NULL, 0, &setting), 0);
	TEST_EQ(tr.cond.idx, 2);
	TEST_EQ(tr.cond.op, FILTER_OP_NE);
	TEST_EQ(tr.cond.val, 100);

	pr_dbg("check filter cond: %s\n", val_str_ok3);
	TEST_EQ(setup_trigger_action(val_str_ok3, &tr, NULL, 0, &setting), 0);
	TEST_EQ(tr.cond.idx, 3);
	TEST_EQ(tr.cond.op, FILTER_OP_GE);
	TEST_EQ(tr.cond.val, 5678);

	pr_dbg("check filter cond: %s\n", val_str_ok4);
	TEST_EQ(setup_trigger_action(val_str_ok4, &tr, NULL, 0, &setting), 0);
	TEST_EQ(tr.cond.idx, 4);
	TEST_EQ(tr.cond.op, FILTER_OP_LT);
	TEST_EQ(tr.cond.val, 9876);

	memset(&tr, 0, sizeof(tr));
	/* suppress usage error messages */
	if (!debug)
		outfp = null_fp;

	TEST_NE(setup_trigger_action(val_str_ng1, &tr, NULL, 0, &setting), 0);
	TEST_NE(setup_trigger_action(val_str_ng2, &tr, NULL, 0, &setting), 0);
	TEST_NE(setup_trigger_action(val_str_ng3, &tr, NULL, 0, &setting), 0);
	TEST_NE(setup_trigger_action(val_str_ng4, &tr, NULL, 0, &setting), 0);

	if (!debug)
		outfp = saved_fp;

	/* failed function should not set any fields */
	TEST_EQ(tr.cond.idx, 0);
	TEST_EQ(tr.cond.op, 0);
	TEST_EQ(tr.cond.val, 0);

	return TEST_OK;
}

TEST_CASE(filter_eval_cond)
{
	struct uftrace_filter_cond cond;

	pr_dbg("check filter cond: arg == 1\n");
	cond.op = FILTER_OP_EQ;
	cond.val = 1;

	TEST_EQ(uftrace_eval_cond(&cond, 1), true);
	TEST_EQ(uftrace_eval_cond(&cond, 2), false);

	pr_dbg("check filter cond: arg == -1\n");
	cond.op = FILTER_OP_EQ;
	cond.val = -1;

	TEST_EQ(uftrace_eval_cond(&cond, 1), false);
	TEST_EQ(uftrace_eval_cond(&cond, -1), true);

	pr_dbg("check filter cond: arg != 1\n");
	cond.op = FILTER_OP_NE;
	cond.val = 1;

	TEST_EQ(uftrace_eval_cond(&cond, 1), false);
	TEST_EQ(uftrace_eval_cond(&cond, 0), true);

	pr_dbg("check filter cond: arg > 10\n");
	cond.op = FILTER_OP_GT;
	cond.val = 10;

	TEST_EQ(uftrace_eval_cond(&cond, 11), true);
	TEST_EQ(uftrace_eval_cond(&cond, 10), false);
	TEST_EQ(uftrace_eval_cond(&cond, -1), false);

	pr_dbg("check filter cond: arg >= 10\n");
	cond.op = FILTER_OP_GE;
	cond.val = 10;

	TEST_EQ(uftrace_eval_cond(&cond, 11), true);
	TEST_EQ(uftrace_eval_cond(&cond, 10), true);
	TEST_EQ(uftrace_eval_cond(&cond, 9), false);

	pr_dbg("check filter cond: arg < 0\n");
	cond.op = FILTER_OP_LT;
	cond.val = 0;

	TEST_EQ(uftrace_eval_cond(&cond, 1), false);
	TEST_EQ(uftrace_eval_cond(&cond, 0), false);
	TEST_EQ(uftrace_eval_cond(&cond, -1), true);

	pr_dbg("check filter cond: arg <= 0\n");
	cond.op = FILTER_OP_LE;
	cond.val = 0;

	TEST_EQ(uftrace_eval_cond(&cond, 1), false);
	TEST_EQ(uftrace_eval_cond(&cond, 0), true);
	TEST_EQ(uftrace_eval_cond(&cond, -1), true);

	return TEST_OK;
}

#endif /* UNIT_TEST */
