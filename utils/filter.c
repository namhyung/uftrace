#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <sys/utsname.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "filter"
#define PR_DOMAIN  DBG_FILTER

#include "libmcount/mcount.h"
#include "utils/filter.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"
#include "utils/utils.h"
#include "utils/list.h"


static void print_trigger(struct ftrace_trigger *tr)
{
	if (tr->flags & TRIGGER_FL_DEPTH)
		pr_dbg("\ttrigger: depth %d\n", tr->depth);
	if (tr->flags & TRIGGER_FL_FILTER) {
		if (tr->fmode == FILTER_MODE_IN)
			pr_dbg("\ttrigger: filter IN\n");
		else
			pr_dbg("\ttrigger: filter OUT\n");
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

	if (tr->flags & TRIGGER_FL_ARGUMENT) {
		struct ftrace_arg_spec *arg;

		pr_dbg("\ttrigger: argument\n");
		list_for_each_entry(arg, tr->pargs, list) {
			if (arg->idx == RETVAL_IDX)
				continue;
			pr_dbg("\t\t arg%d: %c%d\n", arg->idx,
			       ARG_SPEC_CHARS[arg->fmt], arg->size * 8);
		}
	}
	if (tr->flags & TRIGGER_FL_RETVAL) {
		struct ftrace_arg_spec *arg;

		pr_dbg("\ttrigger: return value\n");
		list_for_each_entry(arg, tr->pargs, list) {
			if (arg->idx != RETVAL_IDX)
				continue;
			pr_dbg("\t\t retval%d: %c%d\n", arg->idx,
			       ARG_SPEC_CHARS[arg->fmt], arg->size * 8);
		}
	}

	if (tr->flags & TRIGGER_FL_COLOR)
		pr_dbg("\ttrigger: color '%c'\n", tr->color);
	if (tr->flags & TRIGGER_FL_TIME_FILTER)
		pr_dbg("\ttrigger: time filter %"PRIu64"\n", tr->time);
}

static bool match_ip(struct ftrace_filter *filter, unsigned long ip)
{
	return filter->start <= ip && ip < filter->end;
}

/**
 * uftrace_match_filter - try to match @ip with filters in @root
 * @ip   - instruction address to match
 * @root - root of rbtree which has filters
 * @tr   - trigger data
 */
struct ftrace_filter *uftrace_match_filter(uint64_t ip, struct rb_root *root,
					   struct ftrace_trigger *tr)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct ftrace_filter *iter;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct ftrace_filter, node);

		if (match_ip(iter, ip)) {
			memcpy(tr, &iter->trigger, sizeof(*tr));

			pr_dbg2("filter match: %s\n", iter->name);
			if (dbg_domain[DBG_FILTER] >= 3)
				print_trigger(tr);
			return iter;
		}

		if (iter->start > ip)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	return NULL;
}

static void add_arg_spec(struct list_head *arg_list, struct ftrace_arg_spec *arg,
			 bool exact_match)
{
	bool found = false;
	struct ftrace_arg_spec *oarg, *narg;

	list_for_each_entry(oarg, arg_list, list) {
		switch (arg->type) {
		case ARG_TYPE_INDEX:
		case ARG_TYPE_FLOAT:
			if (arg->type == oarg->type && arg->idx == oarg->idx)
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
			oarg->fmt   = arg->fmt;
			oarg->size  = arg->size;
			oarg->exact = exact_match;
			oarg->type  = arg->type;
			oarg->reg_idx = arg->reg_idx;
		}
	}
	else {
		narg = xmalloc(sizeof(*narg));
		memcpy(narg, arg, sizeof(*narg));
		narg->exact = exact_match;

		/* sort args by index */
		list_for_each_entry(oarg, arg_list, list) {
			if (oarg->type == arg->type && oarg->idx > arg->idx)
				break;
		}

		list_add_tail(&narg->list, &oarg->list);
	}
}

static void add_trigger(struct ftrace_filter *filter, struct ftrace_trigger *tr,
			bool exact_match)
{
	filter->trigger.flags |= tr->flags;

	if (tr->flags & TRIGGER_FL_DEPTH)
		filter->trigger.depth = tr->depth;
	if (tr->flags & TRIGGER_FL_FILTER)
		filter->trigger.fmode = tr->fmode;

	if (tr->flags & TRIGGER_FL_TRACE_ON)
		filter->trigger.flags &= ~TRIGGER_FL_TRACE_OFF;
	if (tr->flags & TRIGGER_FL_TRACE_OFF)
		filter->trigger.flags &= ~TRIGGER_FL_TRACE_ON;

	if (tr->flags & (TRIGGER_FL_ARGUMENT | TRIGGER_FL_RETVAL)) {
		struct ftrace_arg_spec *arg;

		list_for_each_entry(arg, tr->pargs, list)
			add_arg_spec(&filter->args, arg, exact_match);
	}

	if (tr->flags & TRIGGER_FL_COLOR)
		filter->trigger.color = tr->color;
	if (tr->flags & TRIGGER_FL_TIME_FILTER)
		filter->trigger.time = tr->time;
}

static void add_filter(struct rb_root *root, struct ftrace_filter *filter,
		       struct ftrace_trigger *tr, bool exact_match)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct ftrace_filter *iter, *new;

	pr_dbg("add filter for %s\n", filter->name);
	if (dbg_domain[DBG_FILTER] >= 3)
		print_trigger(tr);

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct ftrace_filter, node);

		if (iter->start == filter->start) {
			add_trigger(iter, tr, exact_match);
			return;
		}

		if (iter->start > filter->start)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	new = xmalloc(sizeof(*new));
	memcpy(new, filter, sizeof(*new));
	new->trigger.flags = 0;
	INIT_LIST_HEAD(&new->args);
	new->trigger.pargs = &new->args;

	add_trigger(new, tr, exact_match);

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);
}

static int add_exact_filter(struct rb_root *root, struct symtab *symtab,
			    char *filter_str, struct ftrace_trigger *tr)
{
	struct ftrace_filter filter;
	struct sym *sym;

	sym = find_symname(symtab, filter_str);
	if (sym == NULL)
		return 0;

	filter.name = sym->name;
	filter.start = sym->addr;
	filter.end = sym->addr + sym->size;

	add_filter(root, &filter, tr, true);
	return 1;
}

static int add_regex_filter(struct rb_root *root, struct symtab *symtab,
			    char *filter_str, struct ftrace_trigger *tr)
{
	struct ftrace_filter filter;
	struct sym *sym;
	regex_t re;
	unsigned i;
	int ret = 0;

	if (regcomp(&re, filter_str, REG_NOSUB | REG_EXTENDED)) {
		pr_dbg("regex pattern failed: %s\n", filter_str);
		return 0;
	}

	for (i = 0; i < symtab->nr_sym; i++) {
		sym = &symtab->sym[i];

		if (regexec(&re, sym->name, 0, NULL, 0))
			continue;

		filter.name = sym->name;
		filter.start = sym->addr;
		filter.end = sym->addr + sym->size;

		add_filter(root, &filter, tr, false);
		ret++;
	}

	return ret;
}

static bool is_arm_machine(void)
{
	static char *mach = NULL;

	if (mach == NULL) {
		struct utsname utsbuf;

		uname(&utsbuf);
		mach = xstrdup(utsbuf.machine);
	}

	return mach[0] == 'a' && mach[1] == 'r' && mach[2] == 'm';
}

/* argument_spec = arg1/i32,arg2/x64,... */
static int parse_spec(char *str, struct ftrace_arg_spec *arg, char *suffix)
{
	int fmt = ARG_FMT_AUTO;
	int size = sizeof(long);
	int type = arg->type;
	int bit;

	if (suffix == NULL || *suffix == '\0')
		goto out;

	if (*suffix == '%')
		goto type;

	suffix++;
	switch (*suffix) {
	case 'i':
		fmt = ARG_FMT_SINT;
		break;
	case 'u':
		fmt = ARG_FMT_UINT;
		break;
	case 'x':
		fmt = ARG_FMT_HEX;
		break;
	case 's':
		fmt = ARG_FMT_STR;
		break;
	case 'c':
		fmt = ARG_FMT_CHAR;
		size = sizeof(char);
		break;
	case 'f':
		fmt = ARG_FMT_FLOAT;
		size = sizeof(double);
		break;
	default:
		pr_use("unsupported argument type: %s\n", str);
		return -1;
	}

	suffix++;
	if (*suffix == '\0')
		goto out;
	if (*suffix == '%')
		goto type;

	bit = strtol(suffix, &suffix, 10);
	switch (bit) {
	case 8:
	case 16:
	case 32:
	case 64:
		size = bit / 8;
		break;
	case 80:
		if (fmt == ARG_FMT_FLOAT) {
			size = bit / 8;
			break;
		}
		/* fall through */
	default:
		pr_use("unsupported argument size: %s\n", str);
		return -1;
	}

type:
	if (*suffix == '%') {
		suffix++;

		if (!strncmp(suffix, "stack", 5)) {
			arg->stack_ofs = strtol(suffix+5, NULL, 0);
			type = ARG_TYPE_STACK;
		}
		else {
			arg->reg_idx = arch_register_index(suffix);
			type = ARG_TYPE_REG;

			if (arg->reg_idx < 0) {
				pr_use("unknown register name: %s\n", str);
				return -1;
			}
		}
	}

out:
	/* it seems ARM falls back 'long double' to 'double' */
	if (fmt == ARG_FMT_FLOAT && size == 10 && is_arm_machine())
		size = 8;

	arg->fmt  = fmt;
	arg->size = size;
	arg->type = type;

	return 0;
}

/* argument_spec = arg1/i32,arg2/x64%reg,arg3%stack+1,... */
static int parse_argument_spec(char *str, struct ftrace_trigger *tr)
{
	struct ftrace_arg_spec *arg;
	char *suffix;

	if (!isdigit(str[3])) {
		pr_use("skipping invalid argument: %s\n", str);
		return -1;
	}

	arg = xmalloc(sizeof(*arg));
	INIT_LIST_HEAD(&arg->list);
	arg->idx = strtol(str+3, &suffix, 0);
	arg->type = ARG_TYPE_INDEX;

	if (parse_spec(str, arg, suffix) == -1) {
		free(arg);
		return -1;
	}

	tr->flags |= TRIGGER_FL_ARGUMENT;
	list_add_tail(&arg->list, tr->pargs);

	return 0;
}
/* argument_spec = retval/i32 or retval/x64 ... */
static int parse_retval_spec(char *str, struct ftrace_trigger *tr)
{
	struct ftrace_arg_spec *arg;
	char *suffix;

	arg = xmalloc(sizeof(*arg));
	INIT_LIST_HEAD(&arg->list);
	arg->idx = 0;
	arg->type = ARG_TYPE_INDEX;

	/* set suffix after string "retval" */
	suffix = str + 6;

	if (parse_spec(str, arg, suffix) == -1) {
		free(arg);
		return -1;
	}

	tr->flags |= TRIGGER_FL_RETVAL;
	list_add_tail(&arg->list, tr->pargs);

	return 0;
}

/* argument_spec = fparg1/32,fparg2/64%stack+1,... */
static int parse_float_argument_spec(char *str, struct ftrace_trigger *tr)
{
	struct ftrace_arg_spec *arg;
	char *suffix;

	if (!isdigit(str[5])) {
		pr_use("skipping invalid argument: %s\n", str);
		return -1;
	}

	arg = xmalloc(sizeof(*arg));
	INIT_LIST_HEAD(&arg->list);
	arg->idx = strtol(str+5, &suffix, 0);
	arg->fmt = ARG_FMT_FLOAT;
	arg->type = ARG_TYPE_FLOAT;
	arg->size = sizeof(double);

	if (*suffix == '/') {
		long size = strtol(suffix+1, &suffix, 0);

		if (size != 32 && size != 64 && size != 80) {
			pr_use("invalid argument size: %s\n", str);
			free(arg);
			return -1;
		}
		if (size == 80 && is_arm_machine())
			size = 64;

		arg->size = size / 8;
	}

	if (*suffix == '%') {
		suffix++;

		if (!strncmp(suffix, "stack", 5)) {
			arg->stack_ofs = strtol(suffix+5, NULL, 0);
			arg->type = ARG_TYPE_STACK;
		}
		else {
			arg->reg_idx = arch_register_index(suffix);
			arg->type = ARG_TYPE_REG;

			if (arg->reg_idx < 0) {
				pr_use("unknown register name: %s\n", str);
				free(arg);
				return -1;
			}
		}
	}

	tr->flags |= TRIGGER_FL_ARGUMENT;
	list_add_tail(&arg->list, tr->pargs);

	return 0;
}

static int setup_module_and_trigger(char *str, struct symtabs *symtabs,
				    struct symtab **psymtab,
				    struct ftrace_trigger *tr,
				    bool *found_mod)
{
	char *pos = strchr(str, '@');

	if (pos) {
		char *tr_str;

		*pos++ = '\0';
		tr_str = xstrdup(pos);

		while ((pos = strsep(&tr_str, ",")) != NULL) {
			if (!strncasecmp(pos, "depth=", 6)) {
				tr->flags |= TRIGGER_FL_DEPTH;
				tr->depth = strtoul(pos+6, NULL, 10);

				if (tr->depth < 0 ||
				    tr->depth > MCOUNT_RSTACK_MAX) {
					pr_use("skipping invalid trigger depth: %d\n",
					       tr->depth);
					return -1;
				}
				continue;
			}

			if (!strcasecmp(pos, "backtrace")) {
				tr->flags |= TRIGGER_FL_BACKTRACE;
				continue;
			}

			if (!strncasecmp(pos, "trace", 5)) {
				pos += 5;
				if (*pos == '_' || *pos == '-')
					pos++;

				if (*pos == '\0')
					tr->flags |= TRIGGER_FL_TRACE;
				else if (!strcasecmp(pos, "on"))
					tr->flags |= TRIGGER_FL_TRACE_ON;
				else if (!strcasecmp(pos, "off"))
					tr->flags |= TRIGGER_FL_TRACE_OFF;

				continue;
			}
			else if (!strncasecmp(pos, "arg", 3)) {
				if (parse_argument_spec(pos, tr) < 0)
					return -1;
				continue;
			}
			else if (!strncasecmp(pos, "fparg", 5)) {
				if (parse_float_argument_spec(pos, tr) < 0)
					return -1;
				continue;
			}
			else if (!strncasecmp(pos, "retval", 6)) {
				if (parse_retval_spec(pos, tr) < 0)
					return -1;
				continue;
			}

			if (!strcasecmp(pos, "recover")) {
				tr->flags |= TRIGGER_FL_RECOVER;
				continue;
			}

			if (!strncasecmp(pos, "color=", 6)) {
				const char *color = pos + 6;
				tr->flags |= TRIGGER_FL_COLOR;

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
					/* invalid color is ignored */
				}
				continue;
			}

			if (!strncasecmp(pos, "time=", 5)) {
				tr->flags |= TRIGGER_FL_TIME_FILTER;
				tr->time = parse_time(pos+5, 3);
				continue;
			}

			if (!strcasecmp(pos, "plt"))
				*psymtab = &symtabs->dsymtab;
			else if (!strcasecmp(pos, "kernel"))
				*psymtab = get_kernel_symtab();
			else if (!strcmp(pos, basename(symtabs->filename)))
				*psymtab = &symtabs->symtab;
			else {
				struct ftrace_proc_maps *map;

				map = find_map_by_name(symtabs, pos);
				if (map == NULL) {
					pr_dbg("cannot find module %s\n", pos);
					return -1;
				}

				*psymtab = &map->symtab;
			}

			*found_mod = true;
		}
	}

	return 0;
}

static void setup_trigger(char *filter_str, struct symtabs *symtabs,
			  struct rb_root *root,
			  unsigned long flags, enum filter_mode *fmode)
{
	char *str;
	char *pos, *name;

	if (filter_str == NULL)
		return;

	pos = str = strdup(filter_str);
	if (str == NULL)
		return;

	name = strtok(pos, ";");
	while (name) {
		struct symtab *symtab = &symtabs->symtab;
		LIST_HEAD(args);
		struct ftrace_trigger tr = {
			.flags = flags,
			.pargs = &args,
		};
		int ret = 0;
		bool mod_found = false;
		struct ftrace_arg_spec *arg;
		bool is_regex = strpbrk(name, REGEX_CHARS);

		if (setup_module_and_trigger(name, symtabs, &symtab,
					     &tr, &mod_found) < 0)
			goto next;

		/* skip unintended kernel symbols */
		if (symtab == NULL)
			goto next;

		if (name[0] == '!') {
			tr.fmode = FILTER_MODE_OUT;
			name++;
		} else if (fmode != NULL)
			tr.fmode = FILTER_MODE_IN;

again:
		if (is_regex)
			ret += add_regex_filter(root, symtab, name, &tr);
		else
			ret += add_exact_filter(root, symtab, name, &tr);

		if (!mod_found && (ret == 0 || is_regex)) {
			symtab = &symtabs->dsymtab;
			mod_found = true;
			goto again;
		}

		if (ret > 0 && fmode != NULL) {
			if (tr.fmode == FILTER_MODE_IN)
				*fmode = FILTER_MODE_IN;
			else if (*fmode == FILTER_MODE_NONE)
				*fmode = FILTER_MODE_OUT;
		}
next:
		name = strtok(NULL, ";");

		while (!list_empty(&args)) {
			arg = list_first_entry(&args, struct ftrace_arg_spec, list);
			list_del(&arg->list);
			free(arg);
		}

	}

	free(str);
}

/**
 * ftrace_setup_filter - construct rbtree of filters
 * @filter_str - CSV of filter string
 * @symtabs    - symbol tables to find symbol address
 * @root       - root of resulting rbtree
 * @mode       - filter mode: opt-in (-F) or opt-out (-N)
 */
void ftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			 struct rb_root *root, enum filter_mode *mode)
{
	setup_trigger(filter_str, symtabs, root, TRIGGER_FL_FILTER, mode);
}

/**
 * ftrace_setup_trigger - construct rbtree of triggers
 * @trigger_str - CSV of trigger string (FUNC @ act)
 * @symtabs    - symbol tables to find symbol address
 * @root       - root of resulting rbtree
 */
void ftrace_setup_trigger(char *trigger_str, struct symtabs *symtabs,
			  struct rb_root *root)
{
	setup_trigger(trigger_str, symtabs, root, 0, NULL);
}

/**
 * ftrace_setup_argument - construct rbtree of argument
 * @args_str   - CSV of argument string (FUNC @ arg)
 * @symtabs    - symbol tables to find symbol address
 * @root       - root of resulting rbtree
 */
void ftrace_setup_argument(char *args_str, struct symtabs *symtabs,
			   struct rb_root *root)
{
	setup_trigger(args_str, symtabs, root, 0, NULL);
}

/**
 * ftrace_setup_retval - construct rbtree of retval
 * @retval_str   - CSV of argument string (FUNC @ arg)
 * @symtabs    - symbol tables to find symbol address
 * @root       - root of resulting rbtree
 */
void ftrace_setup_retval(char *retval_str, struct symtabs *symtabs,
			 struct rb_root *root)
{
	setup_trigger(retval_str, symtabs, root, 0, NULL);
}

void ftrace_setup_filter_module(char *trigger_str, struct list_head *head,
				const char *modname)
{
	char *str, *tmp;
	char *pos, *name, *action;
	struct filter_module *fm;

	if (trigger_str == NULL)
		return;

	pos = str = strdup(trigger_str);
	if (str == NULL)
		return;

	name = strtok_r(pos, ";", &tmp);
	while (name) {
		pos = strchr(name, '@');
		if (pos == NULL)
			goto next;

		*pos++ = '\0';
		action = pos;

		while ((pos = strsep(&action, ",")) != NULL) {
			if (!strncasecmp(pos, "depth=", 6))
				continue;
			if (!strcasecmp(pos, "backtrace"))
				continue;
			if (!strcasecmp(pos, "recover"))
				continue;
			if (!strncasecmp(pos, "arg", 3) && isdigit(pos[3]))
				continue;
			if (!strncasecmp(pos, "fparg", 5) && isdigit(pos[5]))
				continue;
			if (!strncasecmp(pos, "retval", 6))
				continue;
			if (!strncasecmp(pos, "trace", 5)) {
				int n = 5;
				if (pos[n] == '_' || pos[n] == '-')
					n++;

				if (pos[n] == '\0' ||
				    !strcasecmp(&pos[n], "on") ||
				    !strcasecmp(&pos[n], "off"))
					continue;
			}

			if (!strcmp(pos, basename(modname)))
				goto next;

			list_for_each_entry(fm, head, list) {
				if (!strcasecmp(fm->name, pos))
					goto next;
			}

			fm = xmalloc(sizeof(*fm) + strlen(pos) + 1);
			strcpy(fm->name, pos);
			list_add_tail(&fm->list, head);
		}

next:
		name = strtok_r(NULL, ";", &tmp);
	}

	free(str);
}

void ftrace_cleanup_filter_module(struct list_head *head)
{
	struct filter_module *fm;

	while (!list_empty(head)) {
		fm = list_first_entry(head, struct filter_module, list);
		list_del(&fm->list);
		free(fm);
	}
}

/**
 * ftrace_cleanup_filter - delete filters in rbtree
 * @root - root of the filter rbtree
 */
void ftrace_cleanup_filter(struct rb_root *root)
{
	struct rb_node *node;
	struct ftrace_filter *filter;
	struct ftrace_arg_spec *arg, *tmp;

	while (!RB_EMPTY_ROOT(root)) {
		node = rb_first(root);
		filter = rb_entry(node, struct ftrace_filter, node);

		rb_erase(node, root);

		list_for_each_entry_safe(arg, tmp, &filter->args, list) {
			list_del(&arg->list);
			free(arg);
		}
		free(filter);
	}
}

/**
 * ftrace_print_filter - print all filters in rbtree
 * @root - root of the filter rbtree
 */
void ftrace_print_filter(struct rb_root *root)
{
	struct rb_node *node;
	struct ftrace_filter *filter;

	node = rb_first(root);
	while (node) {
		filter = rb_entry(node, struct ftrace_filter, node);
		pr_dbg("%lx-%lx: %s\n", filter->start, filter->end, filter->name);
		print_trigger(&filter->trigger);

		node = rb_next(node);
	}
}

char * uftrace_clear_kernel(char *filter_str)
{
	char *str, *pos, *ret, *tmp;

	/* check filter string contains a kernel filter */
	if (filter_str == NULL)
		return NULL;

	if (strstr(filter_str, "@kernel") == NULL)
		return xstrdup(filter_str);

	str = pos = xstrdup(filter_str);
	ret = NULL;

	pos = strtok_r(pos, ";", &tmp);
	while (pos) {
		if (strstr(pos, "@kernel") == NULL)
			ret = strjoin(ret, pos, ";");

		pos = strtok_r(NULL, ";", &tmp);
	}
	free(str);

	return ret;
}

#ifdef UNIT_TEST

static void filter_test_load_symtabs(struct symtabs *stabs)
{
	static struct sym syms[] = {
		{ 0x1000, 0x1000, ST_GLOBAL, "foo::foo" },
		{ 0x2000, 0x1000, ST_GLOBAL, "foo::bar" },
		{ 0x3000, 0x1000, ST_GLOBAL, "foo::baz1" },
		{ 0x4000, 0x1000, ST_GLOBAL, "foo::baz2" },
		{ 0x5000, 0x1000, ST_GLOBAL, "foo::baz3" },
		{ 0x6000, 0x1000, ST_GLOBAL, "foo::~foo" },
	};
	static struct sym dsyms[] = {
		{ 0x21000, 0x1000, ST_PLT, "malloc" },
		{ 0x22000, 0x1000, ST_PLT, "free" },
	};

	stabs->symtab.sym = syms;
	stabs->symtab.nr_sym = ARRAY_SIZE(syms);
	stabs->dsymtab.sym = dsyms;
	stabs->dsymtab.nr_sym = ARRAY_SIZE(dsyms);
	stabs->loaded = true;
}

TEST_CASE(filter_setup_exact)
{
	struct symtabs stabs = {
		.loaded = false,
	};
	struct rb_root root = RB_ROOT;
	struct rb_node *node;
	struct ftrace_filter *filter;

	filter_test_load_symtabs(&stabs);

	/* test1: simple method */
	ftrace_setup_filter("foo::bar", &stabs, &root, NULL);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);

	node = rb_first(&root);
	filter = rb_entry(node, struct ftrace_filter, node);
	TEST_STREQ(filter->name, "foo::bar");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	ftrace_cleanup_filter(&root);
	TEST_EQ(RB_EMPTY_ROOT(&root), true);

	/* test2: destructor */
	ftrace_setup_filter("foo::~foo", &stabs, &root, NULL);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);

	node = rb_first(&root);
	filter = rb_entry(node, struct ftrace_filter, node);
	TEST_STREQ(filter->name, "foo::~foo");
	TEST_EQ(filter->start, 0x6000UL);
	TEST_EQ(filter->end, 0x6000UL + 0x1000UL);

	ftrace_cleanup_filter(&root);
	TEST_EQ(RB_EMPTY_ROOT(&root), true);

	/* test3: unknown symbol */
	ftrace_setup_filter("invalid_name", &stabs, &root, NULL);
	TEST_EQ(RB_EMPTY_ROOT(&root), true);

	return TEST_OK;
}

TEST_CASE(filter_setup_regex)
{
	struct symtabs stabs = {
		.loaded = false,
	};;
	struct rb_root root = RB_ROOT;
	struct rb_node *node;
	struct ftrace_filter *filter;

	filter_test_load_symtabs(&stabs);

	ftrace_setup_filter("foo::b.*", &stabs, &root, NULL);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);

	node = rb_first(&root);
	filter = rb_entry(node, struct ftrace_filter, node);
	TEST_STREQ(filter->name, "foo::bar");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct ftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz1");
	TEST_EQ(filter->start, 0x3000UL);
	TEST_EQ(filter->end, 0x3000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct ftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz2");
	TEST_EQ(filter->start, 0x4000UL);
	TEST_EQ(filter->end, 0x4000UL + 0x1000UL);

	node = rb_next(node);
	filter = rb_entry(node, struct ftrace_filter, node);
	TEST_STREQ(filter->name, "foo::baz3");
	TEST_EQ(filter->start, 0x5000UL);
	TEST_EQ(filter->end, 0x5000UL + 0x1000UL);

	ftrace_cleanup_filter(&root);
	TEST_EQ(RB_EMPTY_ROOT(&root), true);

	return TEST_OK;
}

TEST_CASE(filter_setup_notrace)
{
	struct symtabs stabs = {
		.loaded = false,
	};;
	struct rb_root root = RB_ROOT;
	struct rb_node *node;
	struct ftrace_filter *filter;
	enum filter_mode fmode;

	filter_test_load_symtabs(&stabs);

	ftrace_setup_filter("foo::.*", &stabs, &root, &fmode);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);
	TEST_EQ(fmode, FILTER_MODE_IN);

	ftrace_setup_filter("!foo::foo", &stabs, &root, &fmode);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);
	TEST_EQ(fmode, FILTER_MODE_IN);  /* overall filter mode doesn't change */

	node = rb_first(&root);
	filter = rb_entry(node, struct ftrace_filter, node);
	TEST_STREQ(filter->name, "foo::foo");
	TEST_EQ(filter->trigger.flags, TRIGGER_FL_FILTER);
	TEST_EQ(filter->trigger.fmode, FILTER_MODE_OUT);

	node = rb_next(node);
	filter = rb_entry(node, struct ftrace_filter, node);
	TEST_STREQ(filter->name, "foo::bar");
	TEST_EQ(filter->trigger.flags, TRIGGER_FL_FILTER);
	TEST_EQ(filter->trigger.fmode, FILTER_MODE_IN);

	ftrace_cleanup_filter(&root);
	TEST_EQ(RB_EMPTY_ROOT(&root), true);

	return TEST_OK;
}

TEST_CASE(filter_match)
{
	struct symtabs stabs = {
		.loaded = false,
	};;
	struct rb_root root = RB_ROOT;
	struct rb_node *node;
	struct ftrace_filter *filter;
	enum filter_mode fmode;
	struct ftrace_trigger tr;

	filter_test_load_symtabs(&stabs);

	ftrace_setup_filter("foo::foo", &stabs, &root, &fmode);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);
	TEST_EQ(fmode, FILTER_MODE_IN);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x1000, &root, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_FILTER);
	TEST_EQ(tr.fmode, FILTER_MODE_IN);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x1fff, &root, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_FILTER);
	TEST_EQ(tr.fmode, FILTER_MODE_IN);

	memset(&tr, 0, sizeof(tr));
	TEST_EQ(uftrace_match_filter(0xfff, &root, &tr), NULL);
	TEST_NE(tr.flags, TRIGGER_FL_FILTER);

	memset(&tr, 0, sizeof(tr));
	TEST_EQ(uftrace_match_filter(0x2000, &root, &tr), NULL);
	TEST_NE(tr.flags, TRIGGER_FL_FILTER);

	ftrace_cleanup_filter(&root);
	TEST_EQ(RB_EMPTY_ROOT(&root), true);

	return TEST_OK;
}

TEST_CASE(trigger_setup)
{
	struct symtabs stabs = {
		.loaded = false,
	};;
	struct rb_root root = RB_ROOT;
	struct rb_node *node;
	struct ftrace_filter *filter;
	struct ftrace_trigger tr;

	filter_test_load_symtabs(&stabs);

	ftrace_setup_trigger("foo::bar@depth=2", &stabs, &root);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x2500, &root, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_DEPTH);
	TEST_EQ(tr.depth, 2);

	ftrace_setup_trigger("foo::bar@backtrace", &stabs, &root);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x2500, &root, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_DEPTH | TRIGGER_FL_BACKTRACE);

	ftrace_setup_trigger("foo::baz1@traceon", &stabs, &root);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x3000, &root, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_TRACE_ON);

	ftrace_setup_trigger("foo::baz3@trace_off,depth=1", &stabs, &root);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(uftrace_match_filter(0x5000, &root, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_TRACE_OFF | TRIGGER_FL_DEPTH);
	TEST_EQ(tr.depth, 1);

	ftrace_cleanup_filter(&root);
	TEST_EQ(RB_EMPTY_ROOT(&root), true);

	return TEST_OK;
}

#endif /* UNIT_TEST */
