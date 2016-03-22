#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <ctype.h>

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
			pr_dbg("\t\t arg%d: %c%d\n", arg->idx,
			       ARG_SPEC_CHARS[arg->fmt], arg->size * 8);
		}
	}
}

static bool match_ip(struct ftrace_filter *filter, unsigned long ip)
{
	return filter->start <= ip && ip < filter->end;
}

/**
 * ftrace_match_filter - try to match @ip with filters in @root
 * @root - root of rbtree which has filters
 * @ip   - instruction address to match
 * @tr   - trigger data
 */
struct ftrace_filter *ftrace_match_filter(struct rb_root *root, unsigned long ip,
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

static void add_trigger(struct ftrace_filter *filter, struct ftrace_trigger *tr,
			bool copy_args)
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

	if (tr->flags & TRIGGER_FL_ARGUMENT) {
		struct ftrace_arg_spec *arg, *new;

		if (!copy_args) {
			list_splice_tail_init(tr->pargs, &filter->args);
			return;
		}

		list_for_each_entry(arg, tr->pargs, list) {
			new = xmalloc(sizeof(*new));
			memcpy(new, arg, sizeof(*new));
			list_add_tail(&new->list, &filter->args);
		}
	}
}

static void add_filter(struct rb_root *root, struct ftrace_filter *filter,
		       struct ftrace_trigger *tr, bool copy_args)
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
			add_trigger(iter, tr, copy_args);
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

	add_trigger(new, tr, copy_args);

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);
}

static int add_exact_filter(struct rb_root *root, struct symtab *symtab,
			    char *module, char *filter_str,
			    struct ftrace_trigger *tr)
{
	struct ftrace_filter filter;
	struct sym *sym;

	sym = find_symname(symtab, filter_str);
	if (sym == NULL)
		return 0;

	filter.name = sym->name;
	filter.start = sym->addr;
	filter.end = sym->addr + sym->size;

	add_filter(root, &filter, tr, false);
	return 1;
}

static int add_regex_filter(struct rb_root *root, struct symtab *symtab,
			    char *module, char *filter_str,
			    struct ftrace_trigger *tr)
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

		add_filter(root, &filter, tr, true);
		ret++;
	}

	return ret;
}

/* argument_spec = arg1/i32,arg2/x64,... */
static int parse_argument_spec(char *str, struct ftrace_trigger *tr)
{
	struct ftrace_arg_spec *arg;
	char *suffix;
	int fmt;
	int size;
	int bit;

	if (!isdigit(str[3])) {
		pr_use("skipping invalid argument: %s\n", str);
		return -1;
	}

	arg = xmalloc(sizeof(*arg));
	INIT_LIST_HEAD(&arg->list);
	arg->idx = strtol(str+3, &suffix, 0);

	if (suffix == NULL || *suffix == '\0') {
		arg->fmt  = ARG_FMT_AUTO;
		arg->size = sizeof(long);
		goto add_arg;
	}

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
		break;
	default:
		pr_use("unsupported argument type: %s\n", str);
		return -1;
	}
	arg->fmt = fmt;

	suffix++;
	if (*suffix == '\0') {
		if (fmt == ARG_FMT_CHAR)
			arg->size = 1;
		else
			arg->size = sizeof(long);
		goto add_arg;
	}

	bit = strtol(suffix, NULL, 10);
	switch (bit) {
	case 8:
	case 16:
	case 32:
	case 64:
		size = bit / 8;
		break;
	default:
		pr_use("unsupported argument size: %s\n", str);
		return -1;
	}
	arg->size = size;

add_arg:
	tr->flags |= TRIGGER_FL_ARGUMENT;
	list_add_tail(&arg->list, tr->pargs);

	return 0;
}

static int setup_module_and_trigger(char *str, char *module,
				    struct symtabs *symtabs,
				    struct symtab **psymtab,
				    struct ftrace_trigger *tr)
{
	char *pos = strchr(str, '@');

	*psymtab = &symtabs->symtab;

	if (pos) {
		char *tr_str;
		bool found_mod = false;

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

				if (!strcasecmp(pos, "on"))
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

			if (!strcasecmp(pos, "recover")) {
				tr->flags |= TRIGGER_FL_RECOVER;
				continue;
			}

			if (module == NULL || strcasecmp(pos, module))
				return -1;

			found_mod = true;

			if (!strcasecmp(module, "plt"))
				*psymtab = &symtabs->dsymtab;
			else if (!strcasecmp(module, "kernel"))
				*psymtab = get_kernel_symtab();
		}

		if (module && !found_mod)
			return -1;
	}
	else {
		if (module)
			return -1;
	}

	return 0;
}

static void setup_trigger(char *filter_str, struct symtabs *symtabs,
			  char *module, struct rb_root *root,
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
		int ret;
		char *mod = module;
		struct ftrace_arg_spec *arg;

		if (setup_module_and_trigger(name, mod, symtabs, &symtab,
					     &tr) < 0)
			goto next;

		if (name[0] == '!') {
			tr.fmode = FILTER_MODE_OUT;
			name++;
		} else if (fmode != NULL)
			tr.fmode = FILTER_MODE_IN;

again:
		if (strpbrk(name, REGEX_CHARS))
			ret = add_regex_filter(root, symtab, mod, name, &tr);
		else
			ret = add_exact_filter(root, symtab, mod, name, &tr);

		if (ret == 0 && mod == NULL) {
			mod = "plt";
			symtab = &symtabs->dsymtab;
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
 * @module     - optional module (binary/dso) name
 * @root       - root of resulting rbtree
 * @mode       - filter mode: opt-in (-F) or opt-out (-N)
 */
void ftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			 char *module, struct rb_root *root,
			 enum filter_mode *mode)
{
	setup_trigger(filter_str, symtabs, module, root, TRIGGER_FL_FILTER, mode);
}

/**
 * ftrace_setup_trigger - construct rbtree of triggers
 * @trigger_str - CSV of trigger string (FUNC @ act)
 * @symtabs    - symbol tables to find symbol address
 * @module     - optional module (binary/dso) name
 * @root       - root of resulting rbtree
 */
void ftrace_setup_trigger(char *trigger_str, struct symtabs *symtabs,
			  char *module, struct rb_root *root)
{
	setup_trigger(trigger_str, symtabs, module, root, 0, NULL);
}

/**
 * ftrace_setup_argument - construct rbtree of argument
 * @args_str   - CSV of argument string (FUNC @ arg)
 * @symtabs    - symbol tables to find symbol address
 * @module     - optional module (binary/dso) name
 * @root       - root of resulting rbtree
 */
void ftrace_setup_argument(char *args_str, struct symtabs *symtabs,
			  char *module, struct rb_root *root)
{
	setup_trigger(args_str, symtabs, module, root, 0, NULL);
}

/**
 * ftrace_setup_retval - construct rbtree of retval
 * @retval_str   - CSV of argument string (FUNC @ arg)
 * @symtabs    - symbol tables to find symbol address
 * @module     - optional module (binary/dso) name
 * @root       - root of resulting rbtree
 */
void ftrace_setup_retval(char *retval_str, struct symtabs *symtabs,
			  char *module, struct rb_root *root)
{
	setup_trigger(retval_str, symtabs, module, root, 0, NULL);
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
	ftrace_setup_filter("foo::bar", &stabs, NULL, &root, NULL);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);

	node = rb_first(&root);
	filter = rb_entry(node, struct ftrace_filter, node);
	TEST_STREQ(filter->name, "foo::bar");
	TEST_EQ(filter->start, 0x2000UL);
	TEST_EQ(filter->end, 0x2000UL + 0x1000UL);

	ftrace_cleanup_filter(&root);
	TEST_EQ(RB_EMPTY_ROOT(&root), true);

	/* test2: destructor */
	ftrace_setup_filter("foo::~foo", &stabs, NULL, &root, NULL);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);

	node = rb_first(&root);
	filter = rb_entry(node, struct ftrace_filter, node);
	TEST_STREQ(filter->name, "foo::~foo");
	TEST_EQ(filter->start, 0x6000UL);
	TEST_EQ(filter->end, 0x6000UL + 0x1000UL);

	ftrace_cleanup_filter(&root);
	TEST_EQ(RB_EMPTY_ROOT(&root), true);

	/* test3: unknown symbol */
	ftrace_setup_filter("invalid_name", &stabs, NULL, &root, NULL);
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

	ftrace_setup_filter("foo::b.*", &stabs, NULL, &root, NULL);
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

	ftrace_setup_filter("foo::.*", &stabs, NULL, &root, &fmode);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);
	TEST_EQ(fmode, FILTER_MODE_IN);

	ftrace_setup_filter("!foo::foo", &stabs, NULL, &root, &fmode);
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

	ftrace_setup_filter("foo::foo", &stabs, NULL, &root, &fmode);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);
	TEST_EQ(fmode, FILTER_MODE_IN);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(ftrace_match_filter(&root, 0x1000, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_FILTER);
	TEST_EQ(tr.fmode, FILTER_MODE_IN);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(ftrace_match_filter(&root, 0x1fff, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_FILTER);
	TEST_EQ(tr.fmode, FILTER_MODE_IN);

	memset(&tr, 0, sizeof(tr));
	TEST_EQ(ftrace_match_filter(&root, 0xfff, &tr), NULL);
	TEST_NE(tr.flags, TRIGGER_FL_FILTER);

	memset(&tr, 0, sizeof(tr));
	TEST_EQ(ftrace_match_filter(&root, 0x2000, &tr), NULL);
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

	ftrace_setup_trigger("foo::bar@depth=2", &stabs, NULL, &root);
	TEST_EQ(RB_EMPTY_ROOT(&root), false);

	memset(&tr, 0, sizeof(tr));
	TEST_NE(ftrace_match_filter(&root, 0x2500, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_DEPTH);
	TEST_EQ(tr.depth, 2);

	ftrace_setup_trigger("foo::bar@backtrace", &stabs, NULL, &root);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(ftrace_match_filter(&root, 0x2500, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_DEPTH | TRIGGER_FL_BACKTRACE);

	ftrace_setup_trigger("foo::baz1@traceon", &stabs, NULL, &root);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(ftrace_match_filter(&root, 0x3000, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_TRACE_ON);

	ftrace_setup_trigger("foo::baz3@trace_off,depth=1", &stabs, NULL, &root);
	memset(&tr, 0, sizeof(tr));
	TEST_NE(ftrace_match_filter(&root, 0x5000, &tr), NULL);
	TEST_EQ(tr.flags, TRIGGER_FL_TRACE_OFF | TRIGGER_FL_DEPTH);
	TEST_EQ(tr.depth, 1);

	ftrace_cleanup_filter(&root);
	TEST_EQ(RB_EMPTY_ROOT(&root), true);

	return TEST_OK;
}

#endif /* UNIT_TEST */
