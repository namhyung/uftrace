#include <stdio.h>
#include <stdlib.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "filter"
#define PR_DOMAIN DBG_FILTER

#include "uftrace.h"
#include "utils/argspec.h"
#include "utils/auto-args.h"
#include "utils/dwarf.h"
#include "utils/filter.h"
#include "utils/list.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"
#include "utils/utils.h"

/* RB-tree maintaining automatic arguments and return value */
static struct rb_root auto_argspec = RB_ROOT;
static struct rb_root auto_retspec = RB_ROOT;
static struct rb_root auto_enum = RB_ROOT;

extern void update_trigger(struct uftrace_filter *filter, struct uftrace_trigger *tr,
			   bool exact_match);
extern int setup_trigger_action(char *str, struct uftrace_trigger *tr, char **module,
				unsigned long orig_flags, struct uftrace_filter_setting *setting);

static void add_auto_args(struct rb_root *root, struct uftrace_filter *entry,
			  struct uftrace_trigger *tr)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct uftrace_filter *iter, *new;
	int cmp;

	pr_dbg2("add auto-argument for %s\n", entry->name);

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_filter, node);

		cmp = strcmp(iter->name, entry->name);
		if (cmp == 0) {
			update_trigger(iter, tr, true);
			return;
		}

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	new = xmalloc(sizeof(*new));
	memcpy(new, entry, sizeof(*new));
	new->trigger.flags = 0;
	INIT_LIST_HEAD(&new->args);
	new->trigger.pargs = &new->args;

	update_trigger(new, tr, true);

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);
}

static void build_auto_args(const char *args_str, struct rb_root *root, unsigned long flag,
			    struct uftrace_filter_setting *setting)
{
	struct strv specs = STRV_INIT;
	char *name;
	int j;

	if (args_str == NULL)
		return;

	strv_split(&specs, args_str, ";");

	strv_for_each(&specs, name, j) {
		LIST_HEAD(args);
		struct uftrace_arg_spec *arg;
		struct uftrace_trigger tr = {
			.pargs = &args,
		};
		struct uftrace_filter entry = {
			.name = NULL,
		};
		char *p = strchr(name, '@');

		if (p == NULL)
			continue;

		/*
		 * save original spec string in 'end'.
		 * it needs to be done before setup_trigger_action()
		 * splitting the original string.
		 */
		entry.end = (unsigned long)xstrdup(p + 1);

		if (setup_trigger_action(name, &tr, NULL, flag, setting) < 0)
			goto next;

		/*
		 * it should be copied after setup_trigger_action() removed
		 * '@' for the arg spec
		 */
		entry.name = demangle(name);

		add_auto_args(root, &entry, &tr);

next:
		while (!list_empty(&args)) {
			arg = list_first_entry(&args, struct uftrace_arg_spec, list);
			list_del(&arg->list);
			free_arg_spec(arg);
		}
	}
	strv_free(&specs);
}

static struct uftrace_filter *find_auto_args(struct rb_root *root, char *name)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct uftrace_filter *iter;
	int cmp;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_filter, node);

		cmp = strcmp(iter->name, name);
		if (cmp == 0)
			return iter;

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	return NULL;
}

static struct uftrace_filter *dwarf_argspec_list;

static struct uftrace_filter *find_dwarf_argspec(struct uftrace_filter *filter,
						 struct uftrace_dbg_info *dinfo, bool is_retval,
						 struct uftrace_filter_setting *setting)
{
	LIST_HEAD(dwarf_argspec);
	struct uftrace_filter *dwarf_filter;
	struct uftrace_trigger dwarf_tr = {
		.pargs = &dwarf_argspec,
	};
	char *arg_str;
	unsigned long flag = is_retval ? TRIGGER_FL_RETVAL : TRIGGER_FL_ARGUMENT;
	unsigned long addr = filter->start;

	if (is_retval)
		arg_str = get_dwarf_retspec(dinfo, filter->name, addr);
	else
		arg_str = get_dwarf_argspec(dinfo, filter->name, addr);
	if (arg_str == NULL)
		return NULL;

	arg_str = xstrdup(arg_str);
	setup_trigger_action(arg_str, &dwarf_tr, NULL, flag, setting);
	if (list_empty(dwarf_tr.pargs)) {
		free(arg_str);
		return NULL;
	}

	dwarf_filter = xzalloc(sizeof(*dwarf_filter));
	INIT_LIST_HEAD(&dwarf_filter->args);

	list_splice(dwarf_tr.pargs, &dwarf_filter->args);
	dwarf_filter->trigger.pargs = &dwarf_filter->args;
	dwarf_filter->trigger.flags = dwarf_tr.flags;

	/* XXX: since 'name' was not used here, abuse it as a linked list */
	dwarf_filter->name = (void *)dwarf_argspec_list;
	dwarf_argspec_list = dwarf_filter;

	free(arg_str);
	return dwarf_filter;
}

struct uftrace_filter *find_auto_argspec(struct uftrace_filter *filter, struct uftrace_trigger *tr,
					 struct uftrace_dbg_info *dinfo,
					 struct uftrace_filter_setting *setting)
{
	struct uftrace_filter *auto_arg = NULL;

	if (debug_info_has_argspec(dinfo))
		auto_arg = find_dwarf_argspec(filter, dinfo, false, setting);

	if (auto_arg == NULL)
		auto_arg = find_auto_args(&auto_argspec, filter->name);

	return auto_arg;
}

struct uftrace_filter *find_auto_retspec(struct uftrace_filter *filter, struct uftrace_trigger *tr,
					 struct uftrace_dbg_info *dinfo,
					 struct uftrace_filter_setting *setting)
{
	struct uftrace_filter *auto_ret = NULL;

	if (debug_info_has_argspec(dinfo))
		auto_ret = find_dwarf_argspec(filter, dinfo, true, setting);

	if (auto_ret == NULL)
		auto_ret = find_auto_args(&auto_retspec, filter->name);

	return auto_ret;
}

char *get_auto_argspec_str(void)
{
	return auto_args_list;
}

char *get_auto_retspec_str(void)
{
	return auto_retvals_list;
}

void setup_auto_args(struct uftrace_filter_setting *setting)
{
	if (!RB_EMPTY_ROOT(&auto_enum))
		return;

	parse_enum_string(auto_enum_list, &auto_enum);
	build_auto_args(auto_args_list, &auto_argspec, TRIGGER_FL_ARGUMENT, setting);
	build_auto_args(auto_retvals_list, &auto_retspec, TRIGGER_FL_RETVAL, setting);
}

void setup_auto_args_str(char *args, char *rets, char *enums,
			 struct uftrace_filter_setting *setting)
{
	if (!RB_EMPTY_ROOT(&auto_enum))
		return;

	parse_enum_string(enums, &auto_enum);
	build_auto_args(args, &auto_argspec, TRIGGER_FL_ARGUMENT, setting);
	build_auto_args(rets, &auto_retspec, TRIGGER_FL_RETVAL, setting);
}

static void release_auto_args(struct rb_root *root)
{
	struct rb_node *p;
	struct uftrace_filter *entry;
	struct uftrace_arg_spec *arg, *tmp;

	while (!RB_EMPTY_ROOT(root)) {
		p = rb_first(root);
		entry = rb_entry(p, struct uftrace_filter, node);

		rb_erase(p, root);

		list_for_each_entry_safe(arg, tmp, &entry->args, list) {
			list_del(&arg->list);
			free_arg_spec(arg);
		}

		free(entry->name);
		free((void *)(uintptr_t)entry->end);
		free(entry);
	}
}

void finish_auto_args(void)
{
	struct uftrace_filter *tmp;
	struct uftrace_arg_spec *spec;

	release_enum_def(&auto_enum);
	release_auto_args(&auto_argspec);
	release_auto_args(&auto_retspec);

	while (dwarf_argspec_list) {
		tmp = (void *)dwarf_argspec_list->name;

		while (!list_empty(dwarf_argspec_list->trigger.pargs)) {
			spec = list_first_entry(dwarf_argspec_list->trigger.pargs, typeof(*spec),
						list);
			list_del(&spec->list);
			free_arg_spec(spec);
		}
		free(dwarf_argspec_list);

		dwarf_argspec_list = tmp;
	}
}

/**
 * extract_trigger_args - extract argspec from trigger actions
 * @pargs: pointer to existing argspec
 * @prets: pointer to existing retspec
 * @trigger: trigger string
 *
 * This function extracts arg/ret spec from the trigger string (if any)
 * and append them to pargs or prets respectively so that they can be
 * saved into the info section.
 *
 * It returns 0 if none of arguments or return values are specified,
 * 1 if only one of them is specified, and 2 if both are given.
 */
int extract_trigger_args(char **pargs, char **prets, char *trigger)
{
	char *argspec = NULL;
	char *retspec = NULL;

	/* extract argspec (and retspec) in trigger action */
	if (trigger) {
		struct strv actions = STRV_INIT;
		char *pos, *act;
		int j;

		strv_split(&actions, trigger, ";");

		strv_for_each(&actions, pos, j) {
			char *name = pos;
			char *args = NULL;
			char *rval = NULL;
			bool auto_args = false;

			act = strchr(name, '@');
			if (act == NULL)
				continue;

			*act++ = '\0';

			while ((pos = strsep(&act, ",")) != NULL) {
				if (!strncasecmp(pos, "arg", 3) || !strncasecmp(pos, "fparg", 5))
					args = strjoin(args, pos, ",");
				if (!strncasecmp(pos, "retval", 6))
					rval = "retval";
				if (!strncasecmp(pos, "auto-args", 9))
					auto_args = true;
			}

			if (args) {
				xasprintf(&act, "%s@%s", name, args);
				argspec = strjoin(argspec, act, ";");
				free(act);
				free(args);
			}
			if (rval) {
				xasprintf(&act, "%s@retval", name);
				retspec = strjoin(retspec, act, ";");
				free(act);
			}
			if (auto_args) {
				argspec = strjoin(argspec, name, ";");
				retspec = strjoin(retspec, name, ";");
			}
		}
		strv_free(&actions);
	}

	if (*pargs)
		argspec = strjoin(argspec, *pargs, ";");
	if (*prets)
		retspec = strjoin(retspec, *prets, ";");

	*pargs = argspec;
	*prets = retspec;

	return !!argspec + !!retspec;
}

enum enum_token_ret {
	TOKEN_INVALID = -1,
	TOKEN_NULL,
	TOKEN_STR,
	TOKEN_SIGN,
	TOKEN_NUM,
};

static char enum_token[256];

static enum enum_token_ret enum_next_token(char **str)
{
	char *pos, *tok;
	enum enum_token_ret ret;
	ptrdiff_t len;

	tok = *str;
	if (tok == NULL)
		return TOKEN_NULL;

	while (isspace(*tok))
		tok++;

	if (*tok == '\0')
		return TOKEN_NULL;

	if (ispunct(*tok) && *tok != '_') {
		enum_token[0] = *tok;
		enum_token[1] = '\0';
		*str = tok + 1;
		return TOKEN_SIGN;
	}

	if (isalpha(*tok) || *tok == '_')
		ret = TOKEN_STR;
	else if (isdigit(*tok))
		ret = TOKEN_NUM;
	else
		return TOKEN_INVALID;

	pos = strpbrk(tok, " \n\t=,{}");
	if (pos != NULL)
		len = pos - tok;
	else
		len = strlen(tok);

	if ((size_t)len >= sizeof(enum_token))
		len = sizeof(enum_token) - 1;

	strncpy(enum_token, tok, len);
	enum_token[len] = '\0';
	*str = pos;

	return ret;
}

struct enum_def {
	char *name;
	struct list_head vals;
	struct rb_node node;
};

struct enum_val {
	struct list_head list;
	char *str;
	long val;
};

static void free_enum_def(struct enum_def *e_def)
{
	struct enum_val *e_val;

	if (e_def == NULL)
		return;

	while (!list_empty(&e_def->vals)) {
		e_val = list_first_entry(&e_def->vals, struct enum_val, list);

		list_del(&e_val->list);
		free(e_val->str);
		free(e_val);
	}
	free(e_def->name);
	free(e_def);
}

static void add_enum_tree(struct rb_root *root, struct enum_def *e_def)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct enum_def *iter;
	int cmp;

	pr_dbg2("add enum definition for %s\n", e_def->name);

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct enum_def, node);

		cmp = strcmp(iter->name, e_def->name);
		if (cmp == 0) {
			pr_dbg2("ignore same enum name: %s\n", e_def->name);
			free_enum_def(e_def);
			return;
		}

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&e_def->node, parent, p);
	rb_insert_color(&e_def->node, root);
}

struct enum_def *find_enum_def(struct rb_root *root, char *name)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct enum_def *iter;
	int cmp;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct enum_def, node);

		cmp = strcmp(iter->name, name);
		if (cmp == 0)
			return iter;

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	return NULL;
}

char *convert_enum_val(struct enum_def *e_def, long val)
{
	struct enum_val *e_val;
	char *str = NULL;

	/* exact match? */
	list_for_each_entry(e_val, &e_def->vals, list) {
		if (e_val->val == val)
			return xstrdup(e_val->str);
	}

	/* if not, try OR-ing bit flags */
	list_for_each_entry(e_val, &e_def->vals, list) {
		if (e_val->val <= val) {
			val -= e_val->val;
			str = strjoin(str, e_val->str, "|");
		}

		if (val == 0)
			break;
	}

	/* print hex for unknown value */
	if (str && val) {
		char *tmp;

		xasprintf(&tmp, "%s+%#lx", str, val);
		free(str);
		str = tmp;
	}
	else if (unlikely(str == NULL)) {
		if (labs(val) > 100000)
			xasprintf(&str, "%#lx", val);
		else
			xasprintf(&str, "%ld", val);
	}

	return str;
}

/* caller should free the return value */
char *get_enum_string(struct rb_root *root, char *name, long val)
{
	struct enum_def *e_def;
	char *ret;

	e_def = find_enum_def(root, name);
	if (e_def == NULL)
		e_def = find_enum_def(&auto_enum, name);

	if (e_def == NULL)
		xasprintf(&ret, "%ld", val);
	else
		ret = convert_enum_val(e_def, val);

	return ret;
}

/**
 * parse_enum_string - parse enum and add it to a tree
 * @enum_str: string presentation of enum
 *
 * This function parses @enum_str and add it to @root so that it can be
 * used for argument/return later.  The syntax of enum is same as C
 * (except for the 'enum' keyword) but it only accepts a simple integer
 * constant or other enum constant in RHS.
 *
 * For example, following string should be accepted:
 *
 *   enum number {
 *     ZERO = 0,
 *     ONE,
 *     TWO,
 *     HUNDRED = 100,
 *   };
 */
int parse_enum_string(char *enum_str, struct rb_root *root)
{
	char *pos;
	struct enum_def *e_def = NULL;
	struct enum_val *e_val, *e;
	enum enum_token_ret ret;
	struct strv strv = STRV_INIT;
	int err = -1;
	int j;

	if (enum_str == NULL)
		return 0;

	strv_split(&strv, enum_str, ";");

	strv_for_each(&strv, pos, j) {
		long val = 0;

		ret = enum_next_token(&pos);

		/* ignore empty string */
		if (ret == TOKEN_NULL)
			continue;

		if (ret != TOKEN_STR || strcmp(enum_token, "enum")) {
			pr_dbg("don't have 'enum' prefix\n");
			goto out;
		}

		/* name is mandatory */
		ret = enum_next_token(&pos);
		if (ret != TOKEN_STR) {
			pr_dbg("enum name is missing\n");
			goto out;
		}

		e_def = xmalloc(sizeof(*e_def));
		e_def->name = xstrdup(enum_token);
		INIT_LIST_HEAD(&e_def->vals);

		ret = enum_next_token(&pos);
		if (ret != TOKEN_SIGN || strcmp(enum_token, "{")) {
			pr_dbg("enum start brace is missing\n");
			goto out;
		}

		pr_dbg2("parse enum %s\n", e_def->name);

		ret = enum_next_token(&pos);
		while (ret != TOKEN_NULL && strcmp(enum_token, "}")) {
			char *name = xstrdup(enum_token);

			ret = enum_next_token(&pos);
			if (ret != TOKEN_SIGN) {
				pr_dbg("invalid enum syntax - sign required\n");
				free(name);
				goto out;
			}

			if (!strcmp(enum_token, "=")) {
				while (isspace(*pos))
					pos++;
				val = strtol(pos, &pos, 0);

				/* consume ',' after the number */
				ret = enum_next_token(&pos);
				if (ret != TOKEN_SIGN) {
					pr_dbg("invalid enum syntax - comma needed\n");
					free(name);
					goto out;
				}
			}

			e_val = xmalloc(sizeof(*e_val));
			e_val->str = name;
			e_val->val = val;

			pr_dbg3("  %s = %ld\n", name, val);

			/* sort by value, just in case */
			list_for_each_entry(e, &e_def->vals, list) {
				if (e->val <= val)
					break;
			}
			list_add_tail(&e_val->list, &e->list);

			val++;

			if (!strcmp(enum_token, ","))
				ret = enum_next_token(&pos);
		}

		if (!strcmp(enum_token, "}")) {
			add_enum_tree(root, e_def);
			e_def = NULL;
		}
		else {
			pr_dbg("invalid enum def: %s\n", enum_token);
			goto out;
		}
	}
	err = 0;

out:
	free_enum_def(e_def);
	strv_free(&strv);
	return err;
}

static char *get_enum_def_string(struct enum_def *def)
{
	struct enum_val *e_val;
	int last = -1;
	char *str = NULL;
	char *buf = NULL;

	list_for_each_entry_reverse(e_val, &def->vals, list) {
		/* simple case */
		if (e_val->val == ++last) {
			str = strjoin(str, e_val->str, ",");
			continue;
		}

		last = e_val->val;
		xasprintf(&buf, "%s=%ld", e_val->str, e_val->val);
		str = strjoin(str, buf, ",");
	}
	free(buf);

	return str;
}

void save_enum_def(struct rb_root *root, FILE *fp)
{
	struct rb_node *node;
	struct enum_def *e_def;
	char *str;

	node = rb_first(root);
	while (node) {
		e_def = rb_entry(node, struct enum_def, node);

		str = get_enum_def_string(e_def);
		save_debug_file(fp, 'E', e_def->name, (long)str);
		free(str);

		node = rb_next(node);
	}
}

void release_enum_def(struct rb_root *root)
{
	struct rb_node *node;
	struct enum_def *e_def;

	node = rb_first(root);
	while (node) {
		e_def = rb_entry(node, struct enum_def, node);
		node = rb_next(node);

		rb_erase(&e_def->node, root);
		free_enum_def(e_def);
	}
}

char *get_auto_enum_str(void)
{
	return auto_enum_list;
}

#ifdef UNIT_TEST

TEST_CASE(argspec_auto_args)
{
	char test_auto_args[] = "foo@arg1,arg2/s;bar@fparg1";
	struct uftrace_filter *entry;
	struct uftrace_filter key;
	struct uftrace_arg_spec *spec;
	struct uftrace_filter_setting setting = {
		.lp64 = host_is_lp64(),
	};
	int idx = 1;

	pr_dbg("build auto args from: %s\n", test_auto_args);
	build_auto_args(test_auto_args, &auto_argspec, TRIGGER_FL_ARGUMENT, &setting);

	pr_dbg("'foo' should have two arguments\n");
	key.name = "foo";
	entry = find_auto_argspec(&key, NULL, NULL, &setting);
	TEST_NE(entry, NULL);
	TEST_EQ(entry->trigger.flags, TRIGGER_FL_ARGUMENT);

	list_for_each_entry(spec, &entry->args, list) {
		TEST_EQ(spec->idx, idx);
		TEST_EQ(spec->fmt, idx == 1 ? ARG_FMT_AUTO : ARG_FMT_STR);
		idx++;
	}

	pr_dbg("'foo' should have one FP argument\n");
	key.name = "bar";
	entry = find_auto_argspec(&key, NULL, NULL, &setting);
	TEST_NE(entry, NULL);
	TEST_EQ(entry->trigger.flags, TRIGGER_FL_ARGUMENT);

	spec = list_first_entry(&entry->args, struct uftrace_arg_spec, list);
	TEST_EQ(spec->fmt, ARG_FMT_FLOAT);
	TEST_EQ(spec->idx, 1);

	pr_dbg("'xxx' should not have arguments\n");
	key.name = "xxx";
	entry = find_auto_argspec(&key, NULL, NULL, &setting);
	TEST_EQ(entry, NULL);

	release_auto_args(&auto_argspec);

	pr_dbg("'foo' should not have arguments after released\n");
	key.name = "foo";
	entry = find_auto_argspec(&key, NULL, NULL, &setting);
	TEST_EQ(entry, NULL);

	return TEST_OK;
}

TEST_CASE(argspec_extract)
{
	char test_trigger_str1[] = "foo@arg1,retval";
	char test_trigger_str2[] = "foo@trace-on;bar@depth=2,arg1/s,trace-off,arg2/x64";
	char test_trigger_str3[] = "foo@libabc,arg3/i32%rax,backtrace";
	char *args, *rets;

	pr_dbg("extracting args/rets from %s\n", test_trigger_str1);
	args = rets = NULL;
	extract_trigger_args(&args, &rets, test_trigger_str1);

	TEST_STREQ(args, "foo@arg1");
	TEST_STREQ(rets, "foo@retval");

	free(args);
	free(rets);

	pr_dbg("extracting args/rets from %s\n", test_trigger_str2);
	args = rets = NULL;
	extract_trigger_args(&args, &rets, test_trigger_str2);

	TEST_STREQ("bar@arg1/s,arg2/x64", args);
	TEST_EQ(rets, NULL);

	free(args);
	free(rets);

	pr_dbg("extracting args/rets from %s\n", test_trigger_str3);
	args = rets = NULL;
	extract_trigger_args(&args, &rets, test_trigger_str3);

	TEST_STREQ("foo@arg3/i32%rax", args);
	TEST_EQ(rets, NULL);

	free(args);
	free(rets);

	return TEST_OK;
}

TEST_CASE(argspec_parse_enum)
{
	char test_enum_str1[] = "enum xxx { ZERO, ONE = 111, TWO };";
	char test_enum_str2[] = "enum a { AAA, BBB = 1, CCC }";
	char test_enum_str3[] = ";enum uftrace{record=100,replay=-23,report}";
	struct rb_root enum_tree = RB_ROOT;
	struct rb_node *node;
	struct enum_def *e_def;
	struct enum_val *e_val, *e_next;
	char *str;

	pr_dbg("parse enum string: %s\n", test_enum_str1);
	TEST_EQ(parse_enum_string(test_enum_str1, &enum_tree), 0);
	pr_dbg("parse enum string: %s\n", test_enum_str2);
	TEST_EQ(parse_enum_string(test_enum_str2, &enum_tree), 0);
	pr_dbg("parse enum string: %s\n", test_enum_str3);
	TEST_EQ(parse_enum_string(test_enum_str3, &enum_tree), 0);

	node = rb_first(&enum_tree);
	while (node) {
		e_def = rb_entry(node, struct enum_def, node);

		e_val = list_first_entry(&e_def->vals, struct enum_val, list);
		e_next = list_next_entry(e_val, list);
		TEST_GE(e_val->val, e_next->val);

		e_val = list_next_entry(e_val, list);
		e_next = list_next_entry(e_next, list);
		TEST_GE(e_val->val, e_next->val);

		node = rb_next(node);
	}

	e_def = find_enum_def(&enum_tree, "xxx");
	TEST_NE(e_def, NULL);

	pr_dbg("first enum item should have 0 value\n");
	e_val = list_last_entry(&e_def->vals, struct enum_val, list);
	TEST_STREQ(e_val->str, "ZERO");
	TEST_EQ(e_val->val, 0L);

	pr_dbg("check value increments from previous value\n");
	e_val = list_first_entry(&e_def->vals, struct enum_val, list);
	TEST_STREQ(e_val->str, "TWO");
	TEST_EQ(e_val->val, 112L);

	pr_dbg("check value match to multiple bitmask\n");
	e_def = find_enum_def(&enum_tree, "a");
	str = convert_enum_val(e_def, 3);
	TEST_STREQ(str, "CCC|BBB");
	free(str);

	pr_dbg("check value increments correctly for negative numbers\n");
	e_def = find_enum_def(&enum_tree, "uftrace");
	str = convert_enum_val(e_def, -22);
	TEST_STREQ(str, "report");
	free(str);

	release_enum_def(&enum_tree);

	pr_dbg("after release, it should not find any definition\n");
	TEST_EQ(find_enum_def(&enum_tree, "xxx"), NULL);

	return TEST_OK;
}

#endif /* UNIT_TEST */
