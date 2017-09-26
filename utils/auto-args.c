#include <stdio.h>
#include <stdlib.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "filter"
#define PR_DOMAIN  DBG_FILTER

#include "uftrace.h"
#include "utils/filter.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"
#include "utils/list.h"
#include "utils/auto-args.h"

/* RB-tree maintaining automatic arguments and return value */
static struct rb_root auto_argspec = RB_ROOT;
static struct rb_root auto_retspec = RB_ROOT;

extern void add_trigger(struct uftrace_filter *filter, struct uftrace_trigger *tr,
			bool exact_match);
extern int setup_trigger_action(char *str, struct uftrace_trigger *tr,
				char **module, unsigned long orig_flags);

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
			add_trigger(iter, tr, true);
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

	add_trigger(new, tr, true);

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);
}

static void build_auto_args(const char *args_str, struct rb_root *root,
			    unsigned long flag)
{
	char *str;
	char *pos, *name;

	if (args_str == NULL)
		return;

	pos = str = strdup(args_str);
	if (str == NULL)
		return;

	while ((name = strsep(&pos, ";")) != NULL) {
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

		if (setup_trigger_action(name, &tr, NULL, flag) < 0)
			goto next;

		/*
		 * it should be copied after setup_trigger_action() removed
		 * '@' for the arg spec
		 */
		entry.name = xstrdup(name);
		add_auto_args(root, &entry, &tr);

next:
		while (!list_empty(&args)) {
			arg = list_first_entry(&args, struct uftrace_arg_spec, list);
			list_del(&arg->list);
			free(arg);
		}
	}

	free(str);
}

static struct uftrace_filter * find_auto_args(struct rb_root *root, char *name)
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

struct uftrace_filter * find_auto_argspec(char *name)
{
	return find_auto_args(&auto_argspec, name);
}

struct uftrace_filter * find_auto_retspec(char *name)
{
	return find_auto_args(&auto_retspec, name);
}


void setup_auto_args(void)
{
	build_auto_args(auto_args_list, &auto_argspec, TRIGGER_FL_ARGUMENT);
	build_auto_args(auto_retvals_list, &auto_retspec, TRIGGER_FL_RETVAL);
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
			free(arg);
		}

		free(entry->name);
		free((void *)entry->end);
		free(entry);
	}
}

void finish_auto_args(void)
{
	release_auto_args(&auto_argspec);
	release_auto_args(&auto_retspec);
}

#ifdef UNIT_TEST

TEST_CASE(argspec_auto_args)
{
	char test_auto_args[] = "foo@arg1,arg2/s;bar@fparg1";
	struct uftrace_filter *entry;
	struct uftrace_arg_spec *spec;
	int idx = 1;

	build_auto_args(test_auto_args, &auto_argspec, TRIGGER_FL_ARGUMENT);

	entry = find_auto_argspec("foo");
	TEST_NE(entry, NULL);
	TEST_EQ(entry->trigger.flags, TRIGGER_FL_ARGUMENT);

	list_for_each_entry(spec, &entry->args, list) {
		TEST_EQ(spec->idx, idx);
		TEST_EQ(spec->fmt, idx == 1 ? ARG_FMT_AUTO : ARG_FMT_STR);
		idx++;
	}

	entry = find_auto_argspec("bar");
	TEST_NE(entry, NULL);
	TEST_EQ(entry->trigger.flags, TRIGGER_FL_ARGUMENT);

	spec = list_first_entry(&entry->args, struct uftrace_arg_spec, list);
	TEST_EQ(spec->fmt, ARG_FMT_FLOAT);
	TEST_EQ(spec->idx, 1);

	entry = find_auto_argspec("xxx");
	TEST_EQ(entry, NULL);

	release_auto_args(&auto_argspec);

	entry = find_auto_argspec("foo");
	TEST_EQ(entry, NULL);

	return TEST_OK;
}

#endif /* UNIT_TEST */
