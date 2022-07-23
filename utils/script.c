/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

/* This should be defined before #include "utils.h" */
#define PR_FMT "script"
#define PR_DOMAIN DBG_SCRIPT

#include "utils/script.h"
#include "utils/filter.h"
#include "utils/list.h"
#include "utils/script-luajit.h"
#include "utils/script-python.h"
#include "utils/utils.h"
#include <unistd.h>

/* This will be set by getenv("UFTRACE_SCRIPT"). */
char *script_str;

enum script_type_t script_lang;

/* The below functions are used both in record time and script command. */
script_uftrace_entry_t script_uftrace_entry;
script_uftrace_exit_t script_uftrace_exit;
script_uftrace_event_t script_uftrace_event;
script_uftrace_end_t script_uftrace_end;
script_atfork_prepare_t script_atfork_prepare;

struct script_filter_item {
	struct list_head list;
	struct uftrace_pattern patt;
};

static LIST_HEAD(filters);

enum script_type_t get_script_type(const char *str)
{
	char *ext = strrchr(str, '.');

	/*
	 * The given script will be detected by the file suffix.
	 * As of now, it only handles ".py" suffix for python.
	 */
	if (!strcmp(ext, ".py"))
		return SCRIPT_PYTHON;
	else if (!strcmp(ext, ".lua"))
		return SCRIPT_LUAJIT;
	else if (!strcmp(ext, ".testing"))
		return SCRIPT_TESTING;

	return SCRIPT_UNKNOWN;
}

void script_add_filter(char *func, enum uftrace_pattern_type ptype)
{
	struct script_filter_item *item;

	if (func == NULL)
		return;

	item = xmalloc(sizeof(*item));

	init_filter_pattern(ptype, &item->patt, func);

	pr_dbg2("add script filter: %s (%s)\n", func, get_filter_pattern(item->patt.type));

	list_add_tail(&item->list, &filters);
}

/* returns 1 on match - script should be run */
int script_match_filter(char *func)
{
	struct script_filter_item *item;

	/* special case: no filter */
	if (list_empty(&filters))
		return 1;

	list_for_each_entry(item, &filters, list) {
		if (match_filter_pattern(&item->patt, func))
			return 1;
	}
	return 0;
}

void script_finish_filter(void)
{
	struct script_filter_item *item, *tmp;

	list_for_each_entry_safe(item, tmp, &filters, list) {
		list_del(&item->list);
		free_filter_pattern(&item->patt);
		free(item);
	}
}

static int script_init_for_testing(struct script_info *info, enum uftrace_pattern_type ptype)
{
	int i;
	char *name;

	strv_for_each(&info->cmds, name, i)
		script_add_filter(name, ptype);

	return 0;
}

static void script_finish_for_testing(void)
{
}

int script_init(struct script_info *info, enum uftrace_pattern_type ptype)
{
	char *script_pathname = info->name;

	pr_dbg2("%s(\"%s\")\n", __func__, script_pathname);
	if (access(script_pathname, F_OK) < 0) {
		perror(script_pathname);
		return -1;
	}

	script_lang = get_script_type(script_pathname);
	switch (script_lang) {
	case SCRIPT_PYTHON:
		if (script_init_for_python(info, ptype) < 0) {
			pr_warn("failed to init python scripting\n");
			script_pathname = NULL;
		}
		break;
	case SCRIPT_LUAJIT:
		if (script_init_for_luajit(info, ptype) < 0) {
			pr_warn("failed to init luajit scripting\n");
			script_pathname = NULL;
		}
		break;
	case SCRIPT_TESTING:
		if (script_init_for_testing(info, ptype) < 0) {
			pr_warn("failed to init test scripting\n");
			script_pathname = NULL;
		}
		break;
	default:
		pr_warn("unsupported script type: %s\n", script_pathname);
		script_pathname = NULL;
	}

	if (script_pathname == NULL)
		return -1;

	return 0;
}

void script_finish(void)
{
	pr_dbg2("%s()\n", __func__);
	switch (script_lang) {
	case SCRIPT_PYTHON:
		script_finish_for_python();
		break;
	case SCRIPT_LUAJIT:
		script_finish_for_luajit();
		break;
	case SCRIPT_TESTING:
		script_finish_for_testing();
		break;
	default:
		break;
	}

	script_finish_filter();
}

#ifdef UNIT_TEST
#include <stdio.h>

#define SCRIPT_FILE "xxx.testing"

static int setup_testing_script(struct script_info *info)
{
	FILE *fp;

	fp = fopen(SCRIPT_FILE, "w+");
	if (fp == NULL)
		return -1;

	fprintf(fp, "# uftrace script testing\n");

	strv_append(&info->cmds, "abc");
	strv_append(&info->cmds, "x*z");

	fclose(fp);
	return 0;
}

static int cleanup_testing_script(struct script_info *info)
{
	unlink(SCRIPT_FILE);
	strv_free(&info->cmds);
	return 0;
}

TEST_CASE(script_init)
{
	struct script_info info = {
		.version = "UFTRACE_VERSION",
		.name = SCRIPT_FILE,
	};

	pr_dbg("checking basic script init and finish\n");
	TEST_EQ(setup_testing_script(&info), 0);

	TEST_EQ(script_init(&info, PATT_GLOB), 0);
	TEST_EQ(list_empty(&filters), false);

	TEST_EQ(script_match_filter("abc"), 1);
	TEST_EQ(script_match_filter("xxyyzz"), 1);

	script_finish();
	TEST_EQ(list_empty(&filters), true);

	TEST_EQ(cleanup_testing_script(&info), 0);

	return TEST_OK;
}
#endif /* UNIT_TEST */
