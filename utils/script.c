/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

/* This should be defined before #include "utils.h" */
#define PR_FMT     "script"
#define PR_DOMAIN  DBG_SCRIPT

#include <unistd.h>
#include <regex.h>
#include "utils/script.h"
#include "utils/filter.h"
#include "utils/list.h"


/* This will be set by getenv("UFTRACE_SCRIPT"). */
char *script_str;

/* The below functions are used both in record time and script command. */
script_uftrace_entry_t script_uftrace_entry;
script_uftrace_exit_t script_uftrace_exit;
script_uftrace_end_t script_uftrace_end;

struct script_filter_item {
	struct list_head	list;
	char			*name;
	bool			is_regex;
	regex_t			re;
};

static LIST_HEAD(filters);

static enum script_type_t get_script_type(const char *str)
{
	char *ext = strrchr(str, '.');

	/*
	 * The given script will be detected by the file suffix.
	 * As of now, it only handles ".py" suffix for python.
	 */
	if (!strcmp(ext, ".py"))
		return SCRIPT_PYTHON;

	return SCRIPT_UNKNOWN;
}

void script_add_filter(char *func)
{
	struct script_filter_item *item;

	if (func == NULL)
		return;

	item = xmalloc(sizeof(*item));

	item->name = xstrdup(func);
	item->is_regex = strpbrk(func, REGEX_CHARS);
	if (item->is_regex)
		regcomp(&item->re, item->name, REG_EXTENDED);

	pr_dbg2("add script filter: %s (%s)\n", item->name,
		item->is_regex ? "regex" : "simple");

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
		if (item->is_regex) {
			if (!regexec(&item->re, func, 0, NULL, 0))
				return 1;
		}
		else if (!strcmp(item->name, func))
			return 1;
	}
	return 0;
}

void script_finish_filter(void)
{
	struct script_filter_item *item, *tmp;

	list_for_each_entry_safe(item, tmp, &filters, list) {
		if (item->is_regex)
			regfree(&item->re);
		free(item->name);
		free(item);
	}
}

int script_init(char *script_pathname)
{
	if (access(script_pathname, F_OK) < 0) {
		perror(script_pathname);
		return -1;
	}

	switch (get_script_type(script_pathname)) {
	case SCRIPT_PYTHON:
		if (script_init_for_python(script_pathname) < 0) {
			pr_dbg("failed to init python scripting\n");
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
	script_finish_filter();
}
