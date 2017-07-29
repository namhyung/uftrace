/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <unistd.h>
#include "utils/script.h"


/* This will be set by getenv("UFTRACE_SCRIPT"). */
char *script_str;

/* The below functions are used both in record time and script command. */
script_uftrace_entry_t script_uftrace_entry;
script_uftrace_exit_t script_uftrace_exit;

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

int script_init(char *script_pathname)
{
	if (access(script_pathname, F_OK) < 0) {
		perror(script_pathname);
		return -1;
	}

	switch (get_script_type(script_pathname)) {
	case SCRIPT_PYTHON:
		if (script_init_for_python(script_pathname) < 0)
			script_pathname = NULL;
		break;
	default:
		script_pathname = NULL;
	}

	return 0;
}
