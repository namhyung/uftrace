/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include "libmcount/script.h"

/* This will be set by getenv("UFTRACE_SCRIPT") */
char *script_str;

int (*script_uftrace_entry)(struct mcount_ret_stack *rstack);
int (*script_uftrace_exit)(struct mcount_ret_stack *rstack, long *retval);
