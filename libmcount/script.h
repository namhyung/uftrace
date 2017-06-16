/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef SCRIPT_H
#define SCRIPT_H

#include "libmcount/mcount.h"

extern char *script_str;

extern int (*script_uftrace_entry)(struct mcount_ret_stack *rstack);
extern int (*script_uftrace_exit)(struct mcount_ret_stack *rstack, long *retval);

#endif
