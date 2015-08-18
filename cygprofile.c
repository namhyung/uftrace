/*
 * __cyg_profile_func_{enter,exit} routines for ftrace
 *
 * Copyright (C) 2014-2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>

#include "mcount.h"
#include "utils.h"

void __attribute__((visibility("default")))
__cyg_profile_func_enter(void *child, void *parent)
{
	pr_dbg2("p: %p, c: %p\n", parent, child);

	cygprof_entry((unsigned long)parent, (unsigned long)child);
}

void __attribute__((visibility("default")))
__cyg_profile_func_exit(void *child, void *parent)
{
	pr_dbg2("p: %p, c: %p\n", parent, child);

	cygprof_exit((unsigned long)parent, (unsigned long)child);
}
