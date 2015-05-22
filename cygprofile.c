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

static void __attribute__((constructor)) mcount_init(void)
{
	__monstartup(0, ~0);
}

static void __attribute__((destructor)) mcount_fini(void)
{
	_mcleanup();
}

void __attribute__((visibility("default")))
__cyg_profile_func_enter(void *child, void *parent)
{
	int ret;

	pr_dbg2("p: %p, c: %p\n", parent, child);

	ret = mcount_entry((unsigned long)parent, (unsigned long)child);
	if (ret < 0)
		pr_dbg2("\tfiltered [%d]\n", mcount_rstack_idx);
	else
		pr_dbg2("\tmcount_rstack_idx = %d\n", mcount_rstack_idx);
}

void __attribute__((visibility("default")))
__cyg_profile_func_exit(void *child, void *parent)
{
	int idx = mcount_rstack_idx;

	pr_dbg2("p: %p, c: %p\n", parent, child);

	if (idx < 0)
		idx += MCOUNT_NOTRACE_IDX;

	if (idx <= 0 || idx >= MCOUNT_RSTACK_MAX) {
		pr_dbg2("bad index [%d] for %p -> %p\n",
			idx, parent, child);
		return;
	}

	if (mcount_rstack[idx-1].child_ip == (unsigned long)child &&
	    mcount_rstack[idx-1].parent_ip == (unsigned long)parent)
		mcount_exit();
	else
		pr_dbg2("\tskipped (%p), mcount_rstack_idx = %d (%d)\n",
			child, mcount_rstack_idx, idx);
}
