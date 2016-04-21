/*
 * dummy mcount() routine for ftrace
 *
 * Copyright (C) 2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include "utils/compiler.h"


void __visible_default mcount(void)
{
}

void __visible_default __gnu_mcount_nc(void)
{
}

void __visible_default __fentry__(void)
{
}

void __visible_default __cyg_profile_func_enter(void *child, void *parent)
{
}

void __visible_default __cyg_profile_func_exit(void *child, void *parent)
{
}

void __visible_default __monstartup(unsigned long low, unsigned long high)
{
}

void __visible_default _mcleanup(void)
{
}

void __visible_default mcount_restore(void)
{
}

void __visible_default mcount_reset(void)
{
}
