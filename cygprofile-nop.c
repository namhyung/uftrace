/*
 * dummy __cyg_profile_func_{enter,exit} routines for ftrace
 *
 * Copyright (C) 2014-2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */
void __attribute__((visibility("default")))
__cyg_profile_func_enter(void *child, void *parent)
{
}

void __attribute__((visibility("default")))
__cyg_profile_func_exit(void *child, void *parent)
{
}
