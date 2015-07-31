/*
 * dummy mcount() routine for ftrace
 *
 * Copyright (C) 2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */
void __attribute__((visibility("default")))
mcount(void)
{
}

void __attribute__((visibility("default")))
__fentry__(void)
{
}
