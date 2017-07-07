/*
 * Python binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef PYHOOK_H
#define PYHOOK_H

#include "script.h"
#include <python2.7/Python.h>

int python_init(char *py_pathname);

#endif
