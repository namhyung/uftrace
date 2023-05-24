/*
 * Python script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef UFTRACE_SCRIPT_PYTHON_H
#define UFTRACE_SCRIPT_PYTHON_H

#include "utils/filter.h"

struct uftrace_script_info;

#if defined(HAVE_LIBPYTHON2) || defined(HAVE_LIBPYTHON3)

#include <Python.h>

int script_init_for_python(struct uftrace_script_info *info, enum uftrace_pattern_type ptype);
void script_finish_for_python(void);

#else /* HAVE_LIBPYTHON2 || HAVE_LIBPYTHON3 */

/* Do nothing if libpython.so is not installed. */
static inline int script_init_for_python(struct uftrace_script_info *info,
					 enum uftrace_pattern_type ptype)
{
	return -1;
}

static inline void script_finish_for_python(void)
{
}

#endif /* HAVE_LIBPYTHON2 || HAVE_LIBPYTHON3 */

#endif /* UFTRACE_SCRIPT_PYTHON_H */
