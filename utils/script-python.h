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

struct script_info;

#if defined(HAVE_LIBPYTHON2) || defined(HAVE_LIBPYTHON3)

#include <Python.h>

#define SCRIPT_PYTHON_ENABLED 1
int script_init_for_python(struct script_info *info,
			   enum uftrace_pattern_type ptype);
void script_finish_for_python(void);


#else /* HAVE_LIBPYTHON2 */


/* Do nothing if libpython2.7.so is not installed. */
#define SCRIPT_PYTHON_ENABLED 0
static inline int script_init_for_python(struct script_info *info,
					 enum uftrace_pattern_type ptype)
{
	return -1;
}

static inline void script_finish_for_python(void) {}

#endif /* HAVE_LIBPYTHON2 */

#endif /* UFTRACE_SCRIPT_PYTHON_H */
