/*
 * Python script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef UFTRACE_SCRIPT_PYTHON_H
#define UFTRACE_SCRIPT_PYTHON_H

#ifdef HAVE_LIBPYTHON2

#include <python2.7/Python.h>

#define SCRIPT_ENABLED 1
int script_init_for_python(char *py_pathname);
void script_finish_for_python(void);


#else /* HAVE_LIBPYTHON2 */


/* Do nothing if libpython2.7.so is not installed. */
#define SCRIPT_ENABLED 0
static inline int script_init_for_python(char *py_pathname)
{
	return -1;
}

static inline void script_finish_for_python(void) {}

#endif /* HAVE_LIBPYTHON2 */

#endif /* UFTRACE_SCRIPT_PYTHON_H */
