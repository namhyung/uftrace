/*
 * debug routines for ftrace
 *
 * Copyright (C) 2014, LG Electronics, Namhyung Kim <namhyung@gmail.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "utils.h"

int debug;
int logfd = STDERR_FILENO;

void __pr_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdprintf(logfd, fmt, ap);
	va_end(ap);
}

void __pr_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdprintf(logfd, fmt, ap);
	va_end(ap);

	exit(1);
}

void __pr_err_s(const char *fmt, ...)
{
	va_list ap;
	int saved_errno = errno;
	char buf[512];

	va_start(ap, fmt);
	vdprintf(logfd, fmt, ap);
	va_end(ap);

	dprintf(logfd, ": %s\n", strerror_r(saved_errno, buf, sizeof(buf)));

	exit(1);
}
