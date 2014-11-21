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

#define TERM_COLOR_NORMAL	""
#define TERM_COLOR_RESET	"\033[m"
#define TERM_COLOR_BOLD		"\033[1m"
#define TERM_COLOR_RED		"\033[31m"
#define TERM_COLOR_GREEN	"\033[32m"

int debug;
int logfd = STDERR_FILENO;

#define color(C)  write(logfd, C, sizeof(C)-1)

void __pr_log(const char *fmt, ...)
{
	va_list ap;

	color(TERM_COLOR_BOLD);

	va_start(ap, fmt);
	vdprintf(logfd, fmt, ap);
	va_end(ap);

	color(TERM_COLOR_RESET);
}

void __pr_err(const char *fmt, ...)
{
	va_list ap;

	color(TERM_COLOR_RED);

	va_start(ap, fmt);
	vdprintf(logfd, fmt, ap);
	va_end(ap);

	color(TERM_COLOR_RESET);

	exit(1);
}

void __pr_err_s(const char *fmt, ...)
{
	va_list ap;
	int saved_errno = errno;
	char buf[512];

	color(TERM_COLOR_RED);

	va_start(ap, fmt);
	vdprintf(logfd, fmt, ap);
	va_end(ap);

	dprintf(logfd, ": %s\n", strerror_r(saved_errno, buf, sizeof(buf)));

	color(TERM_COLOR_RESET);

	exit(1);
}
