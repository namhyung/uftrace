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
FILE *logfp;
int log_color = 1;

static void color(const char *code)
{
	size_t len = strlen(code);

	if (!log_color)
		return;

	if (fwrite(code, 1, len, logfp) == len)
		return;  /* ok */

	/* disable color */
	log_color = 0;

	len = sizeof(TERM_COLOR_RESET) - 1;
	if (fwrite(TERM_COLOR_RESET, 1, len, logfp) != len)
		pr_err("resetting terminal color failed");
}

void setup_color(int color)
{
	log_color = color;

	if (log_color >= 0)
		return;

	if (isatty(fileno(logfp)))
		log_color = 1;
	else
		log_color = 0;
}

void __pr_log(const char *fmt, ...)
{
	va_list ap;

	color(TERM_COLOR_BOLD);

	va_start(ap, fmt);
	vfprintf(logfp, fmt, ap);
	va_end(ap);

	color(TERM_COLOR_RESET);
}

void __pr_err(const char *fmt, ...)
{
	va_list ap;

	color(TERM_COLOR_RED);

	va_start(ap, fmt);
	vfprintf(logfp, fmt, ap);
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
	vfprintf(logfp, fmt, ap);
	va_end(ap);

	fprintf(logfp, ": %s\n", strerror_r(saved_errno, buf, sizeof(buf)));

	color(TERM_COLOR_RESET);

	exit(1);
}
