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
#include <assert.h>
#include <limits.h>
#include <inttypes.h>

#include "utils/utils.h"

#define TERM_COLOR_NORMAL	""
#define TERM_COLOR_RESET	"\033[0m"
#define TERM_COLOR_BOLD		"\033[1m"
#define TERM_COLOR_RED		"\033[31m"
#define TERM_COLOR_GREEN	"\033[32m"
#define TERM_COLOR_YELLOW	"\033[33m"

int debug;
FILE *logfp;
int log_color = 1;
FILE *outfp;

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

	if (isatty(fileno(logfp)) && isatty(fileno(outfp)))
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

void __pr_out(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(outfp, fmt, ap);
	va_end(ap);
}

void print_time_unit(uint64_t delta_nsec)
{
	uint64_t delta = delta_nsec;
	uint64_t delta_small = 0;
	char *units[] = { "us", "ms", " s", " m", " h", };
	char *color_units[] = {
		TERM_COLOR_NORMAL "us" TERM_COLOR_RESET,
		TERM_COLOR_GREEN  "ms" TERM_COLOR_RESET,
		TERM_COLOR_YELLOW " s" TERM_COLOR_RESET,
		TERM_COLOR_RED    " m" TERM_COLOR_RESET,
		TERM_COLOR_RED    " h" TERM_COLOR_RESET,
	};
	char *unit;
	unsigned limit[] = { 1000, 1000, 1000, 60, 24, INT_MAX, };
	unsigned idx;

	if (delta_nsec == 0UL) {
		pr_out(" %7s %2s", "", "");
		return;
	}

	for (idx = 0; idx < ARRAY_SIZE(unit); idx++) {
		delta_small = delta % limit[idx];
		delta = delta / limit[idx];

		if (delta < limit[idx+1])
			break;
	}

	assert(idx < ARRAY_SIZE(units));

	if (log_color)
		unit = color_units[idx];
	else
		unit = units[idx];

	pr_out(" %3"PRIu64".%03"PRIu64" %s", delta, delta_small, unit);
}
