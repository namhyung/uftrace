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
#define TERM_COLOR_BLUE		"\033[34m"
#define TERM_COLOR_MAGENTA	"\033[35m"
#define TERM_COLOR_CYAN		"\033[36m"
#define TERM_COLOR_GRAY		"\033[37m"

int debug;
FILE *logfp;
FILE *outfp;
int log_color;
int out_color;
int dbg_domain[DBG_DOMAIN_MAX];

static const struct color_code {
	char		code;
	const char	*color;
} colors[] = {
	{ COLOR_CODE_RED,	TERM_COLOR_RED },
	{ COLOR_CODE_GREEN,	TERM_COLOR_GREEN },
	{ COLOR_CODE_BLUE,	TERM_COLOR_BLUE },
	{ COLOR_CODE_YELLOW,	TERM_COLOR_YELLOW },
	{ COLOR_CODE_MAGENTA,	TERM_COLOR_MAGENTA },
	{ COLOR_CODE_CYAN,	TERM_COLOR_CYAN },
	{ COLOR_CODE_GRAY,	TERM_COLOR_GRAY },
	{ COLOR_CODE_BOLD,	TERM_COLOR_BOLD },
};

static void color(const char *code, FILE *fp)
{
	size_t len = strlen(code);

	if ((fp == logfp && !log_color) ||
	    (fp == outfp && !out_color))
		return;

	if (fwrite(code, 1, len, fp) == len)
		return;  /* ok */

	/* disable color */
	log_color = 0;
	out_color = 0;

	len = sizeof(TERM_COLOR_RESET) - 1;
	if (fwrite(TERM_COLOR_RESET, 1, len, fp) != len)
		pr_err("resetting terminal color failed");
}

void setup_color(int color)
{
	log_color = color;
	out_color = color;

	if (log_color >= 0)
		return;

	if (isatty(fileno(logfp)))
		log_color = 1;
	else
		log_color = 0;

	if (isatty(fileno(outfp)))
		out_color = 1;
	else
		out_color = 0;
}

void __pr_dbg(const char *fmt, ...)
{
	va_list ap;

	color(TERM_COLOR_GRAY, logfp);

	va_start(ap, fmt);
	vfprintf(logfp, fmt, ap);
	va_end(ap);

	color(TERM_COLOR_RESET, logfp);
}

void __pr_log(const char *fmt, ...)
{
	va_list ap;

	color(TERM_COLOR_BOLD, logfp);

	va_start(ap, fmt);
	vfprintf(logfp, fmt, ap);
	va_end(ap);

	color(TERM_COLOR_RESET, logfp);
}

void __pr_err(const char *fmt, ...)
{
	va_list ap;

	color(TERM_COLOR_RED, logfp);

	va_start(ap, fmt);
	vfprintf(logfp, fmt, ap);
	va_end(ap);

	color(TERM_COLOR_RESET, logfp);

	exit(1);
}

void __pr_err_s(const char *fmt, ...)
{
	va_list ap;
	int saved_errno = errno;
	char buf[512];

	color(TERM_COLOR_RED, logfp);

	va_start(ap, fmt);
	vfprintf(logfp, fmt, ap);
	va_end(ap);

	fprintf(logfp, ": %s\n", strerror_r(saved_errno, buf, sizeof(buf)));

	color(TERM_COLOR_RESET, logfp);

	exit(1);
}

void __pr_warn(const char *fmt, ...)
{
	va_list ap;

	color(TERM_COLOR_RED, logfp);

	va_start(ap, fmt);
	vfprintf(logfp, fmt, ap);
	va_end(ap);

	color(TERM_COLOR_RESET, logfp);
}

void __pr_out(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(outfp, fmt, ap);
	va_end(ap);
}

void __pr_color(char code, const char *fmt, ...)
{
	size_t i;
	va_list ap;
	const char *cs = TERM_COLOR_NORMAL;

	for (i = 0; i < ARRAY_SIZE(colors); i++) {
		if (code == colors[i].code)
			cs = colors[i].color;
	}

	color(cs, outfp);

	va_start(ap, fmt);
	vfprintf(outfp, fmt, ap);
	va_end(ap);

	color(TERM_COLOR_RESET, outfp);
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
		pr_out("%7s %2s", "", "");
		return;
	}

	for (idx = 0; idx < ARRAY_SIZE(unit); idx++) {
		delta_small = delta % limit[idx];
		delta = delta / limit[idx];

		if (delta < limit[idx+1])
			break;
	}

	assert(idx < ARRAY_SIZE(units));

	/* for some error cases */
	if (delta > 999)
		delta = delta_small = 999;

	if (out_color)
		unit = color_units[idx];
	else
		unit = units[idx];

	pr_out("%3"PRIu64".%03"PRIu64" %s", delta, delta_small, unit);
}

void print_diff_percent(uint64_t base_nsec, uint64_t pair_nsec)
{
	double percent = 100.0 * (int64_t)(pair_nsec - base_nsec) / base_nsec;
	char *color = percent > 20 ? TERM_COLOR_RED :
		percent > 3 ? TERM_COLOR_MAGENTA :
		percent < -20 ? TERM_COLOR_BLUE :
		percent < -3 ? TERM_COLOR_CYAN : TERM_COLOR_NORMAL;

	if (percent == 0) {
		pr_out(" %7s ", "");
		return;
	}

	/* for some error cases */
	if (percent > 999.99)
		percent = 999.99;

	if (out_color)
		pr_out(" %s%+7.2f%%%s", color, percent, TERM_COLOR_RESET);
	else
		pr_out(" %+7.2f%%", percent);
}
