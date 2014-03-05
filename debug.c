#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include "utils.h"

bool debug;
int logfd = STDERR_FILENO;

void pr_dbg(const char *fmt, ...)
{
	va_list ap;

	if (!debug)
		return;

	va_start(ap, fmt);
	vdprintf(logfd, fmt, ap);
	va_end(ap);
}

void pr_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdprintf(logfd, fmt, ap);
	va_end(ap);
}

void pr_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdprintf(logfd, fmt, ap);
	va_end(ap);

	exit(1);
}
