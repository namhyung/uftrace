/*
 * uftrace - Function (Graph) Tracer for Userspace
 *
 * Copyright (C) 2014-2016  LG Electornics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "ftrace"

#include "uftrace.h"
#include "version.h"
#include "libmcount/mcount.h"
#include "libtraceevent/kbuffer.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"
#include "utils/list.h"
#include "utils/fstack.h"
#include "utils/filter.h"

const char *argp_program_version = "uftrace " UFTRACE_VERSION;
const char *argp_program_bug_address = "http://mod.lge.com/hub/otc/ftrace/issues";

static bool dbg_domain_set = false;

enum options {
	OPT_flat	= 301,
	OPT_plthook,
	OPT_symbols,
	OPT_logfile,
	OPT_force,
	OPT_threads,
	OPT_no_merge,
	OPT_nop,
	OPT_time,
	OPT_max_stack,
	OPT_port,
	OPT_nopager,
	OPT_avg_total,
	OPT_avg_self,
	OPT_color,
	OPT_disabled,
	OPT_demangle,
	OPT_dbg_domain,
	OPT_report,
	OPT_column_view,
	OPT_column_offset,
	OPT_bind_not,
	OPT_task_newline,
	OPT_chrome_trace,
	OPT_diff,
	OPT_sort_column,
	OPT_tid_filter,
};

static struct argp_option ftrace_options[] = {
	{ "library-path", 'L', "PATH", 0, "Load libraries from this PATH" },
	{ "filter", 'F', "FUNC", 0, "Only trace those FUNCs" },
	{ "notrace", 'N', "FUNC", 0, "Don't trace those FUNCs" },
	{ "trigger", 'T', "FUNC@act[,act,...]", 0, "Trigger action on those FUNCs" },
	{ "depth", 'D', "DEPTH", 0, "Trace functions within DEPTH" },
	{ "debug", 'v', 0, 0, "Print debug messages" },
	{ "verbose", 'v', 0, 0, "Print verbose (debug) messages" },
	{ "data", 'd', "DATA", 0, "Use this DATA instead of uftrace.data" },
	{ "flat", OPT_flat, 0, 0, "Use flat output format" },
	{ "no-plthook", OPT_plthook, 0, 0, "Don't hook library function calls" },
	{ "symbols", OPT_symbols, 0, 0, "Print symbol tables" },
	{ "buffer", 'b', "SIZE", 0, "Size of tracing buffer" },
	{ "logfile", OPT_logfile, "FILE", 0, "Save log messages to this file" },
	{ "force", OPT_force, 0, 0, "Trace even if executable is not instrumented" },
	{ "threads", OPT_threads, 0, 0, "Report thread stats instead" },
	{ "tid", OPT_tid_filter, "TID[,TID,...]", 0, "Only replay those tasks" },
	{ "no-merge", OPT_no_merge, 0, 0, "Don't merge leaf functions" },
	{ "nop", OPT_nop, 0, 0, "No operation (for performance test)" },
	{ "time", OPT_time, 0, 0, "Print time information" },
	{ "max-stack", OPT_max_stack, "DEPTH", 0, "Set max stack depth to DEPTH" },
	{ "kernel", 'k', 0, 0, "Trace kernel functions also (if supported)" },
	{ "kernel-full", 'K', 0, 0, "Trace kernel functions in detail (if supported)" },
	{ "host", 'H', "HOST", 0, "Send trace data to HOST instead of write to file" },
	{ "port", OPT_port, "PORT", 0, "Use PORT for network connection" },
	{ "no-pager", OPT_nopager, 0, 0, "Do not use pager" },
	{ "sort", 's', "KEY[,KEY,...]", 0, "Sort reported functions by KEYs" },
	{ "avg-total", OPT_avg_total, 0, 0, "Show average/min/max of total function time" },
	{ "avg-self", OPT_avg_self, 0, 0, "Show average/min/max of self function time" },
	{ "color", OPT_color, "SET", 0, "Use color for output: yes, no, auto" },
	{ "disable", OPT_disabled, 0, 0, "Start with tracing disabled" },
	{ "demangle", OPT_demangle, "TYPE", 0, "C++ symbol demangling: full, simple, no" },
	{ "debug-domain", OPT_dbg_domain, "DOMAIN", 0, "Filter debugging domain" },
	{ "report", OPT_report, 0, 0, "Show live report" },
	{ "column-view", OPT_column_view, 0, 0, "Print tasks in separate columns" },
	{ "column-offset", OPT_column_offset, "DEPTH", 0, "Offset of each column (default: 8)" },
	{ "no-pltbind", OPT_bind_not, 0, 0, "Do not bind dynamic symbols (LD_BIND_NOT)" },
	{ "task-newline", OPT_task_newline, 0, 0, "Interleave a newline when task is changed" },
	{ "time-filter", 't', "TIME", 0, "Hide small functions below the limit" },
	{ "argument", 'A', "FUNC@arg[,arg,...]", 0, "Show function arguments" },
	{ "retval", 'R', "FUNC@retval", 0, "Show function return value" },
	{ "chrome", OPT_chrome_trace, 0, 0, "Dump recored data in chrome trace format" },
	{ "diff", OPT_diff, "DATA", 0, "Report differences" },
	{ "sort-column", OPT_sort_column, "INDEX", 0, "Sort diff report on column INDEX" },
	{ 0 }
};

static unsigned long parse_size(char *str)
{
	unsigned long size;
	char *unit;

	size = strtoul(str, &unit, 0);
	switch (*unit) {
	case '\0':
		break;
	case 'k':
	case 'K':
		size <<= 10;
		break;
	case 'm':
	case 'M':
		size <<= 20;
		break;
	case 'g':
	case 'G':
		size <<= 30;
		break;

	default:
		pr_use("invalid size: %s\n", str);
		size = 0;
		break;
	}

	return size;
}

static char * opt_add_string(char *old, char *new)
{
	size_t oldlen = old ? strlen(old) : 0;
	size_t newlen = strlen(new);
	char *opt;

	opt = xrealloc(old, oldlen + newlen + 2);
	if (old)
		opt[oldlen++] = ';';
	strcpy(opt + oldlen, new);
	return opt;
}

static char * opt_add_prefix_string(char *old, char *prefix, char *new)
{
	size_t oldlen = old ? strlen(old) : 0;
	size_t prelen = strlen(prefix);
	size_t newlen = strlen(new);
	char *opt;

	opt = xrealloc(old, oldlen + prelen + newlen + 2);
	if (old)
		opt[oldlen++] = ';';
	strcpy(opt + oldlen, prefix);
	strcpy(opt + oldlen + prelen, new);
	return opt;
}

static const char * true_str[] = {
	"true", "yes", "on", "y", "1",
};

static const char * false_str[] = {
	"false", "no", "off", "n", "0",
};

static int parse_color(char *arg)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(true_str); i++) {
		if (!strcmp(arg, true_str[i]))
			return 1;
	}

	for (i = 0; i < ARRAY_SIZE(false_str); i++) {
		if (!strcmp(arg, false_str[i]))
			return 0;
	}

	if (!strcmp(arg, "auto"))
		return -1;

	return -2;
}

static int parse_demangle(char *arg)
{
	size_t i;

	if (!strcmp(arg, "simple"))
		return DEMANGLE_SIMPLE;

	if (!strcmp(arg, "full")) {
		if (support_full_demangle())
			return DEMANGLE_FULL;
		return DEMANGLE_NOT_SUPPORTED;
	}

	for (i = 0; i < ARRAY_SIZE(false_str); i++) {
		if (!strcmp(arg, false_str[i]))
			return DEMANGLE_NONE;
	}

	return DEMANGLE_ERROR;
}

static void parse_debug_domain(char *arg)
{
	char *str, *saved_str;
	char *tok, *pos, *tmp;

	saved_str = str = xstrdup(arg);
	while ((tok = strtok_r(str, ",", &pos)) != NULL) {
		int level = -1;

		tmp = strchr(tok, ':');
		if (tmp) {
			*tmp++ = '\0';
			level = strtol(tmp, NULL, 0);
		}

		if (!strcmp(tok, "ftrace"))
			dbg_domain[DBG_FTRACE] = level;
		else if (!strcmp(tok, "symbol"))
			dbg_domain[DBG_SYMBOL] = level;
		else if (!strcmp(tok, "demangle"))
			dbg_domain[DBG_DEMANGLE] = level;
		else if (!strcmp(tok, "filter"))
			dbg_domain[DBG_FILTER] = level;
		else if (!strcmp(tok, "fstack"))
			dbg_domain[DBG_FSTACK] = level;
		else if (!strcmp(tok, "session"))
			dbg_domain[DBG_SESSION] = level;
		else if (!strcmp(tok, "kernel"))
			dbg_domain[DBG_KERNEL] = level;
		else if (!strcmp(tok, "mcount"))
			dbg_domain[DBG_MCOUNT] = level;

		str = NULL;
	}

	dbg_domain_set = true;
	free(saved_str);
}

static uint64_t parse_time(char *arg)
{
	char *unit;
	uint64_t val = strtoull(arg, &unit, 0);

	if (unit == NULL || *unit == '\0')
		return val;

	if (!strcasecmp(unit, "us") || !strcasecmp(unit, "usec"))
		val *= 1000;
	else if (!strcasecmp(unit, "ms") || !strcasecmp(unit, "msec"))
		val *= 1000 * 1000;
	else if (!strcasecmp(unit, "s") || !strcasecmp(unit, "sec"))
		val *= 1000 * 1000 * 1000;

	return val;
}

static error_t parse_option(int key, char *arg, struct argp_state *state)
{
	struct opts *opts = state->input;

	switch (key) {
	case 'L':
		opts->lib_path = arg;
		break;

	case 'F':
		opts->filter = opt_add_string(opts->filter, arg);
		break;

	case 'N':
		opts->filter = opt_add_prefix_string(opts->filter, "!", arg);
		break;

	case 'T':
		opts->trigger = opt_add_string(opts->trigger, arg);
		break;

	case 'D':
		opts->depth = strtol(arg, NULL, 0);
		if (opts->depth <= 0)
			pr_use("invalid depth given: %s\n", arg);
		break;

	case 'v':
		debug++;
		break;

	case 'd':
		opts->dirname = arg;
		break;

	case 'b':
		opts->bsize = parse_size(arg);
		if (opts->bsize & (getpagesize() - 1))
			pr_use("buffer size should be multiple of page size\n");
		break;

	case 'k':
		opts->kernel = 1;
		break;

	case 'K':
		opts->kernel = 2;
		break;

	case 'H':
		opts->host = arg;
		break;

	case 's':
		opts->sort_keys = opt_add_string(opts->sort_keys, arg);
		break;

	case 't':
		opts->threshold = parse_time(arg);
		break;

	case 'A':
		opts->args = opt_add_string(opts->args, arg);
		break;

	case 'R':
		opts->retval = opt_add_string(opts->retval, arg);
		break;

	case OPT_flat:
		opts->flat = true;
		break;

	case OPT_plthook:
		opts->want_plthook = false;
		break;

	case OPT_symbols:
		opts->print_symtab = true;
		break;

	case OPT_logfile:
		opts->logfile = arg;
		break;

	case OPT_force:
		opts->force = true;
		break;

	case OPT_threads:
		opts->report_thread = true;
		break;

	case OPT_tid_filter:
		opts->tid = opt_add_string(opts->tid, arg);
		break;

	case OPT_no_merge:
		opts->no_merge = true;
		break;

	case OPT_nop:
		opts->nop = true;
		break;

	case OPT_time:
		opts->time = true;
		break;

	case OPT_max_stack:
		opts->max_stack = strtol(arg, NULL, 0);
		if (opts->max_stack <= 0 || opts->max_stack > MCOUNT_RSTACK_MAX)
			pr_use("max stack depth should be >0 and <%d\n",
			       MCOUNT_RSTACK_MAX);
		break;

	case OPT_port:
		opts->port = strtol(arg, NULL, 0);
		if (opts->port <= 0)
			pr_use("invalid port number: %s\n", arg);
		break;

	case OPT_nopager:
		opts->use_pager = false;
		break;

	case OPT_avg_total:
		opts->avg_total = true;
		break;

	case OPT_avg_self:
		opts->avg_self = true;
		break;

	case OPT_color:
		opts->color = parse_color(arg);
		if (opts->color == -2)
			pr_use("unknown color setting: %s\n", arg);
		break;

	case OPT_disabled:
		opts->disabled = true;
		break;

	case OPT_demangle:
		demangler = parse_demangle(arg);
		if (demangler == DEMANGLE_ERROR)
			pr_use("unknown demangle value: %s\n", arg);
		else if (demangler == DEMANGLE_NOT_SUPPORTED)
			pr_use("'%s' demangler is not supported\n", arg);
		break;

	case OPT_dbg_domain:
		parse_debug_domain(arg);
		break;

	case OPT_report:
		opts->report = true;
		break;

	case OPT_column_view:
		opts->column_view = true;
		break;

	case OPT_column_offset:
		opts->column_offset = strtol(arg, NULL, 0);
		break;

	case OPT_bind_not:
		opts->want_bind_not = true;
		break;

	case OPT_task_newline:
		opts->task_newline = true;
		break;

	case OPT_chrome_trace:
		opts->chrome_trace = true;
		break;

	case OPT_diff:
		opts->diff = arg;
		break;

	case OPT_sort_column:
		opts->sort_column = strtol(arg, NULL, 0);
		if (opts->sort_column < 0 || opts->sort_column > 2)
			pr_use("invalid column number: %s\n", arg);
		break;

	case ARGP_KEY_ARG:
		if (state->arg_num) {
			/*
			 * This is a second non-option argument.
			 * Returning ARGP_ERR_UNKNOWN will pass control to
			 * the ARGP_KEY_ARGS case.
			 */
			return ARGP_ERR_UNKNOWN;
		}
		if (!strcmp("record", arg))
			opts->mode = FTRACE_MODE_RECORD;
		else if (!strcmp("replay", arg))
			opts->mode = FTRACE_MODE_REPLAY;
		else if (!strcmp("live", arg))
			opts->mode = FTRACE_MODE_LIVE;
		else if (!strcmp("report", arg))
			opts->mode = FTRACE_MODE_REPORT;
		else if (!strcmp("info", arg))
			opts->mode = FTRACE_MODE_INFO;
		else if (!strcmp("recv", arg))
			opts->mode = FTRACE_MODE_RECV;
		else if (!strcmp("dump", arg))
			opts->mode = FTRACE_MODE_DUMP;
		else
			return ARGP_ERR_UNKNOWN; /* almost same as fall through */
		break;

	case ARGP_KEY_ARGS:
		/*
		 * process remaining non-option arguments
		 */
		if (opts->mode == FTRACE_MODE_INVALID)
			opts->mode = FTRACE_MODE_DEFAULT;

		opts->exename = state->argv[state->next];
		opts->idx = state->next;
		break;

	case ARGP_KEY_NO_ARGS:
	case ARGP_KEY_END:
		if (state->arg_num < 1)
			argp_usage(state);

		if (opts->exename == NULL) {
			switch (opts->mode) {
			case FTRACE_MODE_RECORD:
			case FTRACE_MODE_LIVE:
				argp_usage(state);
				break;
			default:
				/* will be set after read_ftrace_info() */
				break;
			}
		}
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

#ifndef UNIT_TEST
int main(int argc, char *argv[])
{
	struct opts opts = {
		.mode		= FTRACE_MODE_INVALID,
		.dirname	= FTRACE_DIR_NAME,
		.want_plthook	= true,
		.bsize		= SHMEM_BUFFER_SIZE,
		.depth		= MCOUNT_DEFAULT_DEPTH,
		.max_stack	= MCOUNT_RSTACK_MAX,
		.port		= FTRACE_RECV_PORT,
		.use_pager	= true,
		.color		= -1,  /* default to 'auto' (turn on if terminal) */
		.column_offset	= 8,
	};
	struct argp argp = {
		.options = ftrace_options,
		.parser = parse_option,
		.args_doc = "[record|replay|live|report|info|dump|recv] [<command> args...]",
		.doc = "uftrace -- function (graph) tracer for userspace",
	};

	/* this must be done before argp_parse() */
	logfp = stderr;
	outfp = stdout;

	argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &opts);

	if (dbg_domain_set && !debug)
		debug = 1;

	if (opts.logfile) {
		logfp = fopen(opts.logfile, "w");
		if (logfp == NULL)
			pr_err("cannot open log file");

		setvbuf(logfp, NULL, _IOLBF, 1024);
	}
	else if (debug) {
		/* ensure normal output is not mixed by debug message */
		setvbuf(outfp, NULL, _IOLBF, 1024);
	}

	if (debug) {
		int d;

		/* set default debug level */
		for (d = 0; d < DBG_DOMAIN_MAX; d++) {
			if (dbg_domain[d] == -1 || !dbg_domain_set)
				dbg_domain[d] = debug;
		}
	}

	setup_color(opts.color);
	setup_signal();

	if (opts.use_pager)
		start_pager();

	switch (opts.mode) {
	case FTRACE_MODE_RECORD:
		command_record(argc, argv, &opts);
		break;
	case FTRACE_MODE_REPLAY:
		command_replay(argc, argv, &opts);
		break;
	case FTRACE_MODE_LIVE:
		command_live(argc, argv, &opts);
		break;
	case FTRACE_MODE_REPORT:
		command_report(argc, argv, &opts);
		break;
	case FTRACE_MODE_INFO:
		command_info(argc, argv, &opts);
		break;
	case FTRACE_MODE_RECV:
		command_recv(argc, argv, &opts);
		break;
	case FTRACE_MODE_DUMP:
		command_dump(argc, argv, &opts);
		break;
	case FTRACE_MODE_INVALID:
		break;
	}

	wait_for_pager();

	if (opts.logfile)
		fclose(logfp);

	return 0;
}
#endif /* UNIT_TEST */
