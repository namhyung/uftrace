/*
 * ftrace - Function Tracer
 *
 * Copyright (C) 2014-2015  LG Electornics, Namhyung Kim <namhyung.kim@lge.com>
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

#include "ftrace.h"
#include "version.h"
#include "libmcount/mcount.h"
#include "libtraceevent/kbuffer.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"
#include "utils/list.h"
#include "utils/fstack.h"
#include "utils/filter.h"

const char *argp_program_version = "ftrace " FTRACE_VERSION;
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
};

static struct argp_option ftrace_options[] = {
	{ "library-path", 'L', "PATH", 0, "Load libraries from this PATH" },
	{ "filter", 'F', "FUNC", 0, "Only trace those FUNCs" },
	{ "notrace", 'N', "FUNC", 0, "Don't trace those FUNCs" },
	{ "trigger", 'T', "FUNC@act[,act,...]", 0, "Trigger action on those FUNCs" },
	{ "depth", 'D', "DEPTH", 0, "Trace functions within DEPTH" },
	{ "debug", 'd', 0, 0, "Print debug messages" },
	{ "file", 'f', "FILE", 0, "Use this FILE instead of ftrace.data" },
	{ "flat", OPT_flat, 0, 0, "Use flat output format" },
	{ "no-plthook", OPT_plthook, 0, 0, "Don't hook library function calls" },
	{ "symbols", OPT_symbols, 0, 0, "Print symbol tables" },
	{ "buffer", 'b', "SIZE", 0, "Size of tracing buffer" },
	{ "logfile", OPT_logfile, "FILE", 0, "Save log messages to this file" },
	{ "force", OPT_force, 0, 0, "Trace even if executable is not instrumented" },
	{ "threads", OPT_threads, 0, 0, "Report thread stats instead" },
	{ "tid", 't', "TID[,TID,...]", 0, "Only replay those tasks" },
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
	{ "threshold", 'r', "TIME", 0, "Hide small functions below the limit" },
	{ "argument", 'A', "FUNC@arg[,arg,...]", 0, "Show function arguments" },
	{ "retval", 'R', "FUNC@retval", 0, "Show function return value" },
	{ "chrome", OPT_chrome_trace, 0, 0, "Dump recored data in chrome trace format" },
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

	case 't':
		opts->tid = opt_add_string(opts->tid, arg);
		break;

	case 'd':
		debug++;
		break;

	case 'f':
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

	case 'r':
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

static int command_dump(int argc, char *argv[], struct opts *opts);

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
		.args_doc = "[record|replay|live|report|info] [<command> args...]",
		.doc = "ftrace -- a function tracer",
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

static void pr_time(uint64_t timestamp)
{
	unsigned sec   = timestamp / 1000000000;
	unsigned nsec  = timestamp % 1000000000;

	pr_out("%u.%09u  ", sec, nsec);
}

static int pr_task(struct opts *opts)
{
	FILE *fp;
	char buf[PATH_MAX];
	struct ftrace_msg msg;
	struct ftrace_msg_task tmsg;
	struct ftrace_msg_sess smsg;
	char *exename;

	snprintf(buf, sizeof(buf), "%s/task", opts->dirname);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return -1;

	while (fread(&msg, sizeof(msg), 1, fp) == 1) {
		if (msg.magic != FTRACE_MSG_MAGIC) {
			pr_red("invalid message magic: %hx\n", msg.magic);
			goto out;
		}

		switch (msg.type) {
		case FTRACE_MSG_TID:
		case FTRACE_MSG_FORK_END:
			if (fread(&tmsg, sizeof(tmsg), 1, fp) != 1) {
				pr_red("cannot read task message: %m\n");
				goto out;
			}

			pr_time(tmsg.time);
			pr_out("task tid %d (pid %d)\n", tmsg.tid, tmsg.pid);
			break;
		case FTRACE_MSG_SESSION:
			if (fread(&smsg, sizeof(smsg), 1, fp) != 1) {
				pr_red("cannot read session message: %m\n");
				goto out;
			}
			exename = xmalloc(ALIGN(smsg.namelen, 8));
			if (fread(exename, ALIGN(smsg.namelen, 8), 1,fp) != 1 ) {
				pr_red("cannot read executable name: %m\n");
				goto out;
			}

			pr_time(smsg.task.time);
			pr_out("session of task %d/%d: %.*s (%s)\n",
			       smsg.task.tid, smsg.task.pid,
			       sizeof(smsg.sid), smsg.sid, exename);
			free(exename);
			break;
		default:
			pr_out("unknown message type: %u\n", msg.type);
			break;
		}
	}

out:
	fclose(fp);
	return 0;
}

static int pr_task_txt(struct opts *opts)
{
	FILE *fp;
	char buf[PATH_MAX];
	char *ptr, *end;
	char *timestamp;
	int pid, tid;
	char sid[20];

	snprintf(buf, sizeof(buf), "%s/task.txt", opts->dirname);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), fp)) {
		if (!strncmp(buf, "TASK", 4)) {
			ptr = strstr(buf, "timestamp=");
			if (ptr == NULL) {
				pr_red("invalid task timestamp\n");
				goto out;
			}
			timestamp = ptr + 10;

			end = strchr(ptr, ' ');
			if (end == NULL) {
				pr_red("invalid task timestamp\n");
				goto out;
			}
			*end++ = '\0';

			sscanf(end, "tid=%d pid=%d", &tid, &pid);

			pr_out("%s  task tid %d (pid %d)\n", timestamp, tid, pid);
		}
		else if (!strncmp(buf, "FORK", 4)) {
			ptr = strstr(buf, "timestamp=");
			if (ptr == NULL) {
				pr_red("invalid task timestamp\n");
				goto out;
			}
			timestamp = ptr + 10;

			end = strchr(ptr, ' ');
			if (end == NULL) {
				pr_red("invalid task timestamp\n");
				goto out;
			}
			*end++ = '\0';

			sscanf(end, "pid=%d ppid=%d", &tid, &pid);

			pr_out("%s  fork pid %d (ppid %d)\n", timestamp, tid, pid);
		}
		else if (!strncmp(buf, "SESS", 4)) {
			char *exename;

			ptr = strstr(buf, "timestamp=");
			if (ptr == NULL) {
				pr_red("invalid session timestamp\n");
				goto out;
			}
			timestamp = ptr + 10;

			end = strchr(ptr, ' ');
			if (end == NULL) {
				pr_red("invalid session timestamp\n");
				goto out;
			}
			*end++ = '\0';

			sscanf(end, "tid=%d sid=%s", &tid, sid);

			ptr = strstr(end, "exename=");
			if (ptr == NULL) {
				pr_red("invalid session exename\n");
				goto out;
			}
			exename = ptr + 8 + 1;  // skip double-quote

			end = strrchr(ptr, '\"');
			if (end == NULL) {
				pr_red("invalid session exename\n");
				goto out;
			}
			*end++ = '\0';

			pr_out("%s  session of task %d: %.*s (%s)\n",
			       timestamp, tid, 16, sid, exename);
		}
	}

out:
	fclose(fp);
	return 0;
}

static void pr_hex(uint64_t *offset, void *data, size_t len)
{
	size_t i;
	unsigned char *h = data;
	uint64_t ofs = *offset;

	if (!debug)
		return;

	while (len >= 16) {
		pr_green(" <%016"PRIx64">:", ofs);
		pr_green(" %02x %02x %02x %02x %02x %02x %02x %02x "
			 " %02x %02x %02x %02x %02x %02x %02x %02x\n",
			 h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
			 h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);

		ofs += 16;
		len -= 16;
		h += 16;
	}

	if (len) {
		pr_green(" <%016"PRIx64">:", ofs);
		if (len > 8) {
			pr_green(" %02x %02x %02x %02x %02x %02x %02x %02x ",
				 h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

			ofs += 8;
			len -= 8;
			h += 8;
		}

		for (i = 0; i < len; i++)
			pr_green(" %02x", *h++);
		pr_green("\n");

		ofs += len;
	}

	*offset = ofs;
}

static void pr_args(struct fstack_arguments *args)
{
	struct ftrace_arg_spec *spec;
	void *ptr = args->data;
	size_t size;
	int i = 0;

	list_for_each_entry(spec, args->args, list) {
		/* skip return value info */
		if (spec->idx == RETVAL_IDX)
			continue;

		if (spec->fmt == ARG_FMT_STR) {
			char buf[64];
			const int null_str = -1;

			size = *(unsigned short *)ptr;
			strncpy(buf, ptr + 2, size);

			if (!memcmp(buf, &null_str, 4))
				strcpy(buf, "NULL");

			pr_out("  args[%d] str: %s\n", i , buf);
			size += 2;
		}
		else {
			long long val = 0;

			memcpy(&val, ptr, spec->size);
			pr_out("  args[%d] %c%d: %#llx\n", i,
			       ARG_SPEC_CHARS[spec->fmt], spec->size * 8, val);
			size = spec->size;
		}

		ptr += ALIGN(size, 4);
		i++;
	}
}

static void pr_retval(struct fstack_arguments *args)
{
	struct ftrace_arg_spec *spec;
	void *ptr = args->data;
	size_t size;
	int i = 0;

	list_for_each_entry(spec, args->args, list) {
		/* skip argument info */
		if (spec->idx != RETVAL_IDX)
			continue;

		if (spec->fmt == ARG_FMT_STR) {
			char buf[64];
			const int null_str = -1;

			size = *(unsigned short *)ptr;
			strncpy(buf, ptr + 2, size);

			if (!memcmp(buf, &null_str, 4))
				strcpy(buf, "NULL");

			pr_out("  retval[%d] str: %s\n", i , buf);
			size += 2;
		}
		else {
			long long val = 0;

			memcpy(&val, ptr, spec->size);
			pr_out("  retval[%d] %c%d: %#llx\n", i,
			       ARG_SPEC_CHARS[spec->fmt], spec->size * 8, val);
			size = spec->size;
		}

		ptr += ALIGN(size, 4);
		i++;
	}
}

static void dump_raw(int argc, char *argv[], struct opts *opts,
		     struct ftrace_file_handle *handle)
{
	int i;
	uint64_t file_offset = 0;
	struct ftrace_task_handle task;

	pr_out("ftrace file header: magic         = ");
	for (i = 0; i < FTRACE_MAGIC_LEN; i++)
		pr_out("%02x", handle->hdr.magic[i]);
	pr_out("\n");
	pr_out("ftrace file header: version       = %u\n", handle->hdr.version);
	pr_out("ftrace file header: header size   = %u\n", handle->hdr.header_size);
	pr_out("ftrace file header: endian        = %u (%s)\n",
	       handle->hdr.endian, handle->hdr.endian == 1 ? "little" : "big");
	pr_out("ftrace file header: class         = %u (%s bit)\n",
	       handle->hdr.class, handle->hdr.class == 2 ? "64" : "32");
	pr_out("ftrace file header: features      = %#"PRIx64"\n", handle->hdr.feat_mask);
	pr_out("ftrace file header: info          = %#"PRIx64"\n", handle->hdr.info_mask);
	pr_hex(&file_offset, &handle->hdr, handle->hdr.header_size);
	pr_out("\n");

	if (debug) {
		pr_out("%d tasks found\n", handle->info.nr_tid);

		/* try to read task.txt first */
		if (pr_task_txt(opts) < 0 && pr_task(opts) < 0)
			pr_red("cannot open task file\n");

		pr_out("\n");
	}

	for (i = 0; i < handle->info.nr_tid; i++) {
		int tid = handle->info.tids[i];

		if (opts->kernel == 2)
			continue;

		setup_task_handle(handle, &task, tid);

		if (task.fp == NULL)
			continue;

		file_offset = 0;
		pr_out("reading %d.dat\n", tid);
		while (!read_task_ustack(&task)) {
			struct ftrace_ret_stack *frs = &task.ustack;
			struct ftrace_session *sess = find_task_session(tid, frs->time);
			struct symtabs *symtabs;
			struct sym *sym = NULL;
			char *name;

			if (sess) {
				symtabs = &sess->symtabs;
				sym = find_symtabs(symtabs, frs->addr, proc_maps);
			}

			name = symbol_getname(sym, frs->addr);

			pr_time(frs->time);
			pr_out("%5d: [%s] %s(%lx) depth: %u\n",
			       tid, frs->type == FTRACE_EXIT ? "exit " :
			       frs->type == FTRACE_ENTRY ? "entry" : "lost ",
			       name, (unsigned long)frs->addr, frs->depth);
			pr_hex(&file_offset, frs, sizeof(*frs));

			if (frs->more) {
				if (frs->type == FTRACE_ENTRY) {
					read_task_args(&task, frs, false);

					pr_time(frs->time);
					pr_out("%5d: [%s] length = %d\n", tid, "args ",
							task.args.len);
					pr_args(&task.args);
					pr_hex(&file_offset, task.args.data, task.args.len);
				} else if (frs->type == FTRACE_EXIT) {
					read_task_args(&task, frs, true);

					pr_time(frs->time);
					pr_out("%5d: [%s] length = %d\n", tid, "retval",
							task.args.len);
					pr_retval(&task.args);
					pr_hex(&file_offset, task.args.data, task.args.len);
				} else
					abort();
			}

			symbol_putname(sym, name);
		}

		fclose(task.fp);
	}

	if (opts->kernel == 0 || handle->kern == NULL)
		return;

	pr_out("\n");
	for (i = 0; i < handle->kern->nr_cpus; i++) {
		struct ftrace_kernel *kernel = handle->kern;
		struct mcount_ret_stack *mrs = &kernel->rstacks[i];
		struct kbuffer *kbuf = kernel->kbufs[i];
		int offset, size;
		struct sym *sym;
		char *name;

		file_offset = 0;
		offset = kbuffer_curr_offset(kbuf);
		pr_out("reading kernel-cpu%d.dat\n", i);
		while (!read_kernel_cpu_data(kernel, i)) {
			int losts = kernel->missed_events[i];

			sym = find_symtabs(NULL, mrs->child_ip, proc_maps);
			name = symbol_getname(sym, mrs->child_ip);

			if (losts) {
				pr_time(mrs->end_time ?: mrs->start_time);
				pr_red("%5d: [%s ]: %d events\n",
				       mrs->tid, "lost", losts);
				kernel->missed_events[i] = 0;
			}

			pr_time(mrs->end_time ?: mrs->start_time);
			pr_out("%5d: [%s] %s(%lx) depth: %u\n",
			       mrs->tid, mrs->end_time ? "exit " : "entry",
			       name, mrs->child_ip, mrs->depth);

			if (debug) {
				/* this is only needed for hex dump */
				void *data = kbuffer_read_at_offset(kbuf, offset, NULL);

				size = kbuffer_event_size(kbuf);
				file_offset = kernel->offsets[i] + kbuffer_curr_offset(kbuf);
				pr_hex(&file_offset, data, size);

				if (kbuffer_next_event(kbuf, NULL))
					offset += size + 4;  // 4 = event header size
				else
					offset = 0;
			}

			symbol_putname(sym, name);
		}
	}
}

static void print_ustack_chrome_trace(struct ftrace_task_handle *task,
				      struct ftrace_ret_stack *frs,
				      int tid, const char* name)
{
	char ph;
	char spec_buf[1024];
	enum argspec_string_bits str_mode = NEEDS_ESCAPE;

	if (frs->type == FTRACE_ENTRY) {
		ph = 'B';
		pr_out("{\"ts\":%lu,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
			frs->time / 1000, ph, tid, name);
		if (frs->more) {
			bool is_retval = false;
			read_task_args(task, frs, is_retval);

			str_mode |= HAS_MORE;
			get_argspec_string(task, spec_buf, sizeof(spec_buf), str_mode);
			pr_out(",\"args\":{\"arguments\":\"%s\"}}",
				spec_buf);
		} else
			pr_out("}");
	} else if (frs->type == FTRACE_EXIT) {
		ph = 'E';
		pr_out("{\"ts\":%lu,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
			frs->time / 1000, ph, tid, name);
		if (frs->more) {
			bool is_retval = true;
			read_task_args(task, frs, is_retval);

			str_mode |= IS_RETVAL | HAS_MORE;
			get_argspec_string(task, spec_buf, sizeof(spec_buf), str_mode);
			pr_out(",\"args\":{\"retval\":\"%s\"}}",
				spec_buf);
		} else
			pr_out("}");
	} else
		abort();
}

static void dump_chrome_trace(int argc, char *argv[], struct opts *opts,
			      struct ftrace_file_handle *handle)
{
	int i;
	struct ftrace_task_handle task;
	char buf[PATH_MAX];
	struct stat statbuf;

	/* read recorded date and time */
	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);
	if (stat(buf, &statbuf) < 0)
		return;

	ctime_r(&statbuf.st_mtime, buf);
	buf[strlen(buf) - 1] = '\0';

	pr_out("{\"traceEvents\":[\n");
	for (i = 0; i < handle->info.nr_tid; i++) {
		int tid = handle->info.tids[i];

		setup_task_handle(handle, &task, tid);

		if (task.fp == NULL)
			continue;

		while (!read_task_ustack(&task)) {
			struct ftrace_ret_stack *frs = &task.ustack;
			struct ftrace_session *sess = find_task_session(tid, frs->time);
			struct symtabs *symtabs;
			struct sym *sym = NULL;
			char *name;
			static bool last_comma = false;

			if (sess) {
				symtabs = &sess->symtabs;
				sym = find_symtabs(symtabs, frs->addr, proc_maps);
			}

			name = symbol_getname(sym, frs->addr);

			if (last_comma)
				pr_out(",\n");

			print_ustack_chrome_trace(&task, frs, tid, name);

			last_comma = true;

			symbol_putname(sym, name);
		}

		fclose(task.fp);
	}
	pr_out("\n");
	pr_out("], \"metadata\": {\n");
	if (handle->hdr.info_mask & (1UL << CMDLINE))
		pr_out("\"command_line\":\"%s\",\n", handle->info.cmdline);
	pr_out("\"recorded_time\":\"%s\"\n", buf);
	pr_out("} }\n");
}

static int command_dump(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
	struct ftrace_kernel kern;

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		pr_err("cannot open data: %s", opts->dirname);

	if (opts->kernel && (handle.hdr.feat_mask & KERNEL)) {
		kern.output_dir = opts->dirname;
		if (setup_kernel_data(&kern) == 0) {
			handle.kern = &kern;
			load_kernel_symbol();
		}
	}

	if (opts->chrome_trace)
		dump_chrome_trace(argc, argv, opts, &handle);
	else
		dump_raw(argc, argv, opts, &handle);

	close_data_file(opts, &handle);

	return ret;
}
