/*
 * uftrace - Function (Graph) Tracer for Userspace
 *
 * Copyright (C) 2014-2018  LG Electronics
 * Author:  Namhyung Kim <namhyung@gmail.com>
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

#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "uftrace"

#include "uftrace.h"
#include "utils/script.h"
#include "utils/utils.h"
#include "version.h"

static const char uftrace_version[] = "uftrace " UFTRACE_VERSION;

static bool dbg_domain_set = false;

static bool parsing_default_opts = false;

enum uftrace_short_options {
	OPT_flat = 301,
	OPT_no_libcall,
	OPT_symbols,
	OPT_logfile,
	OPT_force,
	OPT_task,
	OPT_no_merge,
	OPT_nop,
	OPT_time,
	OPT_max_stack,
	OPT_host,
	OPT_port,
	OPT_nopager,
	OPT_avg_total,
	OPT_avg_self,
	OPT_color,
	OPT_disabled,
	OPT_trace,
	OPT_demangle,
	OPT_dbg_domain,
	OPT_report,
	OPT_column_view,
	OPT_column_offset,
	OPT_bind_not,
	OPT_task_newline,
	OPT_chrome_trace,
	OPT_flame_graph,
	OPT_graphviz,
	OPT_sample_time,
	OPT_diff,
	OPT_format,
	OPT_sort_column,
	OPT_tid_filter,
	OPT_num_thread,
	OPT_no_comment,
	OPT_libmcount_single,
	OPT_rt_prio,
	OPT_kernel_bufsize,
	OPT_kernel_skip_out,
	OPT_kernel_full,
	OPT_kernel_only,
	OPT_list_event,
	OPT_run_cmd,
	OPT_opt_file,
	OPT_keep_pid,
	OPT_diff_policy,
	OPT_event_full,
	OPT_record,
	OPT_no_args,
	OPT_libname,
	OPT_match_type,
	OPT_no_randomize_addr,
	OPT_no_event,
	OPT_no_sched,
	OPT_no_sched_preempt,
	OPT_signal,
	OPT_srcline,
	OPT_with_syms,
	OPT_clock,
	OPT_usage,
	OPT_libmcount_path,
	OPT_mermaid,
	OPT_library_path,
	OPT_loc_filter,
};

/* clang-format off */
__used static const char uftrace_usage[] =
" uftrace -- function (graph) tracer for userspace\n"
"\n"
" usage: uftrace [COMMAND] [OPTION...] [<program>]\n"
"\n"
" COMMAND:\n"
"   record          Run a program and saves the trace data\n"
"   replay          Show program execution in the trace data\n"
"   report          Show performance statistics in the trace data\n"
"   live            Do record and replay in a row (default)\n"
"   info            Show system and program info in the trace data\n"
"   dump            Show low-level trace data\n"
"   recv            Save the trace data from network\n"
"   graph           Show function call graph in the trace data\n"
"   script          Run a script for recorded trace data\n"
"   tui             Show text user interface for graph and report\n"
"\n";

__used static const char uftrace_help[] =
" OPTION:\n"
"      --avg-self             Show average/min/max of self function time\n"
"      --avg-total            Show average/min/max of total function time\n"
"  -a, --auto-args            Show arguments and return value of known functions\n"
"  -A, --argument=FUNC@arg[,arg,...]\n"
"                             Show function arguments\n"
"  -b, --buffer=SIZE          Size of tracing buffer (default: "
	stringify(SHMEM_BUFFER_SIZE_KB) "K)\n"
"      --chrome               Dump recorded data in chrome trace format\n"
"      --clock                Set clock source for timestamp (default: mono)\n"
"      --color=SET            Use color for output: yes, no, auto (default: auto)\n"
"      --column-offset=DEPTH  Offset of each column (default: "
	stringify(OPT_COLUMN_OFFSET) ")\n"
"      --column-view          Print tasks in separate columns\n"
"  -C, --caller-filter=FUNC   Only trace callers of those FUNCs\n"
"  -d, --data=DATA            Use this DATA instead of uftrace.data\n"
"      --debug-domain=DOMAIN  Filter debugging domain\n"
"      --demangle=TYPE        C++ symbol demangling: full, simple, no\n"
"                             (default: simple)\n"
"      --diff=DATA            Report differences\n"
"      --diff-policy=POLICY   Control diff report policy\n"
"                             (default: 'abs,compact,no-percent')\n"
"      --disable              Start with tracing disabled (deprecated)\n"
"  -D, --depth=DEPTH          Trace functions within DEPTH\n"
"  -e, --estimate-return      Use only entry record type for safety\n"
"      --event-full           Show all events outside of function\n"
"  -E, --Event=EVENT          Enable EVENT to save more information\n"
"      --flame-graph          Dump recorded data in FlameGraph format\n"
"      --flat                 Use flat output format\n"
"      --force                Trace even if executable is not instrumented\n"
"      --format=FORMAT        Use FORMAT for output: normal, html (default: normal)\n"
"  -f, --output-fields=FIELD  Show FIELDs in the replay or graph output\n"
"  -F, --filter=FUNC          Only trace those FUNCs\n"
"  -g  --agent                Start an agent in mcount to listen to commands\n"
"      --graphviz             Dump recorded data in DOT format\n"
"  -H, --hide=FUNC            Hide FUNCs from trace\n"
"      --host=HOST            Send trace data to HOST instead of write to file\n"
"  -k, --kernel               Trace kernel functions also (if supported)\n"
"      --keep-pid             Keep same pid during execution of traced program\n"
"      --kernel-buffer=SIZE   Size of kernel tracing buffer (default: 1408K)\n"
"      --kernel-full          Show kernel functions outside of user\n"
"      --kernel-only          Dump kernel data only\n"
"      --kernel-skip-out      Skip kernel functions outside of user (deprecated)\n"
"  -K, --kernel-depth=DEPTH   Trace kernel functions within DEPTH\n"
"      --libmcount-single     Use single thread version of libmcount\n"
"      --list-event           List available events\n"
"  -L, --loc-filter=LOCATION  Only trace functions in the source LOCATION\n"
"      --logfile=FILE         Save log messages to this file\n"
"  -l, --nest-libcall         Show nested library calls\n"
"      --libname              Show libname name with symbol name\n"
"      --libmcount-path=PATH  Load libmcount libraries from this PATH\n"
"      --match=TYPE           Support pattern match: regex, glob (default:\n"
"                             regex)\n"
"      --max-stack=DEPTH      Set max stack depth to DEPTH (default: "
	stringify(OPT_RSTACK_MAX) ")\n"
"      --no-args              Do not show arguments and return value\n"
"      --no-comment           Don't show comments of returned functions\n"
"      --no-event             Disable (default) events\n"
"      --no-sched             Disable schedule events\n"
"      --no-sched-preempt     Hide pre-emptive schedule event\n"
"                             but show regular(sleeping) schedule event\n"
"      --no-libcall           Don't trace library function calls\n"
"      --no-merge             Don't merge leaf functions\n"
"      --no-pager             Do not use pager\n"
"      --no-pltbind           Do not bind dynamic symbols (LD_BIND_NOT)\n"
"      --no-randomize-addr    Disable ASLR (Address Space Layout Randomization)\n"
"      --nop                  No operation (for performance test)\n"
"      --num-thread=NUM       Create NUM recorder threads\n"
"  -N, --notrace=FUNC         Don't trace those FUNCs\n"
"      --opt-file=FILE        Read command-line options from FILE\n"
"  -p  --pid=PID              PID of an interactive mcount instance\n"
"      --port=PORT            Use PORT for network connection (default: "
	stringify(UFTRACE_RECV_PORT) ")\n"
"  -P, --patch=FUNC           Apply dynamic patching for FUNCs\n"
"      --record               Record a new trace data before running command\n"
"      --report               Show live report\n"
"      --rt-prio=PRIO         Record with real-time (FIFO) priority\n"
"  -r, --time-range=TIME~TIME Show output within the TIME(timestamp or elapsed time)\n"
"                             range only\n"
"      --run-cmd=CMDLINE      Command line that want to execute after tracing\n"
"                             data received\n"
"  -R, --retval=FUNC@retval   Show function return value\n"
"      --sample-time=TIME     Show flame graph with this sampling time\n"
"      --signal=SIG@act[,act,...]   Trigger action on those SIGnal\n"
"      --sort-column=INDEX    Sort diff report on column INDEX (default: "
	stringify(OPT_SORT_COLUMN) ")\n"
"      --srcline              Enable recording source line info\n"
"      --symbols              Print symbol tables\n"
"  -s, --sort=KEY[,KEY,...]   Sort reported functions by KEYs (default: "
	stringify(OPT_SORT_KEYS) ")\n"
"  -S, --script=SCRIPT        Run a given SCRIPT in function entry and exit\n"
"  -t, --time-filter=TIME     Hide small functions run less than the TIME\n"
"      --task                 Show task info instead\n"
"      --task-newline         Interleave a newline when task is changed\n"
"      --tid=TID[,TID,...]    Only replay those tasks\n"
"      --time                 Print time information\n"
"      --trace=STATE          Set the recording state: on, off (default: on)\n"
"  -T, --trigger=FUNC@act[,act,...]\n"
"                             Trigger action on those FUNCs\n"
"  -U, --unpatch=FUNC         Don't apply dynamic patching for FUNCs\n"
"  -v, --debug                Print debug messages\n"
"      --verbose              Print verbose (debug) messages\n"
"      --with-syms=DIR        Use symbol files in the DIR\n"
"  -W, --watch=POINT          Watch and report POINT if it's changed\n"
"  -Z, --size-filter=SIZE     Apply dynamic patching for functions bigger than SIZE\n"
"  -h, --help                 Give this help list\n"
"      --usage                Give a short usage message\n"
"  -V, --version              Print program version\n"
"\n"
" Try `man uftrace [COMMAND]' for more information.\n"
"\n";

__used static const char uftrace_footer[] =
" Try `uftrace --help' or `man uftrace [COMMAND]' for more information.\n"
"\n";

static const char uftrace_shopts[] =
	"+aA:b:C:d:D:eE:f:F:ghH:kK:lL:N:p:P:r:R:s:S:t:T:U:vVW:Z:";

#define REQ_ARG(name, shopt) { #name, required_argument, 0, shopt }
#define NO_ARG(name, shopt)  { #name, no_argument, 0, shopt }

static const struct option uftrace_options[] = {
	REQ_ARG(libmcount-path, OPT_libmcount_path),
	REQ_ARG(library-path, OPT_libmcount_path),
	REQ_ARG(filter, 'F'),
	REQ_ARG(notrace, 'N'),
	REQ_ARG(depth, 'D'),
	REQ_ARG(time-filter, 't'),
	REQ_ARG(caller-filter, 'C'),
	REQ_ARG(argument, 'A'),
	REQ_ARG(trigger, 'T'),
	REQ_ARG(retval, 'R'),
	NO_ARG(auto-args, 'a'),
	NO_ARG(no-args, OPT_no_args),
	REQ_ARG(patch, 'P'),
	REQ_ARG(unpatch, 'U'),
	REQ_ARG(size-filter, 'Z'),
	NO_ARG(debug, 'v'),
	NO_ARG(verbose, 'v'),
	REQ_ARG(debug-domain, OPT_dbg_domain),
	NO_ARG(force, OPT_force),
	REQ_ARG(data, 'd'),
	NO_ARG(flat, OPT_flat),
	NO_ARG(symbols, OPT_symbols),
	REQ_ARG(buffer, 'b'),
	REQ_ARG(logfile, OPT_logfile),
	NO_ARG(task, OPT_task),
	REQ_ARG(tid, OPT_tid_filter),
	NO_ARG(no-merge, OPT_no_merge),
	NO_ARG(nop, OPT_nop),
	NO_ARG(time, OPT_time),
	REQ_ARG(max-stack, OPT_max_stack),
	REQ_ARG(host, OPT_host),
	REQ_ARG(port, OPT_port),
	NO_ARG(no-pager, OPT_nopager),
	REQ_ARG(sort, 's'),
	NO_ARG(avg-total, OPT_avg_total),
	NO_ARG(avg-self, OPT_avg_self),
	REQ_ARG(color, OPT_color),
	NO_ARG(disable, OPT_disabled),
	REQ_ARG(trace, OPT_trace),
	REQ_ARG(demangle, OPT_demangle),
	NO_ARG(record, OPT_record),
	NO_ARG(report, OPT_report),
	NO_ARG(column-view, OPT_column_view),
	REQ_ARG(column-offset, OPT_column_offset),
	NO_ARG(no-pltbind, OPT_bind_not),
	NO_ARG(task-newline, OPT_task_newline),
	NO_ARG(chrome, OPT_chrome_trace),
	NO_ARG(graphviz, OPT_graphviz),
	NO_ARG(flame-graph, OPT_flame_graph),
	NO_ARG(mermaid, OPT_mermaid),
	REQ_ARG(sample-time, OPT_sample_time),
	REQ_ARG(diff, OPT_diff),
	REQ_ARG(format, OPT_format),
	REQ_ARG(sort-column, OPT_sort_column),
	REQ_ARG(num-thread, OPT_num_thread),
	NO_ARG(no-comment, OPT_no_comment),
	NO_ARG(libmcount-single, OPT_libmcount_single),
	REQ_ARG(rt-prio, OPT_rt_prio),
	NO_ARG(kernel, 'k'),
	REQ_ARG(kernel-depth, 'K'),
	REQ_ARG(kernel-buffer, OPT_kernel_bufsize),
	NO_ARG(kernel-skip-out, OPT_kernel_skip_out),
	NO_ARG(kernel-full, OPT_kernel_full),
	NO_ARG(kernel-only, OPT_kernel_only),
	REQ_ARG(output-fields, 'f'),
	REQ_ARG(time-range, 'r'),
	REQ_ARG(Event, 'E'),
	NO_ARG(no-event, OPT_no_event),
	NO_ARG(no-sched, OPT_no_sched),
	NO_ARG(no-sched-preempt, OPT_no_sched_preempt),
	NO_ARG(list-event, OPT_list_event),
	REQ_ARG(run-cmd, OPT_run_cmd),
	REQ_ARG(opt-file, OPT_opt_file),
	NO_ARG(keep-pid, OPT_keep_pid),
	REQ_ARG(script, 'S'),
	REQ_ARG(diff-policy, OPT_diff_policy),
	NO_ARG(event-full, OPT_event_full),
	NO_ARG(no-libcall, OPT_no_libcall),
	NO_ARG(nest-libcall, 'l'),
	NO_ARG(libname, OPT_libname),
	REQ_ARG(match, OPT_match_type),
	NO_ARG(no-randomize-addr, OPT_no_randomize_addr),
	REQ_ARG(watch, 'W'),
	REQ_ARG(signal, OPT_signal),
	NO_ARG(srcline, OPT_srcline),
	REQ_ARG(hide, 'H'),
	REQ_ARG(loc-filter, OPT_loc_filter),
	REQ_ARG(loc-filter-warning, 'L'), /* the long option is dummy, will change later */
	REQ_ARG(clock, OPT_clock),
	NO_ARG(help, 'h'),
	NO_ARG(usage, OPT_usage),
	NO_ARG(version, 'V'),
	NO_ARG(estimate-return, 'e'),
	REQ_ARG(with-syms, OPT_with_syms),
	NO_ARG(agent, 'g'),
	REQ_ARG(pid, 'p'),
	{ 0 }
};
/* clang-format on */

#undef REQ_ARG
#undef NO_ARG

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

static char *opt_add_string(char *old_opt, char *new_opt)
{
	return strjoin(old_opt, new_opt, ";");
}

static char *opt_add_prefix_string(char *old_opt, char *prefix, char *new_opt)
{
	new_opt = strjoin(xstrdup(prefix), new_opt, "");

	if (old_opt) {
		old_opt = strjoin(old_opt, new_opt, ";");
		free(new_opt);
		new_opt = old_opt;
	}

	return new_opt;
}

static const char *true_str[] = {
	"true", "yes", "on", "y", "1",
};

static const char *false_str[] = {
	"false", "no", "off", "n", "0",
};

static enum color_setting parse_color(char *arg)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(true_str); i++) {
		if (!strcmp(arg, true_str[i]))
			return COLOR_ON;
	}

	for (i = 0; i < ARRAY_SIZE(false_str); i++) {
		if (!strcmp(arg, false_str[i]))
			return COLOR_OFF;
	}

	if (!strcmp(arg, "auto"))
		return COLOR_AUTO;

	return COLOR_UNKNOWN;
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
	struct strv strv = STRV_INIT;
	char *tok, *tmp;
	int i;

	strv_split(&strv, arg, ",");

	strv_for_each(&strv, tok, i) {
		int level = -1;

		tmp = strchr(tok, ':');
		if (tmp) {
			*tmp++ = '\0';
			level = strtol(tmp, NULL, 0);
		}

		if (!strcmp(tok, "ftrace")) /* for backward compatibility */
			dbg_domain[DBG_UFTRACE] = level;
		else if (!strcmp(tok, "uftrace"))
			dbg_domain[DBG_UFTRACE] = level;
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
		else if (!strcmp(tok, "plthook"))
			dbg_domain[DBG_PLTHOOK] = level;
		else if (!strcmp(tok, "dynamic"))
			dbg_domain[DBG_DYNAMIC] = level;
		else if (!strcmp(tok, "event"))
			dbg_domain[DBG_EVENT] = level;
		else if (!strcmp(tok, "script"))
			dbg_domain[DBG_SCRIPT] = level;
		else if (!strcmp(tok, "dwarf"))
			dbg_domain[DBG_DWARF] = level;
		else if (!strcmp(tok, "wrap"))
			dbg_domain[DBG_WRAP] = level;
	}

	dbg_domain_set = true;
	strv_free(&strv);
}

static bool has_time_unit(const char *str)
{
	if (isalpha(str[strlen(str) - 1]))
		return true;
	else
		return false;
}

static uint64_t parse_any_timestamp(char *str, bool *elapsed)
{
	if (*str == '\0')
		return 0;

	if (has_time_unit(str)) {
		*elapsed = true;
		return parse_time(str, 3);
	}

	*elapsed = false;
	return parse_timestamp(str);
}

static bool parse_time_range(struct uftrace_time_range *range, char *arg)
{
	char *str, *pos;

	str = xstrdup(arg);

	pos = strchr(str, '~');
	if (pos == NULL) {
		free(str);
		return false;
	}

	*pos++ = '\0';

	range->start = parse_any_timestamp(str, &range->start_elapsed);
	range->stop = parse_any_timestamp(pos, &range->stop_elapsed);

	free(str);
	return true;
}

static char *remove_trailing_slash(char *path)
{
	size_t len = strlen(path);

	if (path[len - 1] == '/')
		path[len - 1] = '\0';

	return path;
}

static bool is_libmcount_directory(const char *path)
{
	DIR *dp = NULL;
	struct dirent *ent;
	int ret = false;

	dp = opendir(path);
	if (dp == NULL)
		return false;

	while ((ent = readdir(dp)) != NULL) {
		if ((ent->d_type == DT_DIR && !strcmp(ent->d_name, "libmcount")) ||
		    ((ent->d_type == DT_LNK || ent->d_type == DT_REG) &&
		     !strcmp(ent->d_name, "libmcount.so"))) {
			ret = true;
			break;
		}
	}

	closedir(dp);
	return ret;
}

static int parse_option(struct uftrace_opts *opts, int key, char *arg)
{
	char *pos;

	switch (key) {
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
		if (opts->depth <= 0 || opts->depth >= OPT_DEPTH_MAX) {
			pr_use("invalid depth given: %s (ignoring..)\n", arg);
			opts->depth = OPT_DEPTH_DEFAULT;
		}
		break;

	case 'C':
		opts->caller = opt_add_string(opts->caller, arg);
		/*
		 * caller filter focuses onto a given function,
		 * displaying sched event with it is annoying.
		 */
		opts->no_sched = true;
		break;

	case 'H':
		opts->hide = opt_add_string(opts->hide, arg);
		break;

	case 'L':
		if (is_libmcount_directory(arg))
			pr_warn("--libmcount-path option should be used to set libmcount path.\n");
		/* fall through */
	case OPT_loc_filter:
		pos = strstr(arg, "@hide");
		if (!pos)
			opts->loc_filter = opt_add_string(opts->loc_filter, arg);
		else {
			*pos = '\0';
			opts->loc_filter = opt_add_prefix_string(opts->loc_filter, "!", arg);
		}
		/*
		 * location filter focuses onto a given location,
		 * displaying sched event with it is annoying.
		 */
		opts->no_sched = true;
		break;

	case 'v':
		debug++;
		break;

	case 'd':
		opts->dirname = remove_trailing_slash(arg);
		break;

	case 'b':
		opts->bufsize = parse_size(arg);
		if (opts->bufsize & (getpagesize() - 1)) {
			pr_use("buffer size should be multiple of page size\n");
			opts->bufsize = ROUND_UP(opts->bufsize, getpagesize());
		}
		break;

	case 'k':
		opts->kernel = true;
		opts->kernel_depth = 1;
		break;

	case 'K':
		opts->kernel = true;
		opts->kernel_depth = strtol(arg, NULL, 0);
		if (opts->kernel_depth < 1 || opts->kernel_depth > 50) {
			pr_use("invalid kernel depth: %s. Set depth to 1.\n", arg);
			opts->kernel_depth = 1;
		}
		break;

	case 's':
		opts->sort_keys = opt_add_string(opts->sort_keys, arg);
		break;

	case 'S':
		opts->script_file = arg;
		break;

	case 't':
		/* do not override time-filter or time-range if it's already set */
		if (parsing_default_opts) {
			if (opts->threshold || opts->range.start || opts->range.stop)
				break;
		}

		/* add time-filter to uftrace.data/default.opts */
		strv_append(&default_opts, "-t");
		strv_append(&default_opts, arg);

		opts->threshold = parse_time(arg, 3);
		if (opts->threshold >= OPT_THRESHOLD_MAX) {
			pr_use("invalid time given: %lu (ignoring..)\n", opts->threshold);
			opts->threshold = OPT_THRESHOLD_MAX - 1;
		}
		if (opts->range.start || opts->range.stop) {
			pr_use("--time-range cannot be used with --time-filter\n");
			opts->range.start = opts->range.stop = 0;
		}
		break;

	case 'A':
		opts->args = opt_add_string(opts->args, arg);
		break;

	case 'R':
		opts->retval = opt_add_string(opts->retval, arg);
		break;

	case 'a':
		opts->auto_args = true;
		break;

	case 'l':
		/* --nest-libcall implies --force option */
		opts->force = true;
		opts->nest_libcall = true;
		break;

	case 'f':
		opts->fields = arg;
		break;

	case 'r':
		if (!parse_time_range(&opts->range, arg))
			pr_use("invalid time range: %s (ignoring...)\n", arg);
		if (opts->threshold) {
			pr_use("--time-filter cannot be used with --time-range\n");
			opts->threshold = 0;
		}
		break;

	case 'P':
		opts->patch = opt_add_string(opts->patch, arg);
		break;

	case 'U':
		opts->patch = opt_add_prefix_string(opts->patch, "!", arg);
		break;

	case 'Z':
		opts->size_filter = strtol(arg, NULL, 0);
		if (opts->size_filter <= 0) {
			pr_use("--size-filter should be positive\n");
			opts->size_filter = 0;
		}
		break;

	case 'E':
		if (!strcmp(arg, "list")) {
			pr_use("'-E list' is deprecated, use --list-event instead.\n");
			opts->list_event = true;
		}
		else
			opts->event = opt_add_string(opts->event, arg);
		break;

	case 'W':
		opts->watch = opt_add_string(opts->watch, arg);
		break;

	case 'e':
		opts->estimate_return = true;
		break;

	case 'V':
		pr_out("%s\n", uftrace_version);
		return -1;

	case 'g':
		opts->agent = true;
		break;

	case 'h':
		return -3;

	case 'p':
		opts->pid = strtol(arg, NULL, 0);
		opts->exename = "";
		break;

	case OPT_libmcount_path:
		opts->lib_path = arg;
		break;

	case OPT_usage:
		return -2;

	case OPT_flat:
		opts->flat = true;
		break;

	case OPT_no_libcall:
		opts->libcall = false;
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

	case OPT_task:
		opts->show_task = true;
		break;

	case OPT_tid_filter:
		if (strtol(arg, NULL, 0) <= 0)
			pr_use("invalid thread id: %s\n", arg);
		else
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
		if (opts->max_stack <= 0 || opts->max_stack > OPT_RSTACK_MAX) {
			pr_use("max stack depth should be >0 and <%d\n", OPT_RSTACK_MAX);
			opts->max_stack = OPT_RSTACK_DEFAULT;
		}
		break;

	case OPT_host:
		opts->host = arg;
		break;

	case OPT_port:
		opts->port = strtol(arg, NULL, 0);
		if (opts->port <= 0) {
			pr_use("invalid port number: %s (ignoring..)\n", arg);
			opts->port = UFTRACE_RECV_PORT;
		}
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
		if (opts->color == COLOR_UNKNOWN) {
			pr_use("unknown color setting: %s (ignoring..)\n", arg);
			opts->color = COLOR_AUTO;
		}
		break;

	case OPT_disabled:
		pr_use("'--disable' is deprecated, use --trace=off instead.\n");
		opts->trace = TRACE_STATE_OFF;
		break;

	case OPT_trace:
		if (!strcmp(arg, "on"))
			opts->trace = TRACE_STATE_ON;
		else if (!strcmp(arg, "off"))
			opts->trace = TRACE_STATE_OFF;
		else
			pr_use("unknown tracing state: %s (ignoring..)\n", arg);
		break;

	case OPT_demangle:
		demangler = parse_demangle(arg);
		if (demangler == DEMANGLE_ERROR) {
			pr_use("unknown demangle value: %s (ignoring..)\n", arg);
			demangler = DEMANGLE_SIMPLE;
		}
		else if (demangler == DEMANGLE_NOT_SUPPORTED) {
			pr_use("'%s' demangler is not supported\n", arg);
			demangler = DEMANGLE_SIMPLE;
		}
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
		if (opts->column_offset < 0)
			opts->column_offset = OPT_COLUMN_OFFSET;
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

	case OPT_flame_graph:
		opts->flame_graph = true;
		break;

	case OPT_graphviz:
		opts->graphviz = true;
		break;

	case OPT_diff:
		opts->diff = arg;
		break;

	case OPT_diff_policy:
		opts->diff_policy = arg;
		break;

	case OPT_format:
		if (!strcmp(arg, "normal"))
			format_mode = FORMAT_NORMAL;
		else if (!strcmp(arg, "html")) {
			format_mode = FORMAT_HTML;
			if (opts->color == COLOR_AUTO)
				opts->color = COLOR_ON;
		}
		else {
			pr_use("invalid format argument: %s\n", arg);
			format_mode = FORMAT_NORMAL;
		}
		break;

	case OPT_sort_column:
		opts->sort_column = strtol(arg, NULL, 0);
		if (opts->sort_column < 0 || opts->sort_column > OPT_SORT_COLUMN) {
			pr_use("invalid column number: %d\n", opts->sort_column);
			pr_use("force to set it to --sort-column=%d for diff percentage\n",
			       OPT_SORT_COLUMN);
			opts->sort_column = OPT_SORT_COLUMN;
		}
		break;

	case OPT_num_thread:
		opts->nr_thread = strtol(arg, NULL, 0);
		if (opts->nr_thread < 0) {
			pr_use("invalid thread number: %s\n", arg);
			opts->nr_thread = 0;
		}
		break;

	case OPT_no_comment:
		opts->comment = false;
		break;

	case OPT_libmcount_single:
		opts->libmcount_single = true;
		break;

	case OPT_rt_prio:
		opts->rt_prio = strtol(arg, NULL, 0);
		if (opts->rt_prio < 1 || opts->rt_prio > 99) {
			pr_use("invalid rt prioity: %d (ignoring...)\n", opts->rt_prio);
			opts->rt_prio = 0;
		}
		break;

	case OPT_kernel_bufsize:
		opts->kernel_bufsize = parse_size(arg);
		if (opts->kernel_bufsize & (getpagesize() - 1)) {
			pr_use("buffer size should be multiple of page size\n");
			opts->kernel_bufsize = ROUND_UP(opts->kernel_bufsize, getpagesize());
		}
		break;

	case OPT_kernel_skip_out: /* deprecated */
		opts->kernel_skip_out = true;
		break;

	case OPT_kernel_full:
		opts->kernel_skip_out = false;
		/* see setup_kernel_tracing() also */
		break;

	case OPT_kernel_only:
		opts->kernel_only = true;
		break;

	case OPT_sample_time:
		opts->sample_time = parse_time(arg, 9);
		break;

	case OPT_list_event:
		opts->list_event = true;
		break;

	case OPT_run_cmd:
		if (opts->run_cmd) {
			pr_warn("intermediate --run-cmd argument is ignored.\n");
			free_parsed_cmdline(opts->run_cmd);
		}
		opts->run_cmd = parse_cmdline(arg, NULL);
		break;

	case OPT_opt_file:
		opts->opt_file = arg;
		break;

	case OPT_keep_pid:
		opts->keep_pid = true;
		break;

	case OPT_event_full:
		opts->event_skip_out = false;
		break;

	case OPT_record:
		opts->record = true;
		break;

	case OPT_no_args:
		opts->show_args = false;
		break;

	case OPT_libname:
		opts->libname = true;
		break;

	case OPT_match_type:
		opts->patt_type = parse_filter_pattern(arg);
		if (opts->patt_type == PATT_NONE) {
			pr_use("invalid match pattern: %s (ignoring...)\n", arg);
			opts->patt_type = PATT_REGEX;
		}
		break;

	case OPT_no_randomize_addr:
		opts->no_randomize_addr = true;
		break;

	case OPT_no_event:
		opts->no_event = true;
		break;

	case OPT_no_sched:
		opts->no_sched = true;
		break;

	case OPT_no_sched_preempt:
		opts->no_sched_preempt = true;
		break;

	case OPT_signal:
		opts->sig_trigger = opt_add_string(opts->sig_trigger, arg);
		break;

	case OPT_srcline:
		opts->srcline = true;
		break;

	case OPT_with_syms:
		opts->with_syms = arg;
		break;

	case OPT_clock:
		if (strcmp(arg, "mono") && strcmp(arg, "mono_raw") && strcmp(arg, "boot")) {
			pr_use("invalid clock source: '%s' "
			       "(force to use 'mono')\n",
			       arg);
			arg = "mono";
		}
		opts->clock = arg;
		break;

	case OPT_mermaid:
		opts->mermaid = true;
		break;

	default:
		return -1;
	}
	return 0;
}

static void update_subcmd(struct uftrace_opts *opts, char *cmd)
{
	if (!strcmp(cmd, "record"))
		opts->mode = UFTRACE_MODE_RECORD;
	else if (!strcmp(cmd, "replay"))
		opts->mode = UFTRACE_MODE_REPLAY;
	else if (!strcmp(cmd, "report"))
		opts->mode = UFTRACE_MODE_REPORT;
	else if (!strcmp(cmd, "live"))
		opts->mode = UFTRACE_MODE_LIVE;
	else if (!strcmp(cmd, "graph"))
		opts->mode = UFTRACE_MODE_GRAPH;
	else if (!strcmp(cmd, "info"))
		opts->mode = UFTRACE_MODE_INFO;
	else if (!strcmp(cmd, "dump"))
		opts->mode = UFTRACE_MODE_DUMP;
	else if (!strcmp(cmd, "recv"))
		opts->mode = UFTRACE_MODE_RECV;
	else if (!strcmp(cmd, "script"))
		opts->mode = UFTRACE_MODE_SCRIPT;
	else if (!strcmp(cmd, "tui"))
		opts->mode = UFTRACE_MODE_TUI;
	else
		opts->mode = UFTRACE_MODE_INVALID;
}

static void parse_opt_file(int *argc, char ***argv, char *filename, struct uftrace_opts *opts)
{
	int file_argc;
	char **file_argv;
	char *buf;
	struct stat stbuf;
	FILE *fp;
	char *orig_exename = opts->exename;
	bool has_subcmd = false;

	if (stat(filename, &stbuf) < 0) {
		pr_use("Cannot use opt-file: %s: %m\n", filename);
		exit(0);
	}

	/* prepend dummy string since getopt_long cannot process argv[0] */
	buf = xmalloc(stbuf.st_size + 9);
	strncpy(buf, "uftrace ", 9);

	fp = fopen(filename, "r");
	if (fp == NULL)
		pr_err("Open failed: %s", filename);
	fread_all(buf + 8, stbuf.st_size, fp);
	fclose(fp);
	buf[stbuf.st_size + 8] = '\0';

	file_argv = parse_cmdline(buf, &file_argc);

	/* clear opt_file for error reporting */
	opts->opt_file = NULL;

	/* re-initialize getopt as we start another round */
	optind = 0;

	if (file_argv[1][0] != '-') {
		int orig_mode = opts->mode;

		update_subcmd(opts, file_argv[1]);

		if (opts->mode == UFTRACE_MODE_INVALID) {
			opts->mode = orig_mode;
			has_subcmd = true;
		}
		else {
			if (orig_mode != UFTRACE_MODE_INVALID && orig_mode != opts->mode) {
				pr_use("ignore uftrace command in opt-file\n");
				opts->mode = orig_mode;
			}
			else {
				has_subcmd = true;
			}
		}
	}

	while (true) {
		int key, tmp = 0;

		key = getopt_long(file_argc, file_argv, uftrace_shopts, uftrace_options, &tmp);
		if (key == -1 || key == '?') {
			if (has_subcmd && optind == 1)
				optind++;
			else
				break;
		}

		parse_option(opts, key, optarg);
	}

	/* overwrite argv only if it's not given on command line */
	if (orig_exename == NULL && optind < file_argc) {
		*argc = file_argc;
		*argv = file_argv;

		opts->idx = optind;
		opts->exename = file_argv[optind];

		/* mark it to free at the end */
		opts->opt_file = filename;
	}
	else {
		opts->exename = orig_exename;
		free_parsed_cmdline(file_argv);
	}

	free(buf);
}

/*
 * Parse options in a script file header.  For example,
 *
 *   # uftrace-option: -F main -A malloc@arg1
 *   def uftrace_entry():
 *     pass
 *   ...
 *
 * Note that it only handles some options like filter, trigger,
 * argument, return values and maybe some more.
 */
void parse_script_opt(struct uftrace_opts *opts)
{
	FILE *fp;
	int opt_argc;
	char **opt_argv;
	char *line = NULL;
	size_t len = 0;
	static const char optname[] = "uftrace-option";
	enum script_type_t script_type;
	const char *comments[SCRIPT_TYPE_COUNT] = { "", "#", "--" };
	const char *comment;
	size_t comment_len;

	if (opts->script_file == NULL)
		return;

	fp = fopen(opts->script_file, "r");
	if (fp == NULL)
		pr_err("cannot open script file: %s", opts->script_file);

	script_type = get_script_type(opts->script_file);

	if (script_type == SCRIPT_UNKNOWN) {
		fclose(fp);
		pr_err("unknown script type");
	}

	comment = comments[script_type];
	comment_len = strlen(comment);

	while (getline(&line, &len, fp) > 0) {
		char *pos;

		if (strncmp(line, comment, comment_len))
			continue;

		pos = line + comment_len;
		while (isspace(*pos))
			pos++;

		if (strncmp(pos, optname, strlen(optname)))
			continue;

		/* extract option value */
		pos = strchr(line, ':');
		if (pos == NULL)
			break;

		pr_dbg("adding record option from script: %s", pos + 1);

		/* include ':' so that it can start with optind 1 */
		opt_argv = parse_cmdline(pos, &opt_argc);

		/* re-initialize getopt as we start another round */
		optind = 0;

		while (true) {
			int key, tmp = 0;

			key = getopt_long(opt_argc, opt_argv, uftrace_shopts, uftrace_options,
					  &tmp);
			if (key == -1 || key == '?')
				break;

			parse_option(opts, key, optarg);
		}

		free_parsed_cmdline(opt_argv);
		break;
	}

	free(line);
	fclose(fp);
}

static void free_opts(struct uftrace_opts *opts)
{
	free(opts->filter);
	free(opts->trigger);
	free(opts->sig_trigger);
	free(opts->sort_keys);
	free(opts->args);
	free(opts->retval);
	free(opts->tid);
	free(opts->event);
	free(opts->patch);
	free(opts->caller);
	free(opts->watch);
	free(opts->hide);
	free(opts->loc_filter);
	free_parsed_cmdline(opts->run_cmd);
}

static int parse_options(int argc, char **argv, struct uftrace_opts *opts)
{
	/* initial option parsing index */
	optind = 1;

	while (true) {
		int key, tmp = 0;

		key = getopt_long(argc, argv, uftrace_shopts, uftrace_options, &tmp);
		if (key == -1 || key == '?') {
			if (optind < argc && opts->mode == UFTRACE_MODE_INVALID) {
				update_subcmd(opts, argv[optind]);

				if (opts->mode != UFTRACE_MODE_INVALID) {
					optind++;
					continue;
				}
			}
			break;
		}

		tmp = parse_option(opts, key, optarg);
		if (tmp < 0)
			return tmp;
	}

	if (optind < argc) {
		opts->idx = optind;
		opts->exename = argv[optind];
	}

	return 0;
}

__used static void apply_default_opts(int *argc, char ***argv, struct uftrace_opts *opts)
{
	char *basename = "default.opts";
	char opts_file[PATH_MAX];
	struct stat stbuf;

	/* default.opts is only for analysis commands */
	if (opts->mode == UFTRACE_MODE_RECORD || opts->mode == UFTRACE_MODE_LIVE ||
	    opts->mode == UFTRACE_MODE_RECV)
		return;

	/* this is not to override user given time-filter by default opts */
	parsing_default_opts = true;

	snprintf(opts_file, PATH_MAX, "%s/%s", opts->dirname, basename);
	if (!stat(opts_file, &stbuf) && stbuf.st_size > 0) {
		pr_dbg("apply '%s' option file\n", opts_file);
		parse_opt_file(argc, argv, opts_file, opts);
	}
	else if (!strcmp(opts->dirname, UFTRACE_DIR_NAME) && !access("./info", F_OK)) {
		/* try again applying default.opts in the current dir */
		if (!stat(basename, &stbuf) && stbuf.st_size > 0) {
			pr_dbg("apply './%s' option file\n", basename);
			parse_opt_file(argc, argv, basename, opts);
		}
	}
}

__used static void show_man_page(char *cmd)
{
	char *cmdstr = NULL;

	if (cmd)
		xasprintf(&cmdstr, "uftrace-%s", cmd);
	else
		cmdstr = xstrdup("uftrace");
	execlp("man", "man", cmdstr, (char *)NULL);
	/* fall through if man command itself is not found */
	free(cmdstr);
}

#ifndef UNIT_TEST
int main(int argc, char *argv[])
{
	struct uftrace_opts opts = {
		.mode = UFTRACE_MODE_INVALID,
		.dirname = UFTRACE_DIR_NAME,
		.libcall = true,
		.bufsize = SHMEM_BUFFER_SIZE,
		.max_stack = OPT_RSTACK_DEFAULT,
		.port = UFTRACE_RECV_PORT,
		.use_pager = true,
		.color = COLOR_AUTO, /* turn on if terminal */
		.column_offset = OPT_COLUMN_OFFSET,
		.comment = true,
		.kernel_skip_out = true,
		.fields = NULL,
		.sort_column = OPT_SORT_COLUMN,
		.event_skip_out = true,
		.patt_type = PATT_REGEX,
		.show_args = true,
		.clock = "mono",
	};
	int ret = -1;
	char *pager = NULL;

	/* this must be done before calling pr_*() */
	logfp = stderr;
	outfp = stdout;

	if (argc == 1) {
		pr_out(uftrace_usage);
		pr_out(uftrace_footer);
		return 0;
	}

	switch (parse_options(argc, argv, &opts)) {
	case -1:
		ret = 0;
		goto cleanup;
	case -2:
		pr_out(uftrace_usage);
		pr_out(uftrace_footer);
		ret = 0;
		goto cleanup;
	case -3:
		if (opts.mode)
			show_man_page(argv[1]);
		if (opts.use_pager)
			start_pager(setup_pager());
		pr_out(uftrace_usage);
		pr_out(uftrace_help);
		wait_for_pager();
		ret = 0;
		goto cleanup;
	}

	if (opts.opt_file)
		parse_opt_file(&argc, &argv, opts.opt_file, &opts);

	if (opts.exename == NULL && !opts.list_event) {
		switch (opts.mode) {
		case UFTRACE_MODE_RECORD:
		case UFTRACE_MODE_LIVE:
		case UFTRACE_MODE_INVALID:
			pr_out(uftrace_usage);
			pr_out(uftrace_footer);
			ret = 1;
			goto cleanup;
		}
	}

	if (opts.mode == UFTRACE_MODE_INVALID)
		opts.mode = UFTRACE_MODE_DEFAULT;

	if (dbg_domain_set && !debug)
		debug = 1;

	if (opts.logfile) {
		logfp = fopen(opts.logfile, "a");
		if (logfp == NULL) {
			logfp = stderr;
			pr_err("cannot open log file");
		}

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

	pr_dbg("running %s\n", uftrace_version);

	opts.range.kernel_skip_out = opts.kernel_skip_out;
	opts.range.event_skip_out = opts.event_skip_out;

	if (opts.mode == UFTRACE_MODE_RECORD || opts.mode == UFTRACE_MODE_RECV ||
	    opts.mode == UFTRACE_MODE_TUI)
		opts.use_pager = false;
	if (opts.nop)
		opts.use_pager = false;

	if (opts.use_pager)
		pager = setup_pager();

	if (!opts.pid) { /* Keep uninitialized values in client mode */
		if (!opts.depth)
			opts.depth = OPT_DEPTH_DEFAULT;
	}

	setup_color(opts.color, pager);
	setup_signal();

	/* 'live' will start pager at its replay time */
	if (opts.use_pager && opts.mode != UFTRACE_MODE_LIVE)
		start_pager(pager);

	/* the srcline info is used for TUI status line by default */
	if (opts.mode == UFTRACE_MODE_TUI)
		opts.srcline = true;

	if (!opts.pid) { /* Keep uninitialized values in client mode */
		if (opts.trace == TRACE_STATE_NONE)
			opts.trace = TRACE_STATE_ON;
	}

	/* apply 'default.opts' options for analysis commands */
	apply_default_opts(&argc, &argv, &opts);

	if (opts.idx == 0)
		opts.idx = argc;

	argc -= opts.idx;
	argv += opts.idx;

	if (!opts.libcall && opts.nest_libcall)
		pr_err_ns("cannot use --no-libcall and --nest-libcall options together\n");

	switch (opts.mode) {
	case UFTRACE_MODE_RECORD:
		ret = command_record(argc, argv, &opts);
		break;
	case UFTRACE_MODE_REPLAY:
		ret = command_replay(argc, argv, &opts);
		break;
	case UFTRACE_MODE_LIVE:
		ret = command_live(argc, argv, &opts);
		break;
	case UFTRACE_MODE_REPORT:
		ret = command_report(argc, argv, &opts);
		break;
	case UFTRACE_MODE_INFO:
		ret = command_info(argc, argv, &opts);
		break;
	case UFTRACE_MODE_RECV:
		ret = command_recv(argc, argv, &opts);
		break;
	case UFTRACE_MODE_DUMP:
		ret = command_dump(argc, argv, &opts);
		break;
	case UFTRACE_MODE_GRAPH:
		ret = command_graph(argc, argv, &opts);
		break;
	case UFTRACE_MODE_SCRIPT:
		ret = command_script(argc, argv, &opts);
		break;
	case UFTRACE_MODE_TUI:
		ret = command_tui(argc, argv, &opts);
		break;
	case UFTRACE_MODE_INVALID:
		ret = 1;
		break;
	}

	wait_for_pager();

cleanup:
	if (opts.logfile)
		fclose(logfp);

	if (opts.opt_file)
		free_parsed_cmdline(argv - opts.idx);

	free_opts(&opts);
	return ret;
}
#else

#define OPT_FILE "opt"

TEST_CASE(option_parsing1)
{
	char *stropt = NULL;
	int i;
	bool elapsed_time;

	pr_dbg("check parsing size suffix\n");
	TEST_EQ(parse_size("1234"), 1234);
	TEST_EQ(parse_size("10k"), 10240);
	TEST_EQ(parse_size("100M"), 100 * 1024 * 1024);

	pr_dbg("check string list addition\n");
	stropt = opt_add_string(stropt, "abc");
	TEST_STREQ(stropt, "abc");
	stropt = opt_add_string(stropt, "def");
	TEST_STREQ(stropt, "abc;def");

	free(stropt);
	stropt = NULL;

	pr_dbg("check string list addition with prefix\n");
	stropt = opt_add_prefix_string(stropt, "!", "abc");
	TEST_STREQ(stropt, "!abc");
	stropt = opt_add_prefix_string(stropt, "?", "def");
	TEST_STREQ(stropt, "!abc;?def");

	free(stropt);
	stropt = NULL;

	pr_dbg("check parsing colors\n");
	TEST_EQ(parse_color("1"), COLOR_ON);
	TEST_EQ(parse_color("true"), COLOR_ON);
	TEST_EQ(parse_color("off"), COLOR_OFF);
	TEST_EQ(parse_color("n"), COLOR_OFF);
	TEST_EQ(parse_color("auto"), COLOR_AUTO);
	TEST_EQ(parse_color("ok"), COLOR_UNKNOWN);

	pr_dbg("check parsing demanglers\n");
	TEST_EQ(parse_demangle("simple"), DEMANGLE_SIMPLE);
	TEST_EQ(parse_demangle("no"), DEMANGLE_NONE);
	TEST_EQ(parse_demangle("0"), DEMANGLE_NONE);
	/* full demangling might not supported */
	TEST_NE(parse_demangle("full"), DEMANGLE_SIMPLE);

	for (i = 0; i < DBG_DOMAIN_MAX; i++)
		dbg_domain[i] = 0;

	pr_dbg("check parsing debug domains\n");
	parse_debug_domain("mcount:1,uftrace:2,symbol:3");
	TEST_EQ(dbg_domain[DBG_UFTRACE], 2);
	TEST_EQ(dbg_domain[DBG_MCOUNT], 1);
	TEST_EQ(dbg_domain[DBG_SYMBOL], 3);

	TEST_EQ(parse_any_timestamp("1ns", &elapsed_time), 1ULL);
	TEST_EQ(parse_any_timestamp("2us", &elapsed_time), 2000ULL);
	TEST_EQ(parse_any_timestamp("3ms", &elapsed_time), 3000000ULL);
	TEST_EQ(parse_any_timestamp("4s", &elapsed_time), 4000000000ULL);
	TEST_EQ(parse_any_timestamp("5m", &elapsed_time), 300000000000ULL);

	return TEST_OK;
}

TEST_CASE(option_parsing2)
{
	struct uftrace_opts opts = {
		.mode = UFTRACE_MODE_INVALID,
	};
	char *argv[] = {
		"uftrace", "replay", "-v",  "--data=abc.data", "--kernel", "-t", "1us", "-F",
		"foo",	   "-N",     "bar", "-Abaz@kernel",
	};
	int argc = ARRAY_SIZE(argv);
	int saved_debug = debug;

	pr_dbg("check parsing regular command line options\n");
	parse_options(argc, argv, &opts);

	TEST_EQ(opts.mode, UFTRACE_MODE_REPLAY);
	TEST_EQ(debug, saved_debug + 1);
	TEST_EQ(opts.kernel, 1);
	TEST_EQ(opts.threshold, (uint64_t)1000);
	TEST_STREQ(opts.dirname, "abc.data");
	TEST_STREQ(opts.filter, "foo;!bar");
	TEST_STREQ(opts.args, "baz@kernel");

	free_opts(&opts);
	return TEST_OK;
}

TEST_CASE(option_parsing3)
{
	struct uftrace_opts opts = {
		.mode = UFTRACE_MODE_INVALID,
	};
	char *argv[] = {
		"uftrace",
		"-v",
		"--opt-file",
		OPT_FILE,
	};
	int argc = ARRAY_SIZE(argv);
	char opt_file[] = "-K 2\n"
			  "-b4m\n"
			  "--column-view\n"
			  "--depth=3\n"
			  "t-abc";
	int file_argc;
	char **file_argv;
	FILE *fp;
	int saved_debug = debug;

	/* create opt-file */
	fp = fopen(OPT_FILE, "w");
	TEST_NE(fp, NULL);
	fwrite(opt_file, strlen(opt_file), 1, fp);
	fclose(fp);

	pr_dbg("check parsing regular command line options\n");
	parse_options(argc, argv, &opts);
	TEST_STREQ(opts.opt_file, OPT_FILE);

	pr_dbg("check parsing option files\n");
	parse_opt_file(&file_argc, &file_argv, opts.opt_file, &opts);
	TEST_EQ(file_argc, 7); // +1 for dummy prefix

	unlink(OPT_FILE);

	TEST_EQ(opts.mode, UFTRACE_MODE_INVALID);
	TEST_EQ(debug, saved_debug + 1);
	TEST_EQ(opts.kernel, 1);
	TEST_EQ(opts.kernel_depth, 2);
	TEST_EQ(opts.depth, 3);
	TEST_EQ(opts.bufsize, 4 * 1024 * 1024);
	TEST_EQ(opts.column_view, 1);
	TEST_STREQ(opts.exename, "t-abc");

	free_parsed_cmdline(file_argv);
	free_opts(&opts);
	return TEST_OK;
}

TEST_CASE(option_parsing4)
{
	struct uftrace_opts opts = {
		.mode = UFTRACE_MODE_INVALID,
	};
	char *argv[] = {
		"uftrace",
		"-v",
		"--opt-file",
		OPT_FILE,
	};
	int argc = ARRAY_SIZE(argv);
	char opt_file[] = "-K 2\n"
			  "# buffer size: 4 MB\n"
			  "-b4m\n"
			  "\n"
			  "## show different thread with different indentation\n"
			  "--column-view\n"
			  "\n"
			  "# limit maximum function call depth to 3\n"
			  "--depth=3 # same as -D3 \n"
			  "\n"
			  "\n"
			  "#test program\n"
			  "t-abc\n"
			  "\n";
	int file_argc;
	char **file_argv;
	FILE *fp;
	int saved_debug = debug;

	/* create opt-file */
	fp = fopen(OPT_FILE, "w");
	TEST_NE(fp, NULL);
	fwrite(opt_file, strlen(opt_file), 1, fp);
	fclose(fp);

	pr_dbg("check parsing regular command line options\n");
	parse_options(argc, argv, &opts);
	TEST_STREQ(opts.opt_file, OPT_FILE);

	pr_dbg("check parsing option files\n");
	parse_opt_file(&file_argc, &file_argv, opts.opt_file, &opts);
	TEST_EQ(file_argc, 7); // +1 for dummy prefix

	unlink(OPT_FILE);

	pr_dbg("command mode should remain as is\n");
	TEST_EQ(opts.mode, UFTRACE_MODE_INVALID);
	TEST_EQ(debug, saved_debug + 1);
	TEST_EQ(opts.kernel, 1);
	TEST_EQ(opts.kernel_depth, 2);
	TEST_EQ(opts.depth, 3);
	TEST_EQ(opts.bufsize, 4 * 1024 * 1024);
	TEST_EQ(opts.column_view, 1);
	TEST_STREQ(opts.exename, "t-abc");

	free_parsed_cmdline(file_argv);
	free_opts(&opts);
	return TEST_OK;
}

TEST_CASE(option_parsing5)
{
	struct uftrace_opts opts = {
		.mode = UFTRACE_MODE_INVALID,
	};
	char *argv[] = { "uftrace", "-v", "--opt-file", OPT_FILE, "hello" };
	int argc = ARRAY_SIZE(argv);
	char opt_file[] = "record\n"
			  "-F main\n"
			  "--time-filter 1us\n"
			  "--depth=3\n"
			  "t-abc";
	int file_argc = argc;
	char **file_argv = argv;
	FILE *fp;
	int saved_debug = debug;

	/* create opt-file */
	fp = fopen(OPT_FILE, "w");
	TEST_NE(fp, NULL);
	fwrite(opt_file, strlen(opt_file), 1, fp);
	fclose(fp);

	pr_dbg("check parsing regular command line options\n");
	parse_options(argc, argv, &opts);
	TEST_STREQ(opts.opt_file, OPT_FILE);

	pr_dbg("check parsing option files\n");
	parse_opt_file(&file_argc, &file_argv, opts.opt_file, &opts);

	unlink(OPT_FILE);

	pr_dbg("opt file should update command mode\n");
	TEST_EQ(opts.mode, UFTRACE_MODE_RECORD);
	TEST_EQ(debug, saved_debug + 1);
	/* preserve original arg[cv] if command line is given */
	TEST_EQ(file_argc, argc);
	TEST_EQ(file_argv, (char **)argv);
	TEST_EQ(opts.threshold, (uint64_t)1000);
	TEST_EQ(opts.depth, 3);
	TEST_EQ(opts.idx, 4);
	TEST_STREQ(opts.filter, "main");
	/* it should not update exename to "t-abc" */
	TEST_STREQ(opts.exename, "hello");

	free_opts(&opts);
	return TEST_OK;
}

#endif /* UNIT_TEST */
