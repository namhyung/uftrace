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
#include <errno.h>
#include <argp.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "ftrace"

#include "ftrace.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"
#include "utils/list.h"

const char *argp_program_version = "ftrace v0.4";
const char *argp_program_bug_address = "http://mod.lge.com/hub/otc/ftrace/issues";

#define OPT_flat 	301
#define OPT_plthook 	302
#define OPT_symbols	303
#define OPT_logfile	304
#define OPT_force	305
#define OPT_threads	306
#define OPT_no_merge	307
#define OPT_nop		308
#define OPT_time	309
#define OPT_max_stack	310


static struct argp_option ftrace_options[] = {
	{ "library-path", 'L', "PATH", 0, "Load libraries from this PATH" },
	{ "filter", 'F', "FUNC[,FUNC,...]", 0, "Only trace those FUNCs" },
	{ "notrace", 'N', "FUNC[,FUNC,...]", 0, "Don't trace those FUNCs" },
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
	{ "tid", 'T', "TID[,TID,...]", 0, "Only replay those tasks" },
	{ "no-merge", OPT_no_merge, 0, 0, "Don't merge leaf functions" },
	{ "nop", OPT_nop, 0, 0, "No operation (for performance test)" },
	{ "time", OPT_time, 0, 0, "Print time information" },
	{ "max-stack", OPT_max_stack, "DEPTH", 0, "Set max stack depth to DEPTH" },
	{ "kernel", 'k', 0, 0, "Trace kernel functions also (if supported)" },
	{ "kernel-full", 'K', 0, 0, "Trace kernel functions in detail (if supported)" },
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
		fprintf(stderr, "invalid size unit: %s\n", unit);
		break;
	}

	return size;
}

static error_t parse_option(int key, char *arg, struct argp_state *state)
{
	struct opts *opts = state->input;

	switch (key) {
	case 'L':
		opts->lib_path = arg;
		break;

	case 'F':
		opts->filter = arg;
		break;

	case 'N':
		opts->notrace = arg;
		break;

	case 'D':
		opts->depth = strtol(arg, NULL, 0);
		if (opts->depth <= 0)
			pr_err_ns("invalid depth given: %s\n", arg);
		break;

	case 'T':
		opts->tid = arg;
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
			pr_err_ns("buffer size should be multiple of page size");
		break;

	case 'k':
		opts->kernel = 1;
		break;

	case 'K':
		opts->kernel = 2;
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
			pr_err_ns("max stack depth should be >0 and <%d\n",
				  MCOUNT_RSTACK_MAX);
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

static int command_info(int argc, char *argv[], struct opts *opts);
static int command_dump(int argc, char *argv[], struct opts *opts);

int main(int argc, char *argv[])
{
	struct opts opts = {
		.mode		= FTRACE_MODE_INVALID,
		.dirname	= FTRACE_DIR_NAME,
		.want_plthook	= true,
		.bsize		= SHMEM_BUFFER_SIZE,
		.depth		= MCOUNT_DEFAULT_DEPTH,
		.max_stack	= MCOUNT_RSTACK_MAX,
	};
	struct argp argp = {
		.options = ftrace_options,
		.parser = parse_option,
		.args_doc = "[record|replay|live|report|info|dump] [<command> args...]",
		.doc = "ftrace -- a function tracer",
	};

	argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &opts);

	if (opts.logfile) {
		logfd = open(opts.logfile, O_WRONLY | O_CREAT, 0644);
		if (logfd < 0)
			pr_err("cannot open log file");
	}

	if (opts.print_symtab) {
		struct symtabs symtabs = {
			.loaded = false,
		};

		if (opts.exename == NULL) {
			struct ftrace_file_handle handle;

			if (open_data_file(&opts, &handle) < 0)
				exit(1);
		}

		load_symtabs(&symtabs, opts.exename);
		print_symtabs(&symtabs);
		unload_symtabs(&symtabs);
		exit(0);
	}

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
	case FTRACE_MODE_DUMP:
		command_dump(argc, argv, &opts);
		break;
	case FTRACE_MODE_INVALID:
		break;
	}

	if (opts.logfile)
		close(logfd);

	return 0;
}

static int command_info(int argc, char *argv[], struct opts *opts)
{
	int ret;
	char buf[PATH_MAX];
	struct stat statbuf;
	struct ftrace_file_handle handle;
	const char *fmt = "# %-20s: %s\n";

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);

	if (stat(buf, &statbuf) < 0)
		return -1;

	printf("# ftrace information\n");
	printf("# ==================\n");
	printf(fmt, "program version", argp_program_version);
	printf("# %-20s: %s", "recorded on", ctime(&statbuf.st_mtime));

	if (handle.hdr.info_mask & (1UL << CMDLINE))
		printf(fmt, "cmdline", handle.info.cmdline);

	if (handle.hdr.info_mask & (1UL << EXE_NAME))
		printf(fmt, "exe image", handle.info.exename);

	if (handle.hdr.info_mask & (1UL << EXE_BUILD_ID)) {
		int i;
		printf("# %-20s: ", "build id");
		for (i = 0; i < 20; i++)
			printf("%02x", handle.info.build_id[i]);
		printf("\n");
	}

	if (handle.hdr.info_mask & (1UL << EXIT_STATUS)) {
		int status = handle.info.exit_status;

		if (WIFEXITED(status)) {
			snprintf(buf, sizeof(buf), "exited with code: %d",
				 WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			snprintf(buf, sizeof(buf), "terminated by signal: %d",
				 WTERMSIG(status));
		} else {
			snprintf(buf, sizeof(buf), "unknown exit status: %d",
				 status);
		}
		printf(fmt, "exit status", buf);
	}

	if (handle.hdr.info_mask & (1UL << CPUINFO)) {
		printf("# %-20s: %d/%d (online/possible)\n",
		       "nr of cpus", handle.info.nr_cpus_online,
		       handle.info.nr_cpus_possible);
		printf(fmt, "cpu info", handle.info.cpudesc);
	}

	if (handle.hdr.info_mask & (1UL << MEMINFO))
		printf(fmt, "memory info", handle.info.meminfo);

	if (handle.hdr.info_mask & (1UL << OSINFO)) {
		printf(fmt, "kernel version", handle.info.kernel);
		printf(fmt, "hostname", handle.info.hostname);
		printf(fmt, "distro", handle.info.distro);
	}

	if (handle.hdr.info_mask & (1UL << TASKINFO)) {
		int nr = handle.info.nr_tid;
		bool first = true;

		printf("# %-20s: %d\n", "nr of tasks", nr);

		printf("# %-20s: ", "task list");
		while (nr--) {
			printf("%s%d", first ? "" : ", ", handle.info.tids[nr]);
			first = false;
		}
		printf("\n");
	}

	printf("\n");

	close_data_file(opts, &handle);

	return ret;
}

static int command_dump(int argc, char *argv[], struct opts *opts)
{
	int i;
	int ret;
	char buf[PATH_MAX];
	struct ftrace_file_handle handle;
	struct ftrace_task_handle task;

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	for (i = 0; i < handle.info.nr_tid; i++) {
		int tid = handle.info.tids[i];

		snprintf(buf, sizeof(buf), "%s/%d.dat", opts->dirname, tid);
		task.fp = fopen(buf, "rb");
		if (task.fp == NULL)
			continue;

		printf("reading %d.dat\n", tid);
		while (!read_task_ustack(&task)) {
			struct ftrace_ret_stack *frs = &task.ustack;
			struct ftrace_session *sess = find_task_session(tid, frs->time);
			struct symtabs *symtabs;
			struct sym *sym;
			char *name;

			if (sess == NULL)
				continue;

			symtabs = &sess->symtabs;
			sym = find_symtab(symtabs, frs->addr, proc_maps);
			name = symbol_getname(sym, frs->addr);

			printf("%5d: [%s] %s(%lx) depth: %u\n",
			       tid, frs->type == FTRACE_EXIT ? "exit " : "entry",
			       name, (unsigned long)frs->addr, frs->depth);

			symbol_putname(sym, name);
		}

		fclose(task.fp);
	}

	close_data_file(opts, &handle);

	return ret;
}
