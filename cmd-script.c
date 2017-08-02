/*
 * Python script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdio_ext.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/fstack.h"
#include "utils/script.h"

#include "libtraceevent/event-parse.h"


static int run_script_for_rstack(struct ftrace_file_handle *handle,
				 struct ftrace_task_handle *task,
				 struct opts *opts)
{
	struct uftrace_record *rstack = task->rstack;
	struct uftrace_session_link *sessions = &handle->sessions;
	struct sym *sym = NULL;
	char *symname = NULL;

	sym = task_find_sym(sessions, task, rstack);
	symname = symbol_getname(sym, rstack->addr);

	task->timestamp_last = task->timestamp;
	task->timestamp = rstack->time;

	if (rstack->type == UFTRACE_ENTRY) {
		struct fstack *fstack;
		int depth;
		struct ftrace_trigger tr = {
			.flags = 0,
		};
		int ret;

		ret = fstack_entry(task, rstack, &tr);
		if (ret < 0)
			goto out;

		/* display depth is set in fstack_entry() */
		depth = task->display_depth;

		fstack = &task->func_stack[task->stack_count - 1];
		fstack_update(UFTRACE_ENTRY, task, fstack);

		/* setup arguments for script execution */
		struct script_args sc_args = {
			.tid = task->tid,
			.depth = depth,  /* display depth */
			.timestamp = rstack->time,
			.address = rstack->addr,
			.symname = symname,
		};

		/* script hooking for function entry */
		script_uftrace_entry(&sc_args);
	}
	else if (rstack->type == UFTRACE_EXIT) {
		struct fstack *fstack;

		/* function exit */
		fstack = &task->func_stack[task->stack_count];

		if (!(fstack->flags & FSTACK_FL_NORECORD) && fstack_enabled) {
			int depth = fstack_update(UFTRACE_EXIT, task, fstack);

			/* display depth is set before passing rstack */
			rstack->depth = depth;
		}

		fstack_exit(task);

		/* setup arguments for script execution */
		struct script_args sc_args = {
			.tid = task->tid,
			.depth = rstack->depth,
			.timestamp = rstack->time,
			.duration = fstack->total_time,
			.address = rstack->addr,
			.symname = symname,
		};

		/* script hooking for function exit */
		script_uftrace_exit(&sc_args);
	}
	else if (rstack->type == UFTRACE_LOST) {
		/* Do nothing as of now */
	}
	else if (rstack->type == UFTRACE_EVENT) {
		/* TODO: event handling */
	}
out:
	symbol_putname(sym, symname);
	return 0;
}

int command_script(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
	struct ftrace_task_handle *task;

	if (!SCRIPT_ENABLED) {
		pr_warn("script command is not supported due to missing libpython2.7.so\n");
		return -1;
	}

	if (!opts->script_file) {
		pr_out("Usage: uftrace script [-S|--script] [<script_file>]\n");
		return -1;
	}

	__fsetlocking(outfp, FSETLOCKING_BYCALLER);
	__fsetlocking(logfp, FSETLOCKING_BYCALLER);

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	fstack_setup_filters(opts, &handle);

	/* initialize script */
	if (script_init(opts->script_file) < 0)
		return -1;

	while (read_rstack(&handle, &task) == 0 && !uftrace_done) {
		struct uftrace_record *rstack = task->rstack;

		/* skip user functions if --kernel-only is set */
		if (opts->kernel_only && !is_kernel_record(task, rstack))
			continue;

		if (opts->kernel_skip_out) {
			/* skip kernel functions outside user functions */
			if (!task->user_stack_count &&
			    is_kernel_record(task, rstack))
				continue;
		}

		ret = run_script_for_rstack(&handle, task, opts);

		if (ret)
			break;
	}

	/* dtor for script support */
	script_uftrace_end();

	close_data_file(opts, &handle);

	return ret;
}
