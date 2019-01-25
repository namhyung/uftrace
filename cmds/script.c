/*
 * Python script binding for function entry and exit
 *
 * Copyright (C) 2017-2018, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>

#include "uftrace.h"
#include "utils/event.h"
#include "utils/filter.h"
#include "utils/fstack.h"
#include "utils/script.h"
#include "utils/symbol.h"
#include "utils/utils.h"
#include "version.h"

static int run_script_for_rstack(struct uftrace_data *handle, struct uftrace_task_reader *task,
				 struct uftrace_opts *opts)
{
	struct uftrace_record *rstack = task->rstack;
	struct uftrace_session_link *sessions = &handle->sessions;
	struct uftrace_symbol *sym = NULL;
	char *symname = NULL;

	sym = task_find_sym(sessions, task, rstack);
	symname = symbol_getname(sym, rstack->addr);

	/* skip it if --no-libcall is given */
	if (!opts->libcall && sym && sym->type == ST_PLT_FUNC)
		goto out;

	task->timestamp_last = task->timestamp;
	task->timestamp = rstack->time;

	if (rstack->type == UFTRACE_ENTRY) {
		struct script_context sc_ctx = {
			0,
		};
		struct uftrace_fstack *fstack;
		struct uftrace_trigger tr = {
			.flags = 0,
		};
		int depth;
		int ret;

		ret = fstack_entry(task, rstack, &tr);
		if (ret < 0)
			goto out;

		/* display depth is set in fstack_entry() */
		depth = task->display_depth;

		fstack = fstack_get(task, task->stack_count - 1);
		fstack_update(UFTRACE_ENTRY, task, fstack);

		if (!script_match_filter(symname))
			goto out;

		sc_ctx.tid = task->tid;
		sc_ctx.depth = depth; /* display depth */
		sc_ctx.timestamp = rstack->time;
		sc_ctx.address = rstack->addr;
		sc_ctx.name = symname;

		if (tr.flags & TRIGGER_FL_ARGUMENT && opts->show_args) {
			sc_ctx.argbuf = task->args.data;
			sc_ctx.arglen = task->args.len;
			sc_ctx.argspec = task->args.args;
		}

		/* script hooking for function entry */
		script_uftrace_entry(&sc_ctx);
	}
	else if (rstack->type == UFTRACE_EXIT) {
		struct script_context sc_ctx = {
			0,
		};
		struct uftrace_fstack *fstack;

		/* function exit */
		fstack = fstack_get(task, task->stack_count);

		if (fstack_enabled && fstack && !(fstack->flags & FSTACK_FL_NORECORD)) {
			int depth = fstack_update(UFTRACE_EXIT, task, fstack);

			if (!script_match_filter(symname)) {
				fstack_exit(task);
				goto out;
			}

			/* display depth is set before passing rstack */
			rstack->depth = depth;

			/* setup context for script execution */
			sc_ctx.tid = task->tid;
			sc_ctx.depth = rstack->depth;
			sc_ctx.timestamp = rstack->time;
			sc_ctx.duration = fstack->total_time;
			sc_ctx.address = rstack->addr;
			sc_ctx.name = symname;

			if (rstack->more && opts->show_args) {
				sc_ctx.argbuf = task->args.data;
				sc_ctx.arglen = task->args.len;
				sc_ctx.argspec = task->args.args;
			}

			/* script hooking for function exit */
			script_uftrace_exit(&sc_ctx);
		}

		fstack_exit(task);
	}
	else if (rstack->type == UFTRACE_EVENT) {
		struct script_context sc_ctx = {
			.tid = task->tid,
			.depth = rstack->depth,
			.timestamp = rstack->time,
			.address = rstack->addr,
		};
		struct uftrace_symbol *watch_sym = NULL;

		if (rstack->addr == EVENT_ID_WATCH_VAR) {
			unsigned long long addr = 0;

			if (data_is_lp64(task->h))
				memcpy(&addr, task->args.data, 8);
			else
				memcpy(&addr, task->args.data, 4);

			watch_sym = task_find_sym_addr(sessions, task, rstack->time, addr);
		}

		sc_ctx.name = event_get_name(handle, rstack->addr);
		sc_ctx.argbuf = event_get_data_str(handle, rstack->addr, task->args.data,
						   task->args.len, watch_sym, false);

		script_uftrace_event(&sc_ctx);

		free(sc_ctx.name);
		free(sc_ctx.argbuf);
	}
	else if (rstack->type == UFTRACE_LOST) {
		/* Do nothing as of now */
	}

out:
	symbol_putname(sym, symname);
	return 0;
}

int command_script(int argc, char *argv[], struct uftrace_opts *opts)
{
	int ret;
	struct uftrace_data handle;
	struct uftrace_task_reader *task;
	struct script_info info = {
		.name = opts->script_file,
		.version = UFTRACE_VERSION,
	};

	if (!SCRIPT_ENABLED) {
		pr_warn("script command is not supported due to missing libpython2.7.so\n");
		return -1;
	}

	if (!opts->script_file) {
		pr_out("Usage: uftrace script (-S|--script) <script_file>\n");
		return -1;
	}

	if (opts->record) {
		char *script_file;

		/* parse in-script record option - "uftrace_options" */
		parse_script_opt(opts);

		script_file = opts->script_file;
		opts->script_file = NULL;

		pr_dbg("start recording before running a script\n");
		ret = command_record(argc, argv, opts);
		if (ret < 0) {
			pr_warn("cannot record data: %m\n");
			return -1;
		}

		opts->script_file = script_file;
	}

	__fsetlocking(outfp, FSETLOCKING_BYCALLER);
	__fsetlocking(logfp, FSETLOCKING_BYCALLER);

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
		return -1;
	}

	fstack_setup_filters(opts, &handle);

	strv_copy(&info.cmds, argc, argv);

	/* initialize script */
	if (script_init(&info, opts->patt_type) < 0) {
		ret = -1;
		goto out;
	}

	while (read_rstack(&handle, &task) == 0 && !uftrace_done) {
		if (!fstack_check_opts(task, opts))
			continue;

		ret = run_script_for_rstack(&handle, task, opts);

		if (ret)
			break;
	}

	/* dtor for script support */
	script_uftrace_end();
out:
	script_finish();

	close_data_file(opts, &handle);

	strv_free(&info.cmds);

	return ret;
}
