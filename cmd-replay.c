#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <inttypes.h>
#include <stdio_ext.h>
#include <assert.h>
#include <ctype.h>

#include "ftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/fstack.h"


static int column_index;
static bool skip_kernel_before_user = true;
static int prev_tid = -1;

static int task_column_depth(struct ftrace_task_handle *task, struct opts *opts)
{
	if (!opts->column_view)
		return 0;

	if (task->column_index == -1)
		task->column_index = column_index++;

	return task->column_index * opts->column_offset;
}

static void print_backtrace(struct ftrace_task_handle *task)
{
	int i;
	struct ftrace_session *sess;
	struct fstack *fstack;
	struct sym *sym;
	char *name;

	for (i = 0; i < task->stack_count - 1; i++) {
		fstack = &task->func_stack[i];
		sess = find_task_session(task->tid, fstack->total_time);

		if (sess)
			sym = find_symtabs(&sess->symtabs, fstack->addr, proc_maps);
		else
			sym = NULL;

		name = symbol_getname(sym, fstack->addr);
		pr_out("  backtrace [%5d] |", task->tid);
		pr_gray(" /* [%2d] %s */\n", i, name);
		symbol_putname(sym, name);
	}
}

static int print_flat_rstack(struct ftrace_file_handle *handle,
			     struct ftrace_task_handle *task,
			     struct opts *opts)
{
	static int count;
	struct ftrace_ret_stack *rstack = task->rstack;
	struct ftrace_session *sess = find_task_session(task->tid, rstack->time);
	struct symtabs *symtabs;
	struct sym *sym;
	char *name;
	struct fstack *fstack;

	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtabs(symtabs, rstack->addr, proc_maps);
	name = symbol_getname(sym, rstack->addr);
	fstack = &task->func_stack[rstack->depth];

	if (rstack->type == FTRACE_ENTRY) {
		pr_out("[%d] ==> %d/%d: ip (%s), time (%"PRIu64")\n",
		       count++, task->tid, rstack->depth,
		       name, rstack->time);
	} else if (rstack->type == FTRACE_EXIT) {
		pr_out("[%d] <== %d/%d: ip (%s), time (%"PRIu64":%"PRIu64")\n",
		       count++, task->tid, rstack->depth,
		       name, rstack->time, fstack->total_time);
	} else if (rstack->type == FTRACE_LOST) {
		pr_out("[%d] XXX %d: lost %d records\n",
		       count++, task->tid, (int)rstack->addr);
	}

	symbol_putname(sym, name);
	return 0;
}

static void print_task_newline(int current_tid)
{
	if (prev_tid != -1 && current_tid != prev_tid)
		pr_out(" %7s %2s %7s |\n", "", "", "");

	prev_tid = current_tid;
}

static void get_arg_string(struct ftrace_task_handle *task, bool need_paren,
			   bool have_args, char *args, size_t len)
{
	int i = 0, n = 1;
	long val;
	char str[64];
	const int null_str = -1;
	void *data = task->args.data;
	struct ftrace_arg_spec *spec;

	if (!have_args) {
		if (need_paren)
			strcpy(args, "()");
		else
			args[0] = '\0';
		return;
	}

	assert(task->args.args && !list_empty(task->args.args));

	args[0] = '(';
	list_for_each_entry(spec, task->args.args, list) {
		char fmtstr[16];
		char *len_mod[] = { "hh", "h", "", "ll" };
		char fmt, *lm;
		unsigned idx;
		size_t size = spec->size;

		if (i > 0) {
			n += snprintf(args + n, len, ", ");
			len -= n;
		}

		val = 0ULL;
		fmt = ARG_SPEC_CHARS[spec->fmt];

		switch (spec->fmt) {
		case ARG_FMT_SINT:
		case ARG_FMT_UINT:
		case ARG_FMT_HEX:
			idx = ffs(spec->size) - 1;
			break;
		case ARG_FMT_AUTO:
			memcpy(&val, data, spec->size);
			if (val > 100000LL || val < -100000LL)
				fmt = 'x';
			/* fall through */
		default:
			idx = 2;
			break;
		}

		if (spec->fmt == ARG_FMT_STR) {
			unsigned short slen;
			memcpy(&slen, data, 2);

			memcpy(str, data + 2, slen);
			str[slen] = '\0';

			if (!memcmp(str, &null_str, sizeof(null_str)))
				n += snprintf(args + n, len, "NULL");
			else
				n += snprintf(args + n, len, "\"%.*s\"",
					      slen, str);

			size = slen + 2;
		}
		else if (spec->fmt == ARG_FMT_CHAR) {
			char c;

			memcpy(&c, data, 1);
			if (isprint(c))
				n += snprintf(args + n, len, "'%c'", c);
			else
				n += snprintf(args + n, len, "'\\x%02hhx'", c);
			size = 1;
		}
		else {
			assert(idx < ARRAY_SIZE(len_mod));
			lm = len_mod[idx];

			if (spec->fmt != ARG_FMT_AUTO)
				memcpy(&val, data, spec->size);

			snprintf(fmtstr, sizeof(fmtstr), "%%#%s%c", lm, fmt);

			n += snprintf(args + n, len, fmtstr, val);
		}

		i++;
		len -= n;
		data += ALIGN(size, 4);
	}
	args[n] = ')';
	args[n+1] = '\0';
}

static int print_graph_no_merge_rstack(struct ftrace_file_handle *handle,
				       struct ftrace_task_handle *task,
				       struct opts *opts)
{
	struct ftrace_ret_stack *rstack = task->rstack;
	static bool seen_user_rstack = false;
	struct ftrace_session *sess;
	struct symtabs *symtabs;
	struct sym *sym;
	char *symname;
	bool needs_paren;
	char args[1024];

	if (task == NULL)
		return 0;

	sess = find_task_session(task->tid, rstack->time);
	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtabs(symtabs, rstack->addr, proc_maps);
	symname = symbol_getname(sym, rstack->addr);
	needs_paren = (symname[strlen(symname) - 1] != ')');

	if (skip_kernel_before_user) {
		if (!seen_user_rstack && !is_kernel_address(rstack->addr))
			seen_user_rstack = true;
		if (is_kernel_address(rstack->addr) && !seen_user_rstack)
			goto out;
	}

	if (rstack->type == FTRACE_ENTRY) {
		struct ftrace_trigger tr = {
			.flags = 0,
		};
		struct fstack *fstack;
		int ret;
		int depth = task->display_depth;

		ret = fstack_entry(task, rstack, &tr);
		if (ret < 0)
			goto out;

		if (tr.flags & TRIGGER_FL_BACKTRACE)
			print_backtrace(task);

		depth += task_column_depth(task, opts);

		fstack = &task->func_stack[rstack->depth];

		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		get_arg_string(task, needs_paren, rstack->more, args, sizeof(args));

		/* function entry */
		print_time_unit(0UL);
		pr_out(" [%5d] | %*s%s%s {\n", task->tid,
		       depth * 2, "", symname, args);

		fstack_update(FTRACE_ENTRY, task, fstack);
	}
	else if (rstack->type == FTRACE_EXIT) {
		struct fstack *fstack = &task->func_stack[rstack->depth];
		int depth = fstack_update(FTRACE_EXIT, task, fstack);

		depth += task_column_depth(task, opts);

		/* function exit */
		if (!(fstack->flags & FSTACK_FL_NORECORD) && fstack_enabled) {
			/* give a new line when tid is changed */
			if (opts->task_newline)
				print_task_newline(task->tid);

			print_time_unit(fstack->total_time);
			pr_out(" [%5d] | %*s}", task->tid, depth * 2, "");
			pr_gray(" /* %s */\n", symname);
		}

		fstack_exit(task);
	}
	else if (rstack->type == FTRACE_LOST) {
		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		print_time_unit(0UL);
		pr_out(" [%5d] |", task->tid);
		pr_gray("     /* LOST %d records!! */\n", (int)rstack->addr);
	}
out:
	symbol_putname(sym, symname);
	return 0;
}

static int print_graph_rstack(struct ftrace_file_handle *handle,
			      struct ftrace_task_handle *task,
			      struct opts *opts)
{
	struct ftrace_ret_stack *rstack = task->rstack;
	static bool seen_user_rstack = false;
	struct ftrace_session *sess;
	struct symtabs *symtabs;
	struct sym *sym;
	bool needs_paren;
	char *symname;

	if (task == NULL)
		return 0;

	sess = find_task_session(task->tid, rstack->time);
	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtabs(symtabs, rstack->addr, proc_maps);
	symname = symbol_getname(sym, rstack->addr);
	needs_paren = (symname[strlen(symname) - 1] != ')');

	if (skip_kernel_before_user) {
		if (!seen_user_rstack && !is_kernel_address(rstack->addr))
			seen_user_rstack = true;
		if (is_kernel_address(rstack->addr) && !seen_user_rstack)
			goto out;
	}

	if (rstack->type == FTRACE_ENTRY) {
		struct ftrace_task_handle *next;
		struct fstack *fstack;
		int rstack_depth = rstack->depth;
		int depth = task->display_depth;
		struct ftrace_trigger tr = {
			.flags = 0,
		};
		int ret;
		char args[1024];

		ret = fstack_entry(task, rstack, &tr);
		if (ret < 0)
			goto out;

		if (tr.flags & TRIGGER_FL_BACKTRACE)
			print_backtrace(task);

		depth += task_column_depth(task, opts);

		get_arg_string(task, needs_paren, rstack->more, args, sizeof(args));

		fstack = &task->func_stack[task->stack_count - 1];

		next = fstack_skip(handle, task, rstack_depth);

		if (task == next &&
		    next->rstack->depth == rstack_depth &&
		    next->rstack->type == FTRACE_EXIT) {

			/* give a new line when tid is changed */
			if (opts->task_newline)
				print_task_newline(task->tid);

			/* leaf function - also consume return record */
			print_time_unit(fstack->total_time);

			pr_out(" [%5d] | %*s%s%s;\n", task->tid,
			       depth * 2, "", symname, args);
			/* consume the rstack */
			read_rstack(handle, &next);

			/* fstack_update() is not needed here */

			fstack_exit(task);
		}
		else {
			/* give a new line when tid is changed */
			if (opts->task_newline)
				print_task_newline(task->tid);

			/* function entry */
			print_time_unit(0UL);
			pr_out(" [%5d] | %*s%s%s {\n", task->tid,
			       depth * 2, "", symname, args);

			fstack_update(FTRACE_ENTRY, task, fstack);
		}
	}
	else if (rstack->type == FTRACE_EXIT) {
		struct fstack *fstack;

		/* function exit */
		fstack = &task->func_stack[task->stack_count];

		if (!(fstack->flags & FSTACK_FL_NORECORD) && fstack_enabled) {
			int depth = fstack_update(FTRACE_EXIT, task, fstack);

			depth += task_column_depth(task, opts);

			/* give a new line when tid is changed */
			if (opts->task_newline)
				print_task_newline(task->tid);

			print_time_unit(fstack->total_time);
			pr_out(" [%5d] | %*s}", task->tid, depth * 2, "");
			pr_gray(" /* %s */\n", symname);
		}

		fstack_exit(task);
	}
	else if (rstack->type == FTRACE_LOST) {
		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		print_time_unit(0UL);
		pr_out(" [%5d] |", task->tid);
		pr_gray("     /* LOST %d records!! */\n", (int)rstack->addr);
	}
out:
	symbol_putname(sym, symname);
	return 0;
}

static void print_remaining_stack(void)
{
	int i;
	int total = 0;

	for (i = 0; i < nr_tasks; i++)
		total += tasks[i].stack_count;

	if (total == 0)
		return;

	pr_out("\nftrace stopped tracing with remaining functions");
	pr_out("\n===============================================\n");

	for (i = 0; i < nr_tasks; i++) {
		struct ftrace_task_handle *task = &tasks[i];

		if (task->stack_count == 0)
			continue;

		pr_out("task: %d\n", task->tid);

		while (task->stack_count-- > 0) {
			struct fstack *fstack = &task->func_stack[task->stack_count];
			uint64_t time = fstack->total_time;
			struct ftrace_session *sess = find_task_session(task->tid, time);
			unsigned long ip = fstack->addr;
			struct symtabs *symtabs;
			struct sym *sym;
			char *symname;

			if (sess) {
				symtabs = &sess->symtabs;
				sym = find_symtabs(symtabs, ip, proc_maps);
			} else
				sym = NULL;

			symname = symbol_getname(sym, ip);

			pr_out("[%d] %s\n", task->stack_count, symname);

			symbol_putname(sym, symname);
		}
		pr_out("\n");
	}
}

int command_replay(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
	struct ftrace_task_handle *task;
	struct ftrace_kernel kern;

	__fsetlocking(outfp, FSETLOCKING_BYCALLER);
	__fsetlocking(logfp, FSETLOCKING_BYCALLER);

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	if (opts->kernel && (handle.hdr.feat_mask & KERNEL)) {
		kern.output_dir = opts->dirname;
		if (setup_kernel_data(&kern) == 0) {
			handle.kern = &kern;
			load_kernel_symbol();
		}
	}

	if (opts->filter || opts->trigger) {
		if (setup_fstack_filters(opts->filter, opts->trigger) < 0) {
			pr_err_ns("failed to set filter or trigger: %s%s%s\n",
				  opts->filter ?: "",
				  (opts->filter && opts->trigger) ? " or " : "",
				  opts->trigger ?: "");
			return -1;
		}
	}

	if (opts->disabled)
		fstack_enabled = false;

	if (opts->tid)
		setup_task_filter(opts->tid, &handle);

	fstack_prepare_fixup();

	if (!opts->flat)
		pr_out("# DURATION    TID     FUNCTION\n");

	while (read_rstack(&handle, &task) == 0 && !ftrace_done) {
		if (opts->flat)
			ret = print_flat_rstack(&handle, task, opts);
		else if (opts->no_merge)
			ret = print_graph_no_merge_rstack(&handle, task, opts);
		else
			ret = print_graph_rstack(&handle, task, opts);

		if (ret)
			break;
	}

	print_remaining_stack();

	if (handle.kern)
		finish_kernel_data(handle.kern);

	close_data_file(opts, &handle);

	return ret;
}
