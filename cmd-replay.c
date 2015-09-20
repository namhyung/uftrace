#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <inttypes.h>

#include "ftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"


static bool skip_kernel_before_user = true;

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
			sym = find_symtab(&sess->symtabs, fstack->addr, proc_maps);
		else
			sym = NULL;

		name = symbol_getname(sym, fstack->addr);
		printf("  backtrace [%5d] | /* [%2d] %s */\n",
		       task->tid, i, name);
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
	sym = find_symtab(symtabs, rstack->addr, proc_maps);
	name = symbol_getname(sym, rstack->addr);
	fstack = &task->func_stack[rstack->depth];

	if (rstack->type == FTRACE_ENTRY) {
		printf("[%d] ==> %d/%d: ip (%s), time (%"PRIu64")\n",
		       count++, task->tid, rstack->depth,
		       name, rstack->time);
	} else if (rstack->type == FTRACE_EXIT) {
		printf("[%d] <== %d/%d: ip (%s), time (%"PRIu64":%"PRIu64")\n",
		       count++, task->tid, rstack->depth,
		       name, rstack->time, fstack->total_time);
	} else if (rstack->type == FTRACE_LOST) {
		printf("[%d] XXX %d: lost %d records\n",
		       count++, task->tid, (int)rstack->addr);
	}

	symbol_putname(sym, name);
	return 0;
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

	if (task == NULL)
		return 0;

	sess = find_task_session(task->tid, rstack->time);
	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtab(symtabs, rstack->addr, proc_maps);
	symname = symbol_getname(sym, rstack->addr);

	if (skip_kernel_before_user) {
		if (!seen_user_rstack && !is_kernel_address(rstack->addr))
			seen_user_rstack = true;
		if (is_kernel_address(rstack->addr) && !seen_user_rstack)
			goto out;
	}

	if (rstack->type == FTRACE_ENTRY) {
		if (update_filter_count_entry(task, rstack->addr,
					      handle->depth) == 1 &&
		    opts->backtrace)
			print_backtrace(task);

		if (task->filter_count <= 0)
			goto out;

		if (task->filter_depth-- <= 0)
			goto out;

		/* function entry */
		print_time_unit(0UL);
		printf(" [%5d] | %*s%s() {\n", task->tid,
		       rstack->depth * 2, "", symname);
	} else if (rstack->type == FTRACE_EXIT) {
		/* function exit */
		if (task->filter_count > 0 && task->filter_depth++ >= 0) {
			struct fstack *fstack;

			fstack= &task->func_stack[rstack->depth];
			print_time_unit(fstack->total_time);
			printf(" [%5d] | %*s} /* %s */\n", task->tid,
			       rstack->depth * 2, "", symname);
		}

		update_filter_count_exit(task, rstack->addr, handle->depth);
	} else if (rstack->type == FTRACE_LOST) {
		print_time_unit(0UL);
		printf(" [%5d] |     /* LOST %d records!! */\n",
		       task->tid, (int)rstack->addr);
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
	char *symname;

	if (task == NULL)
		return 0;

	sess = find_task_session(task->tid, rstack->time);
	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtab(symtabs, rstack->addr, proc_maps);
	symname = symbol_getname(sym, rstack->addr);

	if (skip_kernel_before_user) {
		if (!seen_user_rstack && !is_kernel_address(rstack->addr))
			seen_user_rstack = true;
		if (is_kernel_address(rstack->addr) && !seen_user_rstack)
			goto out;
	}

	if (rstack->type == FTRACE_ENTRY) {
		struct ftrace_task_handle *next;
		struct fstack *fstack;
		int depth = rstack->depth;

		if (update_filter_count_entry(task, rstack->addr,
					      handle->depth) == 1 &&
		    opts->backtrace)
			print_backtrace(task);

		if (task->filter_count <= 0)
			goto out;

		if (task->filter_depth-- <= 0)
			goto out;

		if (peek_rstack(handle, &next) < 0)
			next = NULL;

		if (task == next &&
		    next->rstack->depth == depth &&
		    next->rstack->type == FTRACE_EXIT) {
			/* leaf function - also consume return record */
			fstack = &task->func_stack[rstack->depth];

			print_time_unit(fstack->total_time);
			printf(" [%5d] | %*s%s();\n", task->tid,
			       rstack->depth * 2, "", symname);

			/* consume the rstack */
			read_rstack(handle, &next);

			task->filter_depth++;
			update_filter_count_exit(task, next->rstack->addr, handle->depth);
		} else {
			/* function entry */
			print_time_unit(0UL);
			printf(" [%5d] | %*s%s() {\n", task->tid,
			       depth * 2, "", symname);
		}
	} else if (rstack->type == FTRACE_EXIT) {
		/* function exit */
		if (task->filter_count > 0 && task->filter_depth++ >= 0) {
			struct fstack *fstack;

			fstack = &task->func_stack[rstack->depth];

			print_time_unit(fstack->total_time);
			printf(" [%5d] | %*s} /* %s */\n", task->tid,
			       rstack->depth * 2, "", symname);
		}

		update_filter_count_exit(task, rstack->addr, handle->depth);

	} else if (rstack->type == FTRACE_LOST) {
		print_time_unit(0UL);
		printf(" [%5d] |     /* LOST %d records!! */\n",
		       task->tid, (int)rstack->addr);
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

	printf("\nftrace stopped tracing with remaining functions");
	printf("\n===============================================\n");

	for (i = 0; i < nr_tasks; i++) {
		struct ftrace_task_handle *task = &tasks[i];

		if (task->stack_count == 0)
			continue;

		printf("task: %d\n", task->tid);

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
				sym = find_symtab(symtabs, ip, proc_maps);
			} else
				sym = NULL;

			symname = symbol_getname(sym, ip);

			printf("[%d] %s\n", task->stack_count, symname);

			symbol_putname(sym, symname);
		}
		printf("\n");
	}
}

int command_replay(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
	struct ftrace_task_handle *task;
	struct sigaction sa = {
		.sa_flags = 0,
	};
	struct ftrace_kernel kern;

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

	if (opts->filter) {
		ftrace_setup_filter_regex(opts->filter, &first_session->symtabs,
					  &filters.filters, &filters.has_filters);
		if (!filters.has_filters)
			return -1;
	}

	if (opts->notrace) {
		ftrace_setup_filter_regex(opts->notrace, &first_session->symtabs,
					  &filters.notrace, &filters.has_notrace);
		if (!filters.has_notrace)
			return -1;
	}

	start_pager();

	if (opts->tid)
		setup_task_filter(opts->tid, &handle);

	if (!opts->flat)
		printf("# DURATION    TID     FUNCTION\n");

	sa.sa_handler = sighandler;
	sigfillset(&sa.sa_mask);

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

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

	wait_for_pager();
	return ret;
}
