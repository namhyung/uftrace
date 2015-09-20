#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "ftrace.h"
#include "utils/utils.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"


struct trace_entry {
	int pid;
	struct sym *sym;
	uint64_t time_total;
	uint64_t time_self;
	unsigned long nr_called;
	struct rb_node link;
};

static void insert_entry(struct rb_root *root, struct trace_entry *te, bool thread)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	pr_dbg("%s: [%5d] %-40.40s: %"PRIu64" (%lu)\n",
	       __func__, te->pid, te->sym->name, te->time_total, te->nr_called);

	while (*p) {
		int cmp;

		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (thread)
			cmp = te->pid - entry->pid;
		else
			cmp = strcmp(entry->sym->name, te->sym->name);

		if (cmp == 0) {
			entry->time_total += te->time_total;
			entry->time_self  += te->time_self;
			entry->nr_called  += te->nr_called;
			return;
		}

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	entry = xmalloc(sizeof(*entry));
	entry->pid = te->pid;
	entry->sym = te->sym;
	entry->time_total = te->time_total;
	entry->time_self  = te->time_self;
	entry->nr_called  = te->nr_called;

	rb_link_node(&entry->link, parent, p);
	rb_insert_color(&entry->link, root);
}

static void sort_by_time(struct rb_root *root, struct trace_entry *te)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (entry->time_total < te->time_total)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&te->link, parent, p);
	rb_insert_color(&te->link, root);
}

static void report_functions(struct ftrace_file_handle *handle)
{
	struct sym *sym;
	struct trace_entry te;
	struct ftrace_ret_stack *rstack;
	struct rb_root name_tree = RB_ROOT;
	struct rb_root time_tree = RB_ROOT;
	struct rb_node *node;
	const char f_format[] = "  %-40.40s  %10.10s  %10.10s  %10.10s  \n";
	const char line[] = "=================================================";

	struct ftrace_task_handle *task;
	struct ftrace_session *sess;
	struct fstack *fstack;

	while (read_rstack(handle, &task) >= 0) {
		rstack = task->rstack;
		if (rstack->type != FTRACE_EXIT)
			continue;

		if (rstack == &task->kstack)
			sess = first_session;
		else
			sess = find_task_session(task->tid, rstack->time);

		if (sess == NULL)
			continue;

		sym = find_symtab(&sess->symtabs, rstack->addr, NULL);
		if (sym == NULL)
			continue;

		fstack = &task->func_stack[rstack->depth];

		te.pid = task->tid;
		te.sym = sym;
		te.time_total = fstack->total_time;
		te.time_self = te.time_total - fstack->child_time;
		te.nr_called = 1;

		insert_entry(&name_tree, &te, false);
	}

	while (!RB_EMPTY_ROOT(&name_tree)) {
		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		sort_by_time(&time_tree, rb_entry(node, struct trace_entry, link));
	}

	printf(f_format, "Function", "Total time", "Self time", "Nr. called");
	printf(f_format, line, line, line, line);

	for (node = rb_first(&time_tree); node; node = rb_next(node)) {
		char *symname;
		struct trace_entry *entry;

		entry = rb_entry(node, struct trace_entry, link);

		symname = symbol_getname(entry->sym, 0);

		printf("  %-40.40s ", symname);
		print_time_unit(entry->time_total);
		putchar(' ');
		print_time_unit(entry->time_self);
		printf("  %10lu  \n", entry->nr_called);

		symbol_putname(entry->sym, symname);
	}

	while (!RB_EMPTY_ROOT(&time_tree)) {
		node = rb_first(&time_tree);
		rb_erase(node, &time_tree);

		free(rb_entry(node, struct trace_entry, link));
	}
}

static struct sym * find_task_sym(struct ftrace_file_handle *handle, int idx,
				  struct ftrace_ret_stack *rstack)
{
	struct sym *sym;
	struct ftrace_task_handle *task = &tasks[idx];
	struct ftrace_session *sess = find_task_session(task->tid, rstack->time);
	struct symtabs *symtabs = &sess->symtabs;

	if (task->func)
		return task->func;

	if (sess == NULL) {
		pr_log("cannot find session for tid %d\n", task->tid);
		return NULL;
	}

	if (idx == handle->info.nr_tid - 1) {
		/* This is the main thread */
		task->func = sym = find_symname(symtabs, "main");
		if (sym)
			return sym;

		pr_log("no main thread???\n");
		/* fall through */
	}

	task->func = sym = find_symtab(symtabs, rstack->addr, proc_maps);
	if (sym == NULL)
		pr_log("cannot find symbol for %lx\n", rstack->addr);

	return sym;
}

static void report_threads(struct ftrace_file_handle *handle)
{
	int i;
	struct trace_entry te;
	struct ftrace_ret_stack *rstack;
	struct rb_root name_tree = RB_ROOT;
	struct rb_node *node;
	struct ftrace_task_handle *task;
	struct fstack *fstack;
	const char t_format[] = "  %5.5s  %-40.40s  %10.10s  %10.10s  \n";
	const char line[] = "=================================================";

	for (i = 0; i < handle->info.nr_tid; i++) {
		while ((rstack = get_task_ustack(handle, i)) != NULL) {
			task = &tasks[i];

			if (rstack->type == FTRACE_ENTRY && task->func)
				goto next;

			te.pid = task->tid;
			te.sym = find_task_sym(handle, i, rstack);

			fstack = &task->func_stack[rstack->depth];

			if (rstack->type == FTRACE_ENTRY) {
				te.time_total = te.time_self = 0;
				te.nr_called = 0;
			} else if (rstack->type == FTRACE_EXIT) {
				te.time_total = fstack->total_time;
				te.time_self = te.time_total - fstack->child_time;
				te.nr_called = 1;
			}

			insert_entry(&name_tree, &te, true);

		next:
			tasks[i].valid = false; /* force re-read */
		}
	}

	printf(t_format, "TID", "Start function", "Run time", "Nr. funcs");
	printf(t_format, line, line, line, line);

	while (!RB_EMPTY_ROOT(&name_tree)) {
		char *symname;
		struct trace_entry *entry;

		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		entry = rb_entry(node, struct trace_entry, link);
		symname = symbol_getname(entry->sym, 0);

		printf("  %5d  %-40.40s ", entry->pid, symname);
		print_time_unit(entry->time_self);
		printf("  %10lu  \n", entry->nr_called);

		symbol_putname(entry->sym, symname);
	}

	while (!RB_EMPTY_ROOT(&name_tree)) {
		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		free(rb_entry(node, struct trace_entry, link));
	}
}

int command_report(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
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

	start_pager();

	if (opts->tid)
		setup_task_filter(opts->tid, &handle);

	if (opts->report_thread)
		report_threads(&handle);
	else
		report_functions(&handle);

	if (handle.kern)
		finish_kernel_data(handle.kern);

	close_data_file(opts, &handle);

	wait_for_pager();
	return ret;
}
