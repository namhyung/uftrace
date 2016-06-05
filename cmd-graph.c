#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <inttypes.h>
#include <stdio_ext.h>
#include <assert.h>
#include <ctype.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/fstack.h"


struct graph_backtrace {
	int len;
	int hit;
	uint64_t time;
	unsigned long addr[];
};

struct graph_node {
	int nr_edges;
	int nr_calls;
	uint64_t time;
	uint64_t child_time;
	struct list_head edges;
	struct graph_node *parent;
};

struct uftrace_graph {
	int nr_bt;
	int enabled;
	char *func;
	struct ftrace_session *sess;
	struct uftrace_graph *next;
	struct graph_backtrace *bt_curr;
	struct graph_backtrace **bt_list;
	struct graph_node root;
};

static struct uftrace_graph *graph_list = NULL;

static int create_graph(struct ftrace_session *sess, void *func)
{
	struct uftrace_graph *graph = xcalloc(1, sizeof(*graph));

	graph->sess = sess;
	graph->func = xstrdup(func);

	graph->next = graph_list;
	graph_list = graph;

	return 0;
}

static void setup_graph_list(char *func)
{
	walk_sessions(create_graph, func);
}

static struct uftrace_graph * get_graph(struct ftrace_task_handle *task)
{
	struct uftrace_graph *graph;
	struct ftrace_session *sess;

	sess = find_task_session(task->tid, task->ustack.time);
	if (sess == NULL)
		return NULL;

	graph = graph_list;
	while (graph) {
		if (graph->sess == sess)
			return graph;

		graph = graph->next;
	}
	return NULL;
}

static int save_backtrace_addr(struct uftrace_graph *graph,
			       struct ftrace_task_handle *task)
{
	int i;
	int len = task->stack_count;
	unsigned long addrs[len];
	struct graph_backtrace *bt;

	if (len == 0)
		return 0;

	for (i = len - 1; i >= 0; i--)
		addrs[i] = task->func_stack[i].addr;

	for (i = 0; i < graph->nr_bt; i++) {
		bt = graph->bt_list[i];

		if (len == bt->len &&
		    !memcmp(addrs, bt->addr, len * sizeof(*addrs)))
			goto found;
	}

	graph->bt_list = xrealloc(graph->bt_list,
				  (graph->nr_bt + 1) * sizeof(*graph->bt_list));

	bt = xmalloc(sizeof(*bt) + len * sizeof(*addrs));

	bt->len = len;
	bt->hit = 0;
	bt->time = 0;
	memcpy(bt->addr, addrs, len * sizeof(*addrs));

	graph->bt_list[graph->nr_bt++] = bt;

found:
	bt->hit++;
	graph->bt_curr = bt;

	return 0;
}

static void save_backtrace_time(struct uftrace_graph *graph,
				struct ftrace_task_handle *task)
{
	struct fstack *fstack = &task->func_stack[task->stack_count];

	if (graph->bt_curr)
		graph->bt_curr->time += fstack->total_time;
}

static int print_backtrace(struct uftrace_graph *graph)
{
	int i, k;
	struct graph_backtrace *bt;
	struct sym *sym;
	char *symname;

	for (i = 0; i < graph->nr_bt; i++) {
		bt = graph->bt_list[i];

		pr_out(" backtrace #%d: hit %d, time", i, bt->hit);
		print_time_unit(bt->time);
		pr_out("\n");

		for (k = 0; k < bt->len; k++) {
			sym = find_symtabs(&graph->sess->symtabs, bt->addr[k]);
			if (sym)
				symname = xstrdup(sym->name);
			else
				symname = symbol_getname(NULL, bt->addr[k]);

			pr_out("   [%d] %s (%#lx)\n", k, symname, bt->addr[k]);

			free(symname);
		}
		pr_out("\n");
	}

	return 0;
}

static void print_graph(struct uftrace_graph *graph)
{
	pr_out("#\n");
	pr_out("# function graph for '%s'\n", graph->func);
	pr_out("#\n\n");

	print_backtrace(graph);
}

static void func_enter(struct ftrace_task_handle *task)
{
	struct fstack *fstack = &task->func_stack[task->stack_count++];
	struct ftrace_ret_stack *rstack = &task->ustack;

	fstack->addr       = rstack->addr;
	fstack->total_time = rstack->time;
	fstack->child_time = 0;
}

static void func_exit(struct ftrace_task_handle *task)
{
	struct fstack *fstack = &task->func_stack[--task->stack_count];
	struct ftrace_ret_stack *rstack = &task->ustack;

	fstack->total_time = rstack->time - fstack->total_time;
	if (task->stack_count > 0)
		fstack[-1].child_time += fstack->total_time;
}

static int func_lost(void)
{
	pr_out("uftrace: cannot process data that contains LOST records, sorry!\n");
	return -1;
}

static int start_graph(struct uftrace_graph *graph,
		       struct ftrace_task_handle *task)
{
	save_backtrace_addr(graph, task);

	graph->enabled++;
	return 0;
}

static int end_graph(struct uftrace_graph *graph,
		     struct ftrace_task_handle *task)
{
	save_backtrace_time(graph, task);

	graph->enabled--;
	return 0;
}

static int build_graph(struct ftrace_file_handle *handle, char *func)
{
	int i, ret = 0;
	struct ftrace_task_handle task;
	struct uftrace_graph *graph;

	setup_graph_list(func);

	for (i = 0; i < handle->info.nr_tid; i++) {
		int tid = handle->info.tids[i];

		setup_task_handle(handle, &task, tid);

		if (task.fp == NULL)
			continue;

		while (!read_task_ustack(handle, &task)) {
			struct ftrace_ret_stack *frs = &task.ustack;
			struct sym *sym = NULL;
			char *name;

			graph = get_graph(&task);
			if (graph == NULL) {
				pr_log("cannot find graph\n");
				return -1;
			}

			sym = find_symtabs(&graph->sess->symtabs, frs->addr);
			name = symbol_getname(sym, frs->addr);

			if (frs->type == FTRACE_ENTRY)
				func_enter(&task);
			else if (frs->type == FTRACE_EXIT)
				func_exit(&task);
			else if (frs->type == FTRACE_LOST)
				return func_lost();

			if (!strcmp(name, func)) {
				if (frs->type == FTRACE_ENTRY)
					start_graph(graph, &task);
				else if (frs->type == FTRACE_EXIT)
					end_graph(graph, &task);
			}

			/* force re-read in read_task_ustack() */
			task.valid = false;
			symbol_putname(sym, name);
		}
	}

	graph = graph_list;
	while (graph) {
		print_graph(graph);
		graph = graph->next;
	}

	return ret;
}

int command_graph(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
	struct ftrace_kernel kern;
	char *func;

	__fsetlocking(outfp, FSETLOCKING_BYCALLER);
	__fsetlocking(logfp, FSETLOCKING_BYCALLER);

	func = argv[opts->idx];

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

	fstack_prepare_fixup();

	ret = build_graph(&handle, func);

	if (handle.kern)
		finish_kernel_data(handle.kern);

	close_data_file(opts, &handle);

	return ret;
}
