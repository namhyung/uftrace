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
	unsigned long addr;
	int nr_edges;
	int nr_calls;
	uint64_t time;
	uint64_t child_time;
	struct list_head head;
	struct list_head list;
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
	struct graph_node *curr_node;
	struct graph_node root;
};

static struct uftrace_graph *graph_list = NULL;

static int create_graph(struct ftrace_session *sess, void *func)
{
	struct uftrace_graph *graph = xcalloc(1, sizeof(*graph));

	graph->sess = sess;
	graph->func = xstrdup(func);
	INIT_LIST_HEAD(&graph->root.head);

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
	if (!graph->enabled++) {
		save_backtrace_addr(graph, task);
		graph->curr_node = &graph->root;
		graph->curr_node->addr = task->ustack.addr;
		graph->curr_node->nr_calls++;
	}

	return 0;
}

static int end_graph(struct uftrace_graph *graph,
		     struct ftrace_task_handle *task)
{
	if (!--graph->enabled)
		save_backtrace_time(graph, task);

	return 0;
}

static int add_graph_entry(struct uftrace_graph *graph,
			   struct ftrace_task_handle *task)
{
	struct graph_node *node = NULL;
	struct ftrace_ret_stack *rstack = &task->ustack;

	list_for_each_entry(node, &graph->curr_node->head, list) {
		if (node->addr == rstack->addr)
			break;
	}

	if (list_no_entry(node, &graph->curr_node->head, list)) {
		node = xcalloc(1, sizeof(*node));

		node->addr = rstack->addr;
		INIT_LIST_HEAD(&node->head);

		node->parent = graph->curr_node;
		list_add_tail(&node->list, &node->parent->head);
		node->parent->nr_edges++;
	}

	node->nr_calls++;
	graph->curr_node = node;

	return 0;
}

static int add_graph_exit(struct uftrace_graph *graph,
			  struct ftrace_task_handle *task)
{
	struct fstack *fstack = &task->func_stack[task->stack_count];
	struct graph_node *node = graph->curr_node;

	node->time       += fstack->total_time;
	node->child_time += fstack->child_time;

	graph->curr_node = node->parent;

	return 0;
}

static int add_graph(struct uftrace_graph *graph,
		     struct ftrace_task_handle *task)
{
	struct ftrace_ret_stack *rstack = &task->ustack;

	if (rstack->type == FTRACE_ENTRY)
		return add_graph_entry(graph, task);
	else if (rstack->type == FTRACE_EXIT)
		return add_graph_exit(graph, task);
	else
		return 0;
}

static void pr_indent(bool *indent_mask, int indent, bool line)
{
	int i;
	int last = -1;

	for (i = 0; i < indent; i++) {
		if (line && indent_mask[i])
			last = i;
	}

	for (i = 0; i < indent; i++) {
		if (!line || i < last) {
			if (indent_mask[i])
				pr_out(" | ");
			else
				pr_out("   ");
		}
		else {
			if (i == last)
				pr_out(" +-");
			else
				pr_out("---");
		}
	}
}

static void print_graph_node(struct uftrace_graph *graph,
			     struct graph_node *node, int depth,
			     bool *indent_mask, int indent, bool needs_line)
{
	struct sym *sym;
	char *symname;
	struct graph_node *parent = node->parent;
	struct graph_node *child;
	int orig_indent = indent;

	sym = find_symtabs(&graph->sess->symtabs, node->addr);
	symname = symbol_getname(sym, node->addr);

	print_time_unit(node->time);
	pr_out(" : ");
	pr_indent(indent_mask, indent, needs_line);
	pr_out("(%d) %s\n", node->nr_calls, symname);

	if (node->nr_edges > 1) {
		pr_dbg2("add mask (%d) for %s\n", indent, symname);
		indent_mask[indent++] = true;
	}

	/* clear parent indent mask at the last node */
	if (parent && parent->nr_edges > 1 && orig_indent > 0 &&
	    parent->head.prev == &node->list)
		indent_mask[orig_indent - 1] = false;

	if (depth == 1)
		goto out;

	needs_line = (node->nr_edges > 1);
	list_for_each_entry(child, &node->head, list) {
		print_graph_node(graph, child, depth - 1, indent_mask, indent,
				 needs_line);

		if (&child->list != node->head.prev) {
			/* print blank line between siblings */
			pr_out("%*s: ", 12, "");
			pr_indent(indent_mask, indent, false);
			pr_out("\n");
		}
	}

out:
	indent_mask[orig_indent] = false;
	pr_dbg2("del mask (%d) for %s\n", orig_indent, symname);

	symbol_putname(sym, symname);
}

static void print_graph(struct uftrace_graph *graph, struct opts *opts)
{
	bool *indent_mask;

	pr_out("#\n");
	pr_out("# function graph for '%s'\n", graph->func);
	pr_out("#\n\n");

	if (graph->nr_bt) {
		pr_out("backtrace\n");
		pr_out("================================\n");
		print_backtrace(graph);
	}

	pr_out("calling functions\n");
	pr_out("================================\n");
	indent_mask = xcalloc(opts->max_stack, sizeof(*indent_mask));
	print_graph_node(graph, &graph->root, opts->depth,
			 indent_mask, 0, graph->root.nr_edges > 1);
	free(indent_mask);
}

static int build_graph(struct opts *opts, struct ftrace_file_handle *handle, char *func)
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

			if (graph->enabled)
				add_graph(graph, &task);

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
		print_graph(graph, opts);
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

	ret = build_graph(opts, &handle, func);

	if (handle.kern)
		finish_kernel_data(handle.kern);

	close_data_file(opts, &handle);

	return ret;
}
