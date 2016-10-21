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
	struct list_head list;
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

struct task_graph {
	int enabled;
	struct ftrace_task_handle *task;
	struct uftrace_graph *graph;
	struct graph_node *node;
	struct graph_backtrace *bt_curr;
	struct rb_node link;
};

struct uftrace_graph {
	char *func;
	bool kernel_only;
	struct ftrace_session *sess;
	struct uftrace_graph *next;
	struct graph_backtrace *bt_curr;
	struct list_head bt_list;
	struct graph_node root;
};

static struct rb_root tasks = RB_ROOT;
static struct uftrace_graph *graph_list = NULL;

static int create_graph(struct ftrace_session *sess, void *func)
{
	struct uftrace_graph *graph = xcalloc(1, sizeof(*graph));

	graph->sess = sess;
	graph->func = xstrdup(func);
	INIT_LIST_HEAD(&graph->root.head);
	INIT_LIST_HEAD(&graph->bt_list);

	graph->next = graph_list;
	graph_list = graph;

	return 0;
}

static void setup_graph_list(struct opts *opts, char *func)
{
	struct uftrace_graph *graph;

	walk_sessions(create_graph, func);

	graph = graph_list;
	while (graph) {
		graph->kernel_only = opts->kernel_only;
		graph = graph->next;
	}
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

static struct task_graph * get_task_graph(struct ftrace_task_handle *task)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &tasks.rb_node;
	struct task_graph *tg;

	while (*p) {
		parent = *p;
		tg = rb_entry(parent, struct task_graph, link);

		if (tg->task->tid == task->tid)
			goto out;

		if (tg->task->tid > task->tid)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	tg = xmalloc(sizeof(*tg));
	tg->task = task;
	tg->enabled = 0;
	tg->bt_curr = NULL;

	rb_link_node(&tg->link, parent, p);
	rb_insert_color(&tg->link, &tasks);

out:
	tg->graph = get_graph(task);
	return tg;
}

static int save_backtrace_addr(struct task_graph *tg)
{
	int i;
	int skip = 0;
	int len = tg->task->stack_count;
	unsigned long addrs[len];
	struct graph_backtrace *bt;

	if (tg->graph->kernel_only) {
		skip = tg->task->user_stack_count;
		len -= skip;
	}

	if (len == 0)
		return 0;

	for (i = len - 1; i >= 0; i--)
		addrs[i] = tg->task->func_stack[i + skip].addr;

	list_for_each_entry(bt, &tg->graph->bt_list, list) {
		if (len == bt->len &&
		    !memcmp(addrs, bt->addr, len * sizeof(*addrs)))
			goto found;
	}

	bt = xmalloc(sizeof(*bt) + len * sizeof(*addrs));

	bt->len = len;
	bt->hit = 0;
	bt->time = 0;
	memcpy(bt->addr, addrs, len * sizeof(*addrs));

	list_add(&bt->list, &tg->graph->bt_list);

found:
	bt->hit++;
	tg->bt_curr = bt;

	return 0;
}

static void save_backtrace_time(struct task_graph *tg)
{
	struct fstack *fstack = &tg->task->func_stack[tg->task->stack_count];

	if (tg->bt_curr)
		tg->bt_curr->time += fstack->total_time;

	tg->bt_curr = NULL;
}

static int print_backtrace(struct uftrace_graph *graph)
{
	int i = 0, k;
	struct graph_backtrace *bt;
	struct sym *sym;
	char *symname;

	list_for_each_entry(bt, &graph->bt_list, list) {
		pr_out(" backtrace #%d: hit %d, time", i++, bt->hit);
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

static int start_graph(struct task_graph *tg)
{
	if (!tg->enabled++) {
		save_backtrace_addr(tg);

		tg->node = &tg->graph->root;
		tg->node->addr = tg->task->rstack->addr;
		tg->node->nr_calls++;
	}

	return 0;
}

static int end_graph(struct task_graph *tg)
{
	if (!tg->enabled)
		return 0;

	if (!--tg->enabled)
		save_backtrace_time(tg);

	return 0;
}

static int add_graph_entry(struct task_graph *tg)
{
	struct graph_node *node = NULL;
	struct graph_node *curr = tg->node;
	struct ftrace_ret_stack *rstack = tg->task->rstack;

	if (curr == NULL)
		return -1;

	list_for_each_entry(node, &curr->head, list) {
		if (node->addr == rstack->addr)
			break;
	}

	if (list_no_entry(node, &curr->head, list)) {
		node = xcalloc(1, sizeof(*node));

		node->addr = rstack->addr;
		INIT_LIST_HEAD(&node->head);

		node->parent = curr;
		list_add_tail(&node->list, &node->parent->head);
		node->parent->nr_edges++;
	}

	node->nr_calls++;
	tg->node = node;

	return 0;
}

static int add_graph_exit(struct task_graph *tg)
{
	struct fstack *fstack = &tg->task->func_stack[tg->task->stack_count];
	struct graph_node *node = tg->node;

	if (node == NULL)
		return -1;

	node->time       += fstack->total_time;
	node->child_time += fstack->child_time;

	tg->node = node->parent;

	return 0;
}

static int add_graph(struct task_graph *tg)
{
	struct ftrace_ret_stack *rstack = tg->task->rstack;

	if (rstack->type == FTRACE_ENTRY)
		return add_graph_entry(tg);
	else if (rstack->type == FTRACE_EXIT)
		return add_graph_exit(tg);
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

	indent_mask[orig_indent] = false;
	pr_dbg2("del mask (%d) for %s\n", orig_indent, symname);

	symbol_putname(sym, symname);
}

static void print_graph(struct uftrace_graph *graph, struct opts *opts)
{
	bool *indent_mask;

	pr_out("#\n");
	pr_out("# function graph for '%s' (session: %.16s)\n",
	       graph->func, graph->sess->sid);
	pr_out("#\n\n");

	if (!list_empty(&graph->bt_list)) {
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
	pr_out("\n");
}

static int build_graph(struct opts *opts, struct ftrace_file_handle *handle,
		       char *func)
{
	int ret = 0;
	struct ftrace_task_handle *task;
	struct uftrace_graph *graph;
	uint64_t prev_time = 0;

	setup_graph_list(opts, func);

	while (!read_rstack(handle, &task) && !ftrace_done) {
		struct ftrace_ret_stack *frs = task->rstack;
		struct task_graph *tg;
		struct sym *sym = NULL;
		char *name;

		/* skip user functions if --kernel-only is set */
		if (opts->kernel_only && !is_kernel_address(frs->addr))
			continue;

		if (opts->kernel_skip_out) {
			/* skip kernel functions outside user functions */
			if (!task->user_stack_count &&
			    is_kernel_address(frs->addr))
				continue;
		}

		if (!fstack_check_filter(task))
			continue;

		if (prev_time > frs->time) {
			pr_log("inverted time: broken data?\n");
			return -1;
		}
		prev_time = frs->time;

		if (task->stack_count >= opts->max_stack)
			continue;

		tg = get_task_graph(task);
		if (tg->enabled)
			add_graph(tg);

		sym = find_symtabs(&tg->graph->sess->symtabs, frs->addr);
		name = symbol_getname(sym, frs->addr);

		if (!strcmp(name, func)) {
			if (frs->type == FTRACE_ENTRY)
				start_graph(tg);
			else if (frs->type == FTRACE_EXIT)
				end_graph(tg);
		}

		symbol_putname(sym, name);
	}

	graph = graph_list;
	while (graph && !ftrace_done) {
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

	if (opts->idx)
		func = argv[opts->idx];
	else
		func = "main";

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	if (opts->kernel && (handle.hdr.feat_mask & KERNEL)) {
		kern.output_dir = opts->dirname;
		kern.skip_out = opts->kernel_skip_out;
		if (setup_kernel_data(&kern) == 0) {
			handle.kern = &kern;
			load_kernel_symbol();
		}
	}

	fstack_setup_filters(opts, &handle);

	ret = build_graph(opts, &handle, func);

	if (handle.kern)
		finish_kernel_data(handle.kern);

	close_data_file(opts, &handle);

	return ret;
}
