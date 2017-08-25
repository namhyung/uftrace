#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <inttypes.h>
#include <stdio_ext.h>
#include <assert.h>

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
	uint64_t addr[];
};

struct graph_node {
	uint64_t addr;
	int nr_edges;
	int nr_calls;
	uint64_t time;
	uint64_t child_time;
	struct list_head head;
	struct list_head list;
	struct graph_node *parent;
};

struct uftrace_graph {
	char *func;
	bool kernel_only;
	struct uftrace_session *sess;
	struct uftrace_graph *next;
	struct graph_backtrace *bt_curr;
	struct list_head bt_list;
	struct graph_node root;
};

struct task_graph {
	int enabled;
	bool lost;
	struct ftrace_task_handle *task;
	struct uftrace_graph *graph;
	struct graph_node *node;
	struct graph_backtrace *bt_curr;
	struct rb_node link;
};

static struct rb_root tasks = RB_ROOT;
static struct uftrace_graph *graph_list = NULL;

static int create_graph(struct uftrace_session *sess, void *func)
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

static void setup_graph_list(struct ftrace_file_handle *handle, struct opts *opts,
			     char *func)
{
	struct uftrace_graph *graph;

	walk_sessions(&handle->sessions, create_graph, func);

	graph = graph_list;
	while (graph) {
		graph->kernel_only = opts->kernel_only;
		graph = graph->next;
	}
}

static struct uftrace_graph * get_graph(struct ftrace_task_handle *task,
					uint64_t time, uint64_t addr)
{
	struct uftrace_graph *graph;
	struct uftrace_session_link *sessions = &task->h->sessions;
	struct uftrace_session *sess;

	sess = find_task_session(sessions, task->tid, time);
	if (sess == NULL)
		sess = find_task_session(sessions, task->t->pid, time);

	if (sess == NULL) {
		struct uftrace_session *fsess = sessions->first;

		if (is_kernel_address(&fsess->symtabs, addr))
			sess = fsess;
		else
			return NULL;
	}

	graph = graph_list;
	while (graph) {
		if (graph->sess == sess)
			return graph;

		graph = graph->next;
	}
	return NULL;
}

static struct task_graph * get_task_graph(struct ftrace_task_handle *task,
					  uint64_t time, uint64_t addr)
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
	tg->lost = false;
	tg->bt_curr = NULL;

	rb_link_node(&tg->link, parent, p);
	rb_insert_color(&tg->link, &tasks);

out:
	tg->graph = get_graph(task, time, addr);
	return tg;
}

static int save_backtrace_addr(struct task_graph *tg)
{
	int i;
	int skip = 0;
	int len = tg->task->stack_count;
	uint64_t addrs[len];
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
		pr_out(" backtrace #%d: hit %d, time ", i++, bt->hit);
		print_time_unit(bt->time);
		pr_out("\n");

		for (k = 0; k < bt->len; k++) {
			sym = find_symtabs(&graph->sess->symtabs, bt->addr[k]);
			if (sym == NULL)
				sym = session_find_dlsym(graph->sess,
							 bt->time, bt->addr[k]);

			symname = symbol_getname(sym, bt->addr[k]);
			pr_out("   [%d] %s (%#lx)\n", k, symname, bt->addr[k]);
			symbol_putname(sym, symname);
		}
		pr_out("\n");
	}

	return 0;
}

static int start_graph(struct task_graph *tg)
{
	if (!tg->enabled++) {
		save_backtrace_addr(tg);

		pr_dbg("start graph\n");

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

	if (!--tg->enabled) {
		save_backtrace_time(tg);
		tg->lost = false;

		pr_dbg("end graph\n");
	}

	return 0;
}

static int add_graph_entry(struct task_graph *tg)
{
	struct graph_node *node = NULL;
	struct graph_node *curr = tg->node;
	struct uftrace_record *rstack = tg->task->rstack;

	if (curr == NULL)
		return -1;

	if (tg->lost)
		return 1;  /* ignore kernel functions after LOST */

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

	if (tg->lost) {
		if (is_kernel_address(&tg->task->h->sessions.first->symtabs,
				      fstack->addr))
			return 1;

		/*
		 * LOST only occures in kernel, so clear tg->lost
		 * when return to userspace
		 */
		tg->lost = false;
	}

	if (node->addr != fstack->addr)
		pr_dbg("broken graph - addresses not match\n");

	node->time       += fstack->total_time;
	node->child_time += fstack->child_time;

	tg->node = node->parent;

	return 0;
}

static int add_graph_event(struct task_graph *tg)
{
	struct uftrace_record *rec = tg->task->rstack;

	if (rec->addr == EVENT_ID_PERF_SCHED_OUT) {
		/* to match addr with sched-in */
		rec->addr = EVENT_ID_PERF_SCHED_IN;
		return add_graph_entry(tg);
	}
	else if (rec->addr == EVENT_ID_PERF_SCHED_IN) {
		return add_graph_exit(tg);
	}

	return -1;
}

static int add_graph(struct task_graph *tg, int type)
{
	pr_dbg2("add graph (enabled: %d) %s\n", tg->enabled,
		type == UFTRACE_ENTRY ? "ENTRY" :
		type == UFTRACE_EXIT  ? "EXIT"  : "EVENT");

	if (type == UFTRACE_ENTRY)
		return add_graph_entry(tg);
	else if (type == UFTRACE_EXIT)
		return add_graph_exit(tg);
	else if (type == UFTRACE_EVENT)
		return add_graph_event(tg);
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
			     struct graph_node *node, bool *indent_mask,
			     int indent, bool needs_line)
{
	struct sym *sym;
	char *symname;
	struct graph_node *parent = node->parent;
	struct graph_node *child;
	int orig_indent = indent;
	static struct sym sched_sym = {
		.name = "linux:schedule",
	};

	/* XXX: what if it clashes with existing function address */
	if (node->addr == EVENT_ID_PERF_SCHED_IN)
		sym = &sched_sym;
	else
		sym = find_symtabs(&graph->sess->symtabs, node->addr);

	symname = symbol_getname(sym, node->addr);

	pr_out(" ");
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
		print_graph_node(graph, child, indent_mask, indent, needs_line);

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

static int print_graph(struct uftrace_graph *graph, struct opts *opts)
{
	bool *indent_mask;

	/* skip empty graph */
	if (list_empty(&graph->bt_list) && graph->root.time == 0 &&
	    graph->root.nr_edges == 0)
		return 0;

	pr_out("#\n");
	pr_out("# function graph for '%s' (session: %.16s)\n",
	       graph->func, graph->sess->sid);
	pr_out("#\n\n");

	if (!list_empty(&graph->bt_list)) {
		pr_out("backtrace\n");
		pr_out("=====================================\n");
		print_backtrace(graph);
	}

	if (graph->root.time || graph->root.nr_edges) {
		pr_out("calling functions\n");
		pr_out("=====================================\n");
		indent_mask = xcalloc(opts->max_stack, sizeof(*indent_mask));
		print_graph_node(graph, &graph->root, indent_mask, 0,
				 graph->root.nr_edges > 1);
		free(indent_mask);
		pr_out("\n");
	}
	return 1;
}

static void build_graph_node(struct ftrace_task_handle *task, uint64_t time,
			     uint64_t addr, int type, char *func)
{
	struct task_graph *tg;
	struct sym *sym = NULL;
	char *name;

	tg = get_task_graph(task, time, addr);
	if (tg->enabled)
		add_graph(tg, type);

	/* cannot find a session for this record */
	if (tg->graph == NULL)
		return;
	if (type == UFTRACE_EVENT)
		return;

	sym = find_symtabs(&tg->graph->sess->symtabs, addr);
	name = symbol_getname(sym, addr);

	if (!strcmp(name, func)) {
		if (type == UFTRACE_ENTRY)
			start_graph(tg);
		else if (type == UFTRACE_EXIT)
			end_graph(tg);
	}

	symbol_putname(sym, name);
}

static int build_graph(struct opts *opts, struct ftrace_file_handle *handle,
		       char *func)
{
	int ret = 0;
	struct ftrace_task_handle *task;
	struct uftrace_graph *graph;
	uint64_t prev_time = 0;
	int i;

	setup_graph_list(handle, opts, func);

	while (!read_rstack(handle, &task) && !uftrace_done) {
		struct uftrace_record *frs = task->rstack;

		/* skip user functions if --kernel-only is set */
		if (opts->kernel_only && !is_kernel_record(task, frs))
			continue;

		if (opts->kernel_skip_out) {
			/* skip kernel functions outside user functions */
			if (!task->user_stack_count &&
			    is_kernel_record(task, frs))
				continue;
		}

		if (!fstack_check_filter(task))
			continue;

		if (frs->type == UFTRACE_EVENT) {
			if (frs->addr != EVENT_ID_PERF_SCHED_IN &&
			    frs->addr != EVENT_ID_PERF_SCHED_OUT)
				continue;
		}

		if (frs->type == UFTRACE_LOST) {
			struct task_graph *tg;
			struct uftrace_session *fsess;

			if (opts->kernel_skip_out && !task->user_stack_count)
				continue;

			pr_dbg("*** LOST ***\n");

			/* add partial duration of kernel functions before LOST */
			while (task->stack_count >= task->user_stack_count) {
				struct fstack *fstack;

				fstack = &task->func_stack[task->stack_count];

				if (fstack_enabled && fstack->valid &&
				    !(fstack->flags & FSTACK_FL_NORECORD)) {
					build_graph_node(task, prev_time,
							 fstack->addr,
							 UFTRACE_EXIT, func);
				}

				fstack_exit(task);
				task->stack_count--;
			}

			/* force to find a session for kernel function */
			fsess = task->h->sessions.first;
			tg = get_task_graph(task, prev_time,
					    fsess->symtabs.kernel_base + 1);
			tg->lost = true;

			if (tg->enabled && is_kernel_address(&fsess->symtabs,
							     tg->node->addr))
				pr_dbg("not returning to user after LOST\n");

			continue;
		}

		if (prev_time > frs->time) {
			pr_warn("inverted time: broken data?\n");
			return -1;
		}
		prev_time = frs->time;

		if (task->stack_count >= opts->max_stack)
			continue;

		build_graph_node(task, frs->time, frs->addr, frs->type, func);
	}

	/* add duration of remaining functions */
	for (i = 0; i < handle->nr_tasks; i++) {
		uint64_t last_time;
		struct fstack *fstack;

		task = &handle->tasks[i];

		if (task->stack_count == 0)
			continue;

		last_time = task->rstack->time;

		if (handle->time_range.stop)
			last_time = handle->time_range.stop;

		while (--task->stack_count >= 0) {
			fstack = &task->func_stack[task->stack_count];

			if (fstack->addr == 0)
				continue;

			if (fstack->total_time > last_time)
				continue;

			fstack->total_time = last_time - fstack->total_time;
			if (fstack->child_time > fstack->total_time)
				fstack->total_time = fstack->child_time;

			if (task->stack_count > 0)
				fstack[-1].child_time += fstack->total_time;

			build_graph_node(task, last_time, fstack->addr,
					 UFTRACE_EXIT, func);
		}
	}

	graph = graph_list;
	while (graph && !uftrace_done) {
		ret += print_graph(graph, opts);
		graph = graph->next;
	}

	if (!ret) {
		pr_out("uftrace: cannot find graph for '%s'\n", func);
		if (opts_has_filter(opts))
			pr_out("\t please check your filter settings.\n");
	}

	return 0;
}

struct find_func_data {
	char *name;
	bool found;
};

static int find_func(struct uftrace_session *s, void *arg)
{
	struct find_func_data *data = arg;
	struct symtabs *symtabs = &s->symtabs;

	if (find_symname(&symtabs->symtab, data->name))
		data->found = true;
	else if (find_symname(&symtabs->dsymtab, data->name))
		data->found = true;

	return data->found;
}

static void synthesize_depth_trigger(struct opts *opts,
				     struct ftrace_file_handle *handle,
				     char *func)
{
	size_t old_len = opts->trigger ? strlen(opts->trigger) : 0;
	size_t new_len = strlen(func) + 32;
	struct find_func_data ffd = {
		.name = func,
	};

	walk_sessions(&handle->sessions, find_func, &ffd);

	opts->trigger = xrealloc(opts->trigger, old_len + new_len);
	snprintf(opts->trigger + old_len, new_len,
		 "%s%s@%sdepth=%d", old_len ? ";" : "",
		 func, ffd.found ? "" : "kernel,", opts->depth);
}

int command_graph(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
	char *func;

	__fsetlocking(outfp, FSETLOCKING_BYCALLER);
	__fsetlocking(logfp, FSETLOCKING_BYCALLER);

	if (opts->idx)
		func = argv[opts->idx];
	else
		func = "main";

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open data: %s: %m\n", opts->dirname);
		return -1;
	}

	if (opts->depth != OPT_DEPTH_DEFAULT) {
		/*
		 * Applying depth filter before the function might
		 * lead to undesired result.  Set a synthetic depth
		 * trigger to prevent the function from filtering out.
		 */
		synthesize_depth_trigger(opts, &handle, func);
	}

	fstack_setup_filters(opts, &handle);

	ret = build_graph(opts, &handle, func);

	close_data_file(opts, &handle);

	return ret;
}
