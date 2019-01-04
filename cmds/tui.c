#ifdef HAVE_LIBNCURSES

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ncurses.h>
#include <locale.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "uftrace.h"
#include "version.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "utils/graph.h"
#include "utils/report.h"
#include "utils/list.h"
#include "utils/rbtree.h"
#include "utils/field.h"
#include "utils/dwarf.h"

#define KEY_ESCAPE  27

static bool tui_finished;
static bool tui_debug;

struct tui_graph_node {
	struct uftrace_graph_node n;
	struct uftrace_graph *graph;
	struct list_head link; // for tui_report_node.head
	bool folded;
};

struct tui_report_node {
	struct uftrace_report_node n;
	struct list_head head; // links tui_graph_node.link
};

struct tui_list_node {
	struct list_head list;
	void *data;
};

struct tui_window;

struct tui_window_ops {
	void * (*prev)(struct tui_window *win, void *node, bool update);
	void * (*next)(struct tui_window *win, void *node, bool update);
	void * (*top)(struct tui_window *win, bool update);
	void * (*parent)(struct tui_window *win, void *node);
	void * (*sibling_prev)(struct tui_window *win, void *node);
	void * (*sibling_next)(struct tui_window *win, void *node);
	bool (*needs_blank)(struct tui_window *win, void *prev, void *next);
	bool (*enter)(struct tui_window *win, void *node);
	bool (*collapse)(struct tui_window *win, void *node, bool all, int depth);
	bool (*expand)(struct tui_window *win, void *node, bool all, int depth);
	void (*header)(struct tui_window *win, struct uftrace_data *handle);
	void (*footer)(struct tui_window *win, struct uftrace_data *handle);
	void (*display)(struct tui_window *win, void *node);
	bool (*search)(struct tui_window *win, void *node, char *str);
	bool (*longest_child)(struct tui_window *win, void *node);
	struct debug_location * (*location)(struct tui_window *win, void *node);
};

struct tui_window {
	const struct tui_window_ops *ops;
	void *top;
	void *curr;
	void *old;
	int top_index;
	int curr_index;
	int search_count;
};

struct tui_report {
	struct tui_window win;
	struct list_head list;
	struct rb_root name_tree;
	struct rb_root sort_tree;
	int nr_sess;
	int nr_func;
};

struct tui_graph {
	struct tui_window win;
	struct uftrace_graph ug;
	struct list_head list;
	struct tui_graph_node *disp;
	int top_depth;
	int curr_depth;
	int disp_depth;
	int width;
	bool *top_mask;
	bool *disp_mask;
	size_t mask_size;
	bool disp_update;
};

struct tui_list {
	struct tui_window win;
	struct list_head head;
	int nr_node;
};

static LIST_HEAD(tui_graph_list);
static LIST_HEAD(graph_output_fields);
static struct tui_report tui_report;
static struct tui_graph partial_graph;
static struct tui_list tui_info;
static struct tui_list tui_session;
static char *tui_search;

static const struct tui_window_ops graph_ops;
static const struct tui_window_ops report_ops;
static const struct tui_window_ops info_ops;
static const struct tui_window_ops session_ops;

static void tui_window_move_down(struct tui_window *win);

#define FIELD_SPACE  2
#define FIELD_SEP  " :"

#define C_NORMAL  0
#define C_HEADER  1
#define C_GREEN   2
#define C_YELLOW  3
#define C_RED     4

static const char *help[] = {
	"ARROW         Navigation",
	"PgUp/Dn",
	"Home/End",
	"Enter         Fold/unfold graph or Select session",
	"G             Show (full) call graph",
	"g             Show call graph for this function",
	"R             Show uftrace report",
	"r             Show uftrace report for this function",
	"I             Show uftrace info",
	"S             Change session",
	"O             Open editor",
	"c/e           Collapse/Expand direct children graph",
	"C/E           Collapse/Expand all descendant graph",
	"n/p           Next/Prev sibling",
	"u             Move up to parent",
	"l             Move to the longest executed child",
	"j/k           Move down/up",
	"z             Set current line to the center of screen",
	"/             Search",
	"</>/N/P       Search next/prev",
	"v             Show debug message",
	"h/?           Show this help",
	"q             Quit",
};

static void init_colors(void)
{
	if (!has_colors())
		return;

	start_color();

	/* C_NORMAL uses the default color pair */
	init_pair(C_HEADER, COLOR_WHITE,  COLOR_BLUE);
	init_pair(C_GREEN,  COLOR_GREEN,  COLOR_BLACK);
	init_pair(C_YELLOW, COLOR_YELLOW, COLOR_BLACK);
	init_pair(C_RED,    COLOR_RED,    COLOR_BLACK);
}

static void print_time(uint64_t ntime)
{
	char *units[] = { "us", "ms", " s", " m", " h", };
	int pairs[] = { C_NORMAL, C_GREEN, C_YELLOW, C_RED, C_RED };
	unsigned limit[] = { 1000, 1000, 1000, 60, 24, INT_MAX, };
	uint64_t fract;
	unsigned idx;

	if (ntime == 0UL) {
		printw("%7s %2s", "", "");
		return;
	}

	for (idx = 0; idx < ARRAY_SIZE(units); idx++) {
		fract = ntime % limit[idx];
		ntime = ntime / limit[idx];

		if (ntime < limit[idx+1])
			break;
	}

	/* for some error cases */
	if (ntime > 999)
		ntime = fract = 999;

	printw("%3"PRIu64".%03"PRIu64" ", ntime, fract);
	attron(COLOR_PAIR(pairs[idx]));
	printw("%2s", units[idx]);
	attroff(COLOR_PAIR(pairs[idx]));
}

static void print_graph_total(struct field_data *fd)
{
	struct uftrace_graph_node *node = fd->arg;
	uint64_t d;

	d = node->time;

	print_time(d);
}

static void print_graph_self(struct field_data *fd)
{
	struct uftrace_graph_node *node = fd->arg;
	uint64_t d;

	d = node->time - node->child_time;

	print_time(d);
}

static void print_graph_addr(struct field_data *fd)
{
	struct uftrace_graph_node *node = fd->arg;

	/* uftrace records (truncated) 48-bit addresses */
	int width = sizeof(long) == 4 ? 8 : 12;

	printw("%*lx", width, node->addr);
}

static struct display_field field_total_time= {
	.id      = GRAPH_F_TOTAL_TIME,
	.name    = "total-time",
	.alias   = "total",
	.header  = "TOTAL TIME",
	.length  = 10,
	.print   = print_graph_total,
	.list    = LIST_HEAD_INIT(field_total_time.list),
};

static struct display_field field_self_time= {
	.id      = GRAPH_F_SELF_TIME,
	.name    = "self-time",
	.alias   = "self",
	.header  = " SELF TIME",
	.length  = 10,
	.print   = print_graph_self,
	.list    = LIST_HEAD_INIT(field_self_time.list),
};

static struct display_field field_addr = {
	.id      = GRAPH_F_ADDR,
	.name    = "address",
	.alias   = "addr",
#if __SIZEOF_LONG == 4
	.header  = "  ADDR  ",
	.length  = 8,
#else
	.header  = "   ADDRESS  ",
	.length  = 12,
#endif
	.print   = print_graph_addr,
	.list    = LIST_HEAD_INIT(field_addr.list),
};

/* index of this table should be matched to display_field_id */
static struct display_field *graph_field_table[] = {
	&field_total_time,
	&field_self_time,
	&field_addr,
};

static void setup_default_graph_field(struct list_head *fields, struct opts *opts)
{
	add_field(fields, graph_field_table[GRAPH_F_TOTAL_TIME]);
}

static inline bool is_first_child(struct tui_graph_node *prev,
				  struct tui_graph_node *next)
{
	return prev->n.head.next == &next->n.list;
}

static inline bool is_last_child(struct tui_graph_node *prev,
				 struct tui_graph_node *next)
{
	return prev->n.head.prev == &next->n.list;
}

static int create_data(struct uftrace_session *sess, void *arg)
{
	struct tui_graph *graph = xzalloc(sizeof(*graph));

	pr_dbg("create graph for session %.*s (%s)\n",
	       SESSION_ID_LEN, sess->sid, sess->exename);

	graph_init(&graph->ug, sess);

	list_add_tail(&graph->list, &tui_graph_list);

	tui_report.nr_sess++;

	return 0;
}

static void tui_setup(struct uftrace_data *handle, struct opts *opts)
{
	walk_sessions(&handle->sessions, create_data, NULL);

	tui_report.name_tree = RB_ROOT;

	setup_field(&graph_output_fields, opts, setup_default_graph_field,
		    graph_field_table, ARRAY_SIZE(graph_field_table));
}

static void tui_cleanup(void)
{
	struct tui_graph *graph;

	if (!tui_finished)
		endwin();

	tui_finished = true;

	while (!list_empty(&tui_graph_list)) {
		graph = list_first_entry(&tui_graph_list, typeof(*graph), list);
		list_del(&graph->list);
		free(graph);
	}
	graph_remove_task();
}

static struct uftrace_graph * get_graph(struct uftrace_task_reader *task,
					uint64_t time, uint64_t addr)
{
	struct tui_graph *graph;
	struct uftrace_session_link *sessions = &task->h->sessions;
	struct uftrace_session *sess;

	sess = find_task_session(sessions, task->t, time);
	if (sess == NULL) {
		struct uftrace_session *fsess = sessions->first;

		if (is_kernel_address(&fsess->symtabs, addr))
			sess = fsess;
		else
			return NULL;
	}

	list_for_each_entry(graph, &tui_graph_list, list) {
		if (graph->ug.sess == sess)
			return &graph->ug;
	}
	return NULL;
}

static bool list_is_none(struct list_head *list)
{
	return list->next == NULL && list->prev == NULL;
}

static void update_report_node(struct uftrace_task_reader *task, char *symname,
			       struct uftrace_task_graph *tg)
{
	struct tui_report_node *node;
	struct tui_graph_node *graph_node;

	/* graph is not set probably due to filters (or error?) */
	if (tg->node == NULL)
		return;

	node = (struct tui_report_node *)report_find_node(&tui_report.name_tree,
							  symname);
	if (node == NULL) {
		node = xzalloc(sizeof(*node));
		INIT_LIST_HEAD(&node->head);
		report_add_node(&tui_report.name_tree, symname, (void *)node);
		tui_report.nr_func++;
	}

	graph_node = (struct tui_graph_node *)tg->node;
	if (list_is_none(&graph_node->link))
		list_add_tail(&graph_node->link, &node->head);

	report_update_node(&node->n, task);
}

static int build_tui_node(struct uftrace_task_reader *task,
			  struct uftrace_record *rec)
{
	struct uftrace_task_graph *tg;
	struct uftrace_graph *graph;
	struct tui_graph_node *graph_node;
	struct sym *sym;
	char *name;
	uint64_t addr = rec->addr;

	tg = graph_get_task(task, sizeof(*tg));
	graph = get_graph(task, rec->time, rec->addr);

	if (tg->node == NULL || tg->graph != graph)
		tg->node = &graph->root;

	tg->graph = graph;

	if (is_kernel_record(task, rec)) {
		struct uftrace_session *fsess;

		fsess = task->h->sessions.first;
		addr = get_kernel_address(&fsess->symtabs, addr);
	}

	if (rec->type == UFTRACE_ENTRY || rec->type == UFTRACE_EXIT) {
		sym = task_find_sym_addr(&task->h->sessions,
					 task, rec->time, addr);
		name = symbol_getname(sym, addr);

		if (rec->type == UFTRACE_EXIT)
			update_report_node(task, name, tg);
	}
	else if (rec->type == UFTRACE_EVENT) {
		sym = &sched_sym;
		name = symbol_getname(sym, addr);

		if (addr == EVENT_ID_PERF_SCHED_IN)
			update_report_node(task, name, tg);
		else if (addr != EVENT_ID_PERF_SCHED_OUT)
			return 0;
	}
	else  /* rec->type == UFTRACE_LOST */
		return 0;

	graph_add_node(tg, rec->type, name, sizeof(struct tui_graph_node));
	if (tg->node && tg->node != &graph->root) {
		graph_node = (struct tui_graph_node *)tg->node;
		graph_node->graph = graph;
	}

	symbol_putname(sym, name);
	return 0;
}

static void add_remaining_node(struct opts *opts, struct uftrace_data *handle)
{
	uint64_t last_time;
	struct fstack *fstack;
	struct uftrace_task_reader *task;
	struct uftrace_task_graph *tg;
	struct sym *sym;
	char *name;
	int i;

	for (i = 0; i < handle->nr_tasks; i++) {
		task = &handle->tasks[i];

		if (task->stack_count == 0)
			continue;

		if (opts->kernel_skip_out && task->user_stack_count == 0)
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

			tg = graph_get_task(task, sizeof(*tg));
			sym = task_find_sym_addr(&handle->sessions,
						 task, fstack->total_time,
						 fstack->addr);
			name = symbol_getname(sym, fstack->addr);

			fstack->total_time = last_time - fstack->total_time;
			if (fstack->child_time > fstack->total_time)
				fstack->total_time = fstack->child_time;

			if (task->stack_count > 0)
				fstack[-1].child_time += fstack->total_time;

			update_report_node(task, name, tg);
			graph_add_node(tg, UFTRACE_EXIT, name,
				       sizeof(struct tui_graph_node));

			symbol_putname(sym, name);
		}
	}
}

static struct tui_graph_node * append_graph_node(struct uftrace_graph_node *dst,
						 struct tui_graph *graph,
						 char *name)
{
	struct tui_graph_node *node;

	node = xzalloc(sizeof(*node));

	node->n.name = xstrdup(name);
	INIT_LIST_HEAD(&node->n.head);

	node->n.parent = dst;
	node->graph = &graph->ug;
	list_add_tail(&node->n.list, &dst->head);
	dst->nr_edges++;

	return node;
}

static void copy_graph_node(struct uftrace_graph_node *dst,
			    struct uftrace_graph_node *src)
{
	struct uftrace_graph_node *child;
	struct tui_graph_node *node;

	list_for_each_entry(child, &src->head, list) {
		list_for_each_entry(node, &dst->head, n.list) {
			if (!strcmp(child->name, node->n.name))
				break;
		}

		if (list_no_entry(node, &dst->head, n.list)) {
			struct tui_graph *graph;

			node = (struct tui_graph_node *)src;
			graph = container_of(node->graph, typeof(*graph), ug);

			node = append_graph_node(dst, graph,
						 child->name);
		}

		node->n.addr        = child->addr;
		node->n.time       += child->time;
		node->n.child_time += child->child_time;
		node->n.nr_calls   += child->nr_calls;

		copy_graph_node(&node->n, child);
	}
}

static void tui_window_init(struct tui_window *win,
			    const struct tui_window_ops *ops)
{
	void *top = ops->top(win, true);

	win->ops = ops;
	win->top = top;
	win->curr = win->old = top;
	win->top_index = win->curr_index = 0;
}

static struct tui_graph * tui_graph_init(struct opts *opts)
{
	struct tui_graph *graph;
	struct uftrace_graph_node *top, *node;

	list_for_each_entry(graph, &tui_graph_list, list) {
		/* top (root) is an artificial node, fill the info */
		top = &graph->ug.root;
		top->name = basename(graph->ug.sess->exename);
		top->nr_calls = 1;

		list_for_each_entry(node, &graph->ug.root.head, list) {
			top->time       += node->time;
			top->child_time += node->time;
		}

		tui_window_init(&graph->win, &graph_ops);

		graph->mask_size = sizeof(*graph->top_mask) * opts->max_stack;

		graph->top_mask  = xzalloc(graph->mask_size);
		graph->disp_mask = xmalloc(graph->mask_size);
	}

	graph = list_first_entry(&tui_graph_list, typeof(*graph), list);

	partial_graph.mask_size = graph->mask_size;
	partial_graph.top_mask  = xzalloc(graph->mask_size);
	partial_graph.disp_mask = xmalloc(graph->mask_size);

	tui_window_init(&partial_graph.win, &graph_ops);

	INIT_LIST_HEAD(&partial_graph.ug.root.head);
	INIT_LIST_HEAD(&partial_graph.ug.special_nodes);

	/* select first session */
	partial_graph.ug.sess = graph->ug.sess;

	return graph;
}

static void tui_graph_finish(void)
{
	struct tui_graph *graph;

	list_for_each_entry(graph, &tui_graph_list, list) {
		graph_destroy(&graph->ug);
		free(graph->top_mask);
		free(graph->disp_mask);
	}

	graph_destroy(&partial_graph.ug);
	free(partial_graph.top_mask);
	free(partial_graph.disp_mask);
}

static void build_partial_graph(struct tui_report_node *root_node,
				struct tui_graph *target)
{
	struct tui_graph *graph = &partial_graph;
	struct tui_graph_node *root, *node;
	char *str;

	graph_destroy(&graph->ug);

	graph->ug.sess = target->ug.sess;

	xasprintf(&str, "=== Function Call Graph for '%s' ===", root_node->n.name);

	root = (struct tui_graph_node*) &graph->ug.root;
	root->n.name = str;
	root->n.parent = NULL;

	root->n.time       = 0;
	root->n.child_time = 0;
	root->n.nr_calls   = 0;

	/* special node */
	root = append_graph_node(&graph->ug.root, target,
				 "========== Back-trace ==========");

	list_for_each_entry(node, &root_node->head, link) {
		struct tui_graph_node *tmp, *parent;
		int n = 0;

		if (node->graph != &target->ug)
			continue;

		tmp = root;
		parent = node;

		while (parent->n.parent) {
			tmp = append_graph_node(&tmp->n, target, parent->n.name);

			tmp->n.addr       = parent->n.addr;
			tmp->n.time       = node->n.time;
			tmp->n.child_time = node->n.child_time;
			tmp->n.nr_calls   = node->n.nr_calls;

			/* fold backtrace at the first child */
			if (n++ == 1)
				tmp->folded = true;

			parent = (void *)parent->n.parent;
		}

		/* but, unfoled it if it's the last child */
		if (n == 2)
			tmp->folded = false;
	}

	/* special node */
	root = append_graph_node(&graph->ug.root, target,
				 "========== Call Graph ==========");

	root = append_graph_node(&root->n, target, root_node->n.name);

	list_for_each_entry(node, &root_node->head, link) {
		if (node->graph != &target->ug)
			continue;

		root->n.addr        = node->n.addr;
		root->n.time       += node->n.time;
		root->n.child_time += node->n.child_time;
		root->n.nr_calls   += node->n.nr_calls;

		copy_graph_node(&root->n, &node->n);
	}

	tui_window_init(&graph->win, &graph_ops);

	memset(graph->top_mask, 0, graph->mask_size);
}

static inline bool is_special_node(struct uftrace_graph_node *node)
{
	return node->name[0] == '=';
}

static struct tui_graph_node * graph_prev_node(struct tui_graph_node *node,
					       int *depth, bool *indent_mask)
{
	struct uftrace_graph_node *n = &node->n;
	struct tui_graph_node *parent = (void *)n->parent;

	/* root node */
	if (parent == NULL) {
		*depth = 0;
		return NULL;
	}

	/* simple case: if it's the first child, move to the parent */
	if (is_first_child(parent, node)) {
		if (!list_is_singular(&n->parent->head) && *depth > 0) {
			*depth -= 1;
			if (indent_mask)
				indent_mask[*depth] = false;
		}
		n = n->parent;
		goto out;
	}

	/* move to sibling */
	n = list_prev_entry(n, list);
	node = (struct tui_graph_node *)n;

	/* if it has children, move to the last child */
	while (!list_empty(&n->head) && !node->folded) {
		if (!list_is_singular(&n->head)) {
			if (indent_mask)
				indent_mask[*depth] = false;
			*depth += 1;
		}

		n = list_last_entry(&n->head, typeof(*n), list);
		node = (struct tui_graph_node *)n;
	}

out:
	if (n->parent && !list_is_singular(&n->parent->head)) {
		if (indent_mask && *depth > 0)
			indent_mask[*depth - 1] = true;
	}

	return (struct tui_graph_node *)n;
}

static struct tui_graph_node * graph_next_node(struct tui_graph_node *node,
					       int *depth, bool *indent_mask)
{
	struct uftrace_graph_node *n = &node->n;
	struct tui_graph_node *parent = (void *)n->parent;

	if (parent && !list_is_singular(&n->parent->head) &&
	    is_last_child(parent, node) && indent_mask && *depth > 0)
		indent_mask[*depth - 1] = false;

	/* simple case: if it has children, move to it */
	if (!list_empty(&n->head) && (parent == NULL || !node->folded)) {
		if (!list_is_singular(&n->head)) {
			if (indent_mask)
				indent_mask[*depth] = true;
			*depth += 1;
		}

		n = list_first_entry(&n->head, typeof(*n), list);

		if (is_special_node(n))
			*depth = 0;
		return (struct tui_graph_node *)n;
	}

	/* parent should not be folded */
	while (n->parent != NULL) {
		parent = (struct tui_graph_node *)n->parent;

		/* move to sibling if possible */
		if (!is_last_child(parent, (void *)n)) {
			n = list_next_entry(n, list);

			if (is_special_node(n))
				*depth = 0;
			return (struct tui_graph_node *)n;
		}

		/* otherwise look up parent */
		n = n->parent;
		if (!list_is_singular(&n->head) && *depth > 0) {
			*depth -= 1;
			if (indent_mask)
				indent_mask[*depth] = false;
		}
	}

	return NULL;
}

/* per-window operations for graph window */
static void * win_top_graph(struct tui_window *win, bool update)
{
	struct tui_graph *graph = (struct tui_graph *)win;

	if (update)
		graph->top_depth = 0;

	return &graph->ug.root;
}

static void * win_prev_graph(struct tui_window *win, void *node, bool update)
{
	void *prev;
	int depth;
	struct tui_graph *graph = (struct tui_graph *)win;

	if (update)
		prev = graph_prev_node(node, &graph->top_depth, graph->top_mask);
	else
		prev = graph_prev_node(node, &depth, NULL);

	return prev;
}

static void * win_next_graph(struct tui_window *win, void *node, bool update)
{
	void *next;
	int depth;
	struct tui_graph *graph = (struct tui_graph *)win;

	if (update) {
		/* update top node for new page */
		next = graph_next_node(node, &graph->top_depth, graph->top_mask);
	}
	else if (graph->disp_update) {
		/* update display node for next */
		next = graph_next_node(node, &graph->disp_depth,
				       graph->disp_mask);
		graph->disp = next;
	}
	else {
		next = graph_next_node(node, &depth, NULL);
	}

	return next;
}

static bool win_needs_blank_graph(struct tui_window *win, void *prev, void *next)
{
	return !is_first_child(prev, next);
}

static void * win_sibling_prev_graph(struct tui_window *win, void *node)
{
	struct uftrace_graph_node *curr = node;
	struct uftrace_graph_node *parent = curr->parent;

	if (parent == NULL)
		return NULL;

	if (list_first_entry(&parent->head, typeof(*curr), list) == curr)
		return NULL;

	return list_prev_entry(curr, list);
}

static void * win_sibling_next_graph(struct tui_window *win, void *node)
{
	struct uftrace_graph_node *curr = node;
	struct uftrace_graph_node *parent = curr->parent;

	if (parent == NULL)
		return NULL;

	if (list_last_entry(&parent->head, typeof(*curr), list) == curr)
		return NULL;

	return list_next_entry(curr, list);
}

static void * win_parent_graph(struct tui_window *win, void *node)
{
	struct uftrace_graph_node *curr = node;

	return curr->parent;
}

static bool win_enter_graph(struct tui_window *win, void *node)
{
	struct tui_graph_node *curr = node;

	/* root node is not foldable */
	if (curr->n.parent == NULL)
		return false;

	if (list_empty(&curr->n.head))
		return false;

	curr->folded = !curr->folded;
	return true;
}

static int fold_graph_node(struct tui_graph_node *node, bool fold,
			   bool all, int depth)
{
	struct tui_graph_node *child;
	int count = 0;
	bool curr_fold = fold;

	if (!all && depth < 0)
		return 0;
	else if (depth > 0)
		curr_fold = false;

	/* do not fold leaf nodes - it's meaningless but confusing */
	if (list_empty(&node->n.head))
		return 0;

	if (node->folded != curr_fold) {
		node->folded = curr_fold;
		count++;
	}

	list_for_each_entry(child, &node->n.head, n.list)
		count += fold_graph_node(child, fold, all, depth - 1);

	return count;
}

static bool win_collapse_graph(struct tui_window *win, void *node, bool all,
			       int depth)
{
	return fold_graph_node(node, true, all, depth);
}

static bool win_expand_graph(struct tui_window *win, void *node, bool all,
			     int depth)
{
	return fold_graph_node(node, false, all, depth);
}

static void win_header_graph(struct tui_window *win,
			     struct uftrace_data *handle)
{
	int w = 0, c;
	char *buf, *p;
	struct tui_graph *graph = (struct tui_graph *)win;
	struct display_field *field;

	/* calculate width for fields */
	list_for_each_entry(field, &graph_output_fields, list) {
		w += field->length + FIELD_SPACE;
	}
	if (!list_empty(&graph_output_fields))
		w += strlen(FIELD_SEP);

	graph->width = w;

	w += strlen(" FUNCTION");

	if (list_empty(&graph_output_fields)) {
		printw("%-*.*s", COLS, COLS, "uftrace graph TUI");
		goto out;
	}

	buf = p = xmalloc(w + 1);

	list_for_each_entry(field, &graph_output_fields, list) {
		c = snprintf(p, w, "%*s%*s", FIELD_SPACE, "",
			     field->length, field->header);
		p += c;
		w -= c;
	}
	snprintf(p, w+1, "%s %s", FIELD_SEP, "FUNCTION");

	printw("%-*.*s", COLS, COLS, buf);
	free(buf);

out:
	/* start with same make as top */
	graph->disp = graph->win.top;
	graph->disp_depth = graph->top_depth;
	graph->disp_update = true;
	memcpy(graph->disp_mask, graph->top_mask, graph->mask_size);
}

static void win_footer_graph(struct tui_window *win,
			     struct uftrace_data *handle)
{
	char buf[COLS + 1];
	struct tui_graph *graph = (struct tui_graph *)win;
	struct tui_graph_node *node = win->curr;
	struct uftrace_session *sess = graph->ug.sess;

	if (tui_debug) {
		snprintf(buf, COLS, "uftrace graph: top: %d depth: %d, curr: %d depth: %d",
			 graph->win.top_index, graph->top_depth,
			 graph->win.curr_index, graph->curr_depth);
	}
	else if (tui_search) {
		snprintf(buf, COLS, "uftrace graph: searching \"%s\"  (%d match, %s)",
			 tui_search, graph->win.search_count,
			 "use '<' and '>' keys to navigate");
	}
	else {
		struct debug_location *dloc;

		dloc = win->ops->location(win, win->curr);

		if (dloc != NULL && dloc->file != NULL) {
			snprintf(buf, COLS, "uftrace graph: %s [line:%d]",
				 dloc->file->name, dloc->line);
		}
		else if (find_symtabs(&sess->symtabs, node->n.addr) != NULL) {
			/* some symbols don't have source location */
			snprintf(buf, COLS, "uftrace graph: %s [at %#"PRIx64"]",
				 "source location is not available",
				 node->n.addr);
		}
		else {
			snprintf(buf, COLS, "uftrace graph: session %.*s (%s)",
				 SESSION_ID_LEN, sess->sid, sess->exename);
		}
	}
	buf[COLS] = '\0';

	printw("%-*s", COLS, buf);

	graph->disp_update = false;
}

static void print_graph_field(struct uftrace_graph_node *node)
{
	struct display_field *field;
	struct field_data fd = {
		.arg = node,
	};

	if (list_empty(&graph_output_fields))
		return;

	list_for_each_entry(field, &graph_output_fields, list) {
		printw("%*s", FIELD_SPACE, "");
		field->print(&fd);
	}
	printw(FIELD_SEP);
}

static void print_graph_empty(void)
{
	struct display_field *field;

	if (list_empty(&graph_output_fields))
		return;

	list_for_each_entry(field, &graph_output_fields, list)
		printw("%*s", field->length + FIELD_SPACE, "");

	printw(FIELD_SEP);
}

static void print_graph_indent(struct tui_graph *graph,
			       struct tui_graph_node *node,
			       int depth, bool single_child)
{
	int i;
	struct tui_graph_node *parent = (void *)node->n.parent;

	for (i = 0; i < depth; i++) {
		if (!graph->disp_mask[i]) {
			printw("   ");
			continue;
		}

		if (i < depth - 1 || single_child)
			printw("  │");
		else if (is_last_child(parent, node))
			printw("  └");
		else
			printw("  ├");
	}
}

static void win_display_graph(struct tui_window *win, void *node)
{
	struct tui_graph *graph = (struct tui_graph *)win;
	struct tui_graph_node *curr = node;
	struct tui_graph_node *parent;
	int d = graph->disp_depth;
	int w = graph->width;
	const char *fold_sign;
	bool single_child = false;
	int width;

	if (node == NULL) {
		print_graph_empty();
		print_graph_indent(graph, graph->disp, d, true);
		return;
	}

	fold_sign = curr->folded ? "▶" : "─";

	parent = win_parent_graph(win, node);
	if (parent == NULL)
		fold_sign = " ";
	else if (list_is_singular(&parent->n.head)) {
		single_child = true;
		if (!curr->folded)
			fold_sign = " ";
	}

	print_graph_field(&curr->n);
	print_graph_indent(graph, curr, d, single_child);

	width = d * 3 + w;

	if (is_special_node(&curr->n)) {
		width = COLS - width;
		if (width > 0)
			printw("%-*.*s", width, width, curr->n.name);
	}
	else {
		char buf[32];

		/* 4 = fold_sign(1) + parenthesis92) + space(1) */
		width += snprintf(buf, sizeof(buf),
				  "%d", curr->n.nr_calls) + 4;
		width = COLS - width;

		if (width > 0) {
			printw("%s(%d) %-*.*s", fold_sign, curr->n.nr_calls,
			       width, width, curr->n.name);
		}
	}
}

static bool win_search_graph(struct tui_window *win, void *node, char *str)
{
	struct tui_graph_node *curr = node;

	return strstr(curr->n.name, str);
}

static bool win_longest_child_graph(struct tui_window *win, void *node)
{
	struct tui_graph_node *curr = node;
	struct tui_graph_node *child;
	struct tui_graph_node *longest_child = NULL;
	uint64_t longest_child_time = 0;

	curr->folded = false;

	list_for_each_entry(child, &curr->n.head, n.list) {
		fold_graph_node(child, true, false, 0);
		if (longest_child_time < child->n.time) {
			longest_child_time = child->n.time;
			longest_child = child;
		}
	}

	if (longest_child == NULL)
		return false;

	longest_child->folded = false;
	while (win->curr != longest_child)
		tui_window_move_down(win);

	return true;
}

static struct debug_location *win_location_graph(struct tui_window *win,
						 void *node)
{
	struct tui_graph *graph = (struct tui_graph *)win;
	struct tui_graph_node *curr = node;
	struct uftrace_session *sess = graph->ug.sess;

	return find_file_line(&sess->symtabs, curr->n.addr);
}

static const struct tui_window_ops graph_ops = {
	.prev = win_prev_graph,
	.next = win_next_graph,
	.top = win_top_graph,
	.parent = win_parent_graph,
	.sibling_prev = win_sibling_prev_graph,
	.sibling_next = win_sibling_next_graph,
	.needs_blank = win_needs_blank_graph,
	.enter = win_enter_graph,
	.collapse = win_collapse_graph,
	.expand = win_expand_graph,
	.header = win_header_graph,
	.footer = win_footer_graph,
	.display = win_display_graph,
	.search = win_search_graph,
	.longest_child = win_longest_child_graph,
	.location = win_location_graph,
};

/* some default (no-op) window operations */
static bool win_needs_blank_no(struct tui_window *win, void *prev, void *next)
{
	return false;
}

static void * win_sibling_prev_no(struct tui_window *win, void *node)
{
	return win->ops->prev(win, node, false);
}

static void * win_sibling_next_no(struct tui_window *win, void *node)
{
	return win->ops->next(win, node, false);
}

static void * win_parent_no(struct tui_window *win, void *node)
{
	return NULL;
}

/* per-window operations for report window */
static struct tui_report * tui_report_init(struct opts *opts)
{
	struct tui_window *win = &tui_report.win;

	report_setup_sort("total");
	report_sort_nodes(&tui_report.name_tree, &tui_report.sort_tree);
	tui_window_init(win, &report_ops);

	return &tui_report;
}

static void tui_report_finish(void)
{
}

static void * win_top_report(struct tui_window *win, bool update)
{
	struct tui_report *report = (struct tui_report *)win;
	struct rb_node *node = rb_first(&report->sort_tree);

	return rb_entry(node, struct tui_report_node, n.sort_link);
}

static void * win_prev_report(struct tui_window *win, void *node, bool update)
{
	struct tui_report_node *curr = node;
	struct rb_node *rbnode = rb_prev(&curr->n.sort_link);

	if (rbnode == NULL)
		return NULL;

	return rb_entry(rbnode, struct tui_report_node, n.sort_link);
}

static void * win_next_report(struct tui_window *win, void *node, bool update)
{
	struct tui_report_node *curr = node;
	struct rb_node *rbnode = rb_next(&curr->n.sort_link);

	if (rbnode == NULL)
		return NULL;

	return rb_entry(rbnode, struct tui_report_node, n.sort_link);
}

static bool win_search_report(struct tui_window *win, void *node, char *str)
{
	struct tui_report_node *curr = node;

	return strstr(curr->n.name, str);
}

static void win_header_report(struct tui_window *win, struct uftrace_data *handle)
{
	int w = 46;

	printw("  %10s  %10s  %10s  %s", "Total Time", "Self Time", "Calls", "Function");
	if (COLS > w)
		printw("%*s", COLS - w, "");
}

static void win_footer_report(struct tui_window *win, struct uftrace_data *handle)
{
	char buf[COLS + 1];

	if (tui_debug) {
		snprintf(buf, COLS, "uftrace report: top: %d, curr: %d",
			 win->top_index, win->curr_index);
	}
	else if (tui_search) {
		snprintf(buf, COLS, "uftrace report: searching \"%s\"  (%d match, %s)",
			 tui_search, win->search_count, "use '<' and '>' keys to navigate");
	}
	else {
		struct debug_location *dloc;

		dloc = win->ops->location(win, win->curr);

		if (dloc != NULL && dloc->file != NULL) {
			snprintf(buf, COLS, "uftrace report: %s [line:%d]",
				 dloc->file->name, dloc->line);
		}
		else {
			struct tui_report *report = (struct tui_report *)win;

			snprintf(buf, COLS, "uftrace report: %s (%d sessions, %d functions)",
				 handle->dirname, report->nr_sess, report->nr_func);
		}
	}
	buf[COLS] = '\0';

	printw("%-*.*s", COLS, COLS, buf);
}

static void win_display_report(struct tui_window *win, void *node)
{
	struct tui_report_node *curr = node;
	int width = 38;  /* 3 output fields and spaces */

	printw("  ");
	print_time(curr->n.total.sum);
	printw("  ");
	print_time(curr->n.self.sum);
	printw("  ");
	printw("%10u", curr->n.call);
	printw("  ");

	printw("%-*.*s", COLS - width, COLS - width, curr->n.name);
}

static struct debug_location *win_location_report(struct tui_window *win,
						  void *node)
{
	struct tui_report_node *curr = node;
	struct tui_graph_node *gnode;
	struct uftrace_session *sess;
	struct debug_location *dloc;

	list_for_each_entry(gnode, &curr->head, link) {
		sess = gnode->graph->sess;
		dloc = find_file_line(&sess->symtabs, gnode->n.addr);

		if (dloc != NULL && dloc->file != NULL)
			return dloc;
	}
	return NULL;
}

static const struct tui_window_ops report_ops = {
	.prev = win_prev_report,
	.next = win_next_report,
	.top = win_top_report,
	.parent = win_parent_no,
	.sibling_prev = win_sibling_prev_no,
	.sibling_next = win_sibling_next_no,
	.needs_blank = win_needs_blank_no,
	.header = win_header_report,
	.footer = win_footer_report,
	.display = win_display_report,
	.search = win_search_report,
	.location = win_location_report,
};

/* per-window operations for list window */
static void * win_top_list(struct tui_window *win, bool update)
{
	struct tui_list *list = (struct tui_list *)win;

	return list_first_entry(&list->head, struct tui_list_node, list);
}

static void * win_prev_list(struct tui_window *win, void *node, bool update)
{
	struct tui_list *list = (struct tui_list *)win;

	if (list_first_entry(&list->head, struct tui_list_node, list) == node)
		return NULL;

	return list_prev_entry((struct tui_list_node *)node, list);
}

static void * win_next_list(struct tui_window *win, void *node, bool update)
{
	struct tui_list *list = (struct tui_list *)win;

	if (list_last_entry(&list->head, struct tui_list_node, list) == node)
		return NULL;

	return list_next_entry((struct tui_list_node *)node, list);
}

/* per-window operations for info window */
static void build_info_node(void *data, const char *fmt, ...)
{
	va_list ap;
	struct tui_list *info = data;
	struct tui_list_node *node;
	char *str = NULL;

	node = xmalloc(sizeof(*node));

	va_start(ap, fmt);
	xvasprintf(&str, fmt, ap);
	va_end(ap);

	/* remove trailing newline */
	str[strlen(str) - 1] = '\0';

	node->data = str;
	list_add_tail(&node->list, &info->head);
}

static struct tui_list * tui_info_init(struct opts *opts,
				       struct uftrace_data *handle)
{
	INIT_LIST_HEAD(&tui_info.head);
	process_uftrace_info(handle, opts, build_info_node, &tui_info);

	tui_window_init(&tui_info.win, &info_ops);
			
	return &tui_info;
}

static void tui_info_finish(void)
{
	struct tui_list_node *node, *tmp;

	list_for_each_entry_safe(node, tmp, &tui_info.head, list) {
		list_del(&node->list);
		free(node->data);
		free(node);
	}
}

static void win_header_info(struct tui_window *win,
			    struct uftrace_data *handle)
{

	printw("%-*.*s", COLS, COLS, "uftrace info");
}

#define print_buf(fmt, ...)						\
	({ int _x = snprintf(buf + len, sz - len, fmt, ## __VA_ARGS__); len += _x; })

static void win_footer_info(struct tui_window *win,
			    struct uftrace_data *handle)
{
	char buf[256];
	size_t sz = sizeof(buf);
	int len = 0;

	print_buf("uftrace version: %s", UFTRACE_VERSION);
	printw("%-*.*s", COLS, COLS, buf);
}

static void win_display_info(struct tui_window *win, void *node)
{
	struct tui_list_node *curr = node;

	printw("%-*.*s", COLS, COLS, curr->data);
}

static const struct tui_window_ops info_ops = {
	.prev = win_prev_list,
	.next = win_next_list,
	.top = win_top_list,
	.parent = win_parent_no,
	.sibling_prev = win_sibling_prev_no,
	.sibling_next = win_sibling_next_no,
	.needs_blank = win_needs_blank_no,
	.header = win_header_info,
	.footer = win_footer_info,
	.display = win_display_info,
};

#define TUI_SESS_REPORT    1
#define TUI_SESS_INFO      2
#define TUI_SESS_HELP      3
#define TUI_SESS_QUIT      4
#define TUI_SESS_DUMMY_NR  4

/* per-window operations for session window */
static struct tui_list * tui_session_init(struct opts *opts)
{
	struct tui_graph *graph;
	struct tui_list_node *node;
	int i;

	INIT_LIST_HEAD(&tui_session.head);
	tui_session.nr_node = 0;

	list_for_each_entry(graph, &tui_graph_list, list) {
		node = xmalloc(sizeof(*node));

		node->data = graph->ug.sess;
		list_add_tail(&node->list, &tui_session.head);
		tui_session.nr_node++;
	}

	for (i = 1; i <= TUI_SESS_DUMMY_NR; i++) {
		node = xmalloc(sizeof(*node));
		node->data = (void *)(long)i;
		list_add_tail(&node->list, &tui_session.head);
	}

	tui_window_init(&tui_session.win, &session_ops);

	return &tui_session;
}

static void tui_session_finish(void)
{
	struct tui_list_node *node, *tmp;

	list_for_each_entry_safe(node, tmp, &tui_session.head, list) {
		list_del(&node->list);
		free(node);
	}
}

static void win_header_session(struct tui_window *win,
			       struct uftrace_data *handle)
{
	printw("%s %-*s", "Key", COLS - 4, "uftrace command");
}

static void win_footer_session(struct tui_window *win,
			       struct uftrace_data *handle)
{
	char buf[256];
	struct tui_list *s_list = (struct tui_list *)win;
	struct tui_list_node *node = win->curr;
	struct uftrace_session *s = node->data;

	switch ((long)node->data) {
	case TUI_SESS_REPORT:
	case TUI_SESS_INFO:
	case TUI_SESS_HELP:
	case TUI_SESS_QUIT:
		snprintf(buf, sizeof(buf), "uftrace: %d session(s)",
			 s_list->nr_node);
		break;
	default:
		snprintf(buf, sizeof(buf), "session %.*s:  exe image: %s",
			 SESSION_ID_LEN, s->sid, s->exename);
		break;
	}

	printw("%-*s", COLS, buf);
}

static struct tui_graph * get_current_graph(struct tui_list_node *node,
					    int *count)
{
	struct tui_graph *graph;
	int n = 1;

	list_for_each_entry(graph, &tui_graph_list, list) {
		if (graph->ug.sess == node->data) {
			if (count)
				*count = n;
			return graph;
		}
		n++;
	}

	if (count)
		*count = 0;
	return NULL;
}

static void win_display_session(struct tui_window *win, void *node)
{
	int len = 0;
	char buf[1024];
	size_t sz = sizeof(buf);
	struct tui_list_node *curr = node;
	struct uftrace_session *s = curr->data;
	struct uftrace_session *curr_sess = NULL;
	int count = 0;

	switch ((long)s) {
	case TUI_SESS_REPORT:
		print_buf(" R  Report functions");
		break;
	case TUI_SESS_INFO:
		print_buf(" I  uftrace Info");
		break;
	case TUI_SESS_HELP:
		print_buf(" h  Help message");
		break;
	case TUI_SESS_QUIT:
		print_buf(" q  quit");
		break;
	default:
		curr_sess = partial_graph.ug.sess;
		get_current_graph(node, &count);
		print_buf(" %c  %s #%d: %s", s == curr_sess ? 'G' : ' ',
			  "call Graph for session", count,
			  basename(s->exename));
		break;
	}

	printw("%-*.*s", COLS, COLS, buf);
}

static bool win_enter_session(struct tui_window *win, void *node)
{
	/* update partial graph for different session */
	struct tui_list_node *curr = node;
	struct uftrace_session *old = partial_graph.ug.sess;
	struct uftrace_session *new = curr->data;
	struct uftrace_graph_node *ugnode;
	struct tui_report_node *func;

	if ((unsigned long)curr->data <= TUI_SESS_DUMMY_NR)
		return true;

	if (old == new)
		return false;

	partial_graph.ug.sess = curr->data;

	/* get root node */
	ugnode = &partial_graph.ug.root;
	if (list_empty(&ugnode->head))
		return true;

	/* get function call node */
	ugnode = list_last_entry(&ugnode->head, typeof(*ugnode), list);
	/* get first child (= actual function) */
	ugnode = list_first_entry(&ugnode->head, typeof(*ugnode), list);

	func = (void *)report_find_node(&tui_report.name_tree, ugnode->name);

	build_partial_graph(func, get_current_graph(node, NULL));
	return true;
}

static const struct tui_window_ops session_ops = {
	.prev = win_prev_list,
	.next = win_next_list,
	.top = win_top_list,
	.parent = win_parent_no,
	.sibling_prev = win_sibling_prev_no,
	.sibling_next = win_sibling_next_no,
	.needs_blank = win_needs_blank_no,
	.enter = win_enter_session,
	.header = win_header_session,
	.footer = win_footer_session,
	.display = win_display_session,
};

/* common window operations */
static void tui_window_move_up(struct tui_window *win)
{
	void *node;

	node = win->ops->prev(win, win->curr, false);
	if (node == NULL)
		return;
	win->curr_index--;

	if (win->ops->needs_blank(win, node, win->curr))
		win->curr_index--;

	if (win->curr_index < win->top_index) {
		win->top = win->ops->prev(win, win->top, true);
		win->top_index = win->curr_index;
	}
	win->curr = node;
}

static void tui_window_move_down(struct tui_window *win)
{
	void *node;

	node = win->ops->next(win, win->curr, false);
	if (node == NULL)
		return;
	win->curr_index++;

	if (win->ops->needs_blank(win, win->curr, node))
		win->curr_index++;

	win->curr = node;

	while (win->curr_index - win->top_index >= LINES - 2) {
		node = win->ops->next(win, win->top, true);
		win->top_index++;

		if (win->ops->needs_blank(win, win->top, node))
			win->top_index++;

		win->top = node;
	}
}

static void tui_window_page_up(struct tui_window *win)
{
	void *node;

	if (win->curr != win->top) {
		win->curr = win->top;
		win->curr_index = win->top_index;
		return;
	}

	while (win->top_index - win->curr_index < LINES - 2) {
		node = win->ops->prev(win, win->top, true);
		if (node == NULL)
			break;
		win->curr_index--;

		if (win->ops->needs_blank(win, node, win->top))
			win->curr_index--;

		win->top = node;
	}
	win->curr = win->top;
	win->top_index = win->curr_index;
}

static void tui_window_page_down(struct tui_window *win)
{
	int orig_index;
	int next_index;
	void *node;

	orig_index = win->top_index;
	next_index = win->curr_index;

	node = win->ops->next(win, win->curr, false);
	if (node == NULL)
		return;
	next_index++;

	if (win->ops->needs_blank(win, win->curr, node))
		next_index++;

	if (next_index - win->top_index >= LINES - 2) {
		/* we're already at the end of page - move to next page */
		orig_index = next_index;
	}

	do {
		/* move curr to the bottom from orig_index */
		win->curr = node;
		win->curr_index = next_index;

		node = win->ops->next(win, win->curr, false);
		if (node == NULL)
			break;
		next_index++;

		if (win->ops->needs_blank(win, win->curr, node))
			next_index++;
	}
	while (next_index - orig_index < LINES - 2);

	/* move top if page was moved */
	while (win->curr_index - win->top_index >= LINES - 2) {
		node = win->ops->next(win, win->top, true);
		win->top_index++;

		if (win->ops->needs_blank(win, win->top, node))
			win->top_index++;

		win->top = node;
	}
}

static void tui_window_move_home(struct tui_window *win)
{
	win->top = win->curr = win->ops->top(win, true);
	win->top_index = win->curr_index = 0;
}

static void tui_window_move_end(struct tui_window *win)
{
	void *node;

	/* move to the last node */
	while (true) {
		node = win->ops->next(win, win->curr, false);
		if (node == NULL)
			break;

		win->curr_index++;

		if (win->ops->needs_blank(win, win->curr, node))
			win->curr_index++;

		win->curr = node;
	}

	/* move top if page was moved */
	while (win->curr_index - win->top_index >= LINES - 2) {
		node = win->ops->next(win, win->top, true);
		win->top_index++;

		if (win->ops->needs_blank(win, win->top, node))
			win->top_index++;

		win->top = node;
	}
}

/* move to the previous sibling */
static bool tui_window_move_prev(struct tui_window *win)
{
	void *prev = win->ops->sibling_prev(win, win->curr);
	int count = 0;

	if (prev == NULL)
		return false;

	if (win->ops->collapse == NULL) {
		while (win->curr != prev)
			tui_window_move_up(win);
		return false;
	}

	/* fold the current node before moving to the previous sibling */
	count = win->ops->collapse(win, win->curr, false, 0);

	while (win->curr != prev)
		tui_window_move_up(win);

	/* collapse the current node after moving to the previous sibling */
	count += win->ops->collapse(win, win->curr, false, 1);

	return count;
}

/* move to the next sibling */
static bool tui_window_move_next(struct tui_window *win)
{
	void *next = win->ops->sibling_next(win, win->curr);
	int count = 0;

	if (next == NULL)
		return false;

	if (win->ops->collapse == NULL) {
		while (win->curr != next)
			tui_window_move_down(win);
		return false;
	}

	/* fold the current node before moving to the next sibling */
	count = win->ops->collapse(win, win->curr, false, 0);

	while (win->curr != next)
		tui_window_move_down(win);

	/* collapse the current node after moving to the next sibling */
	count += win->ops->collapse(win, win->curr, false, 1);

	return count;
}

static void tui_window_display(struct tui_window *win, bool full_redraw,
			       struct uftrace_data *handle)
{
	int count;
	void *node = win->top;

	/* too small screen */
	if (LINES <= 2)
		return;

	move(0, 0);
	attron(COLOR_PAIR(C_HEADER) | A_BOLD);
	win->ops->header(win, handle);
	attroff(COLOR_PAIR(C_HEADER) | A_BOLD);

	for (count = 0; count < LINES - 2; count++) {
		void *next;

		if (!full_redraw && node != win->curr && node != win->old)
			goto next;

		if (node == win->curr)
			attron(A_REVERSE);

		move(count + 1, 0);
		win->ops->display(win, node);

		if (node == win->curr)
			attroff(A_REVERSE);

next:
		next = win->ops->next(win, node, false);
		if (next == NULL)
			break;

		if (win->ops->needs_blank(win, node, next)) {
			count++;
			move(count + 1, 0);
			win->ops->display(win, NULL);
		}

		node = next;
	}

	move(LINES - 1, 0);
	attron(COLOR_PAIR(C_HEADER) | A_BOLD);
	win->ops->footer(win, handle);
	attroff(COLOR_PAIR(C_HEADER) | A_BOLD);
}

static void tui_window_set_middle_prev(struct tui_window *win, void *target)
{
	void *prev;

	while (win->curr != target)
		tui_window_move_up(win);

	while (win->curr_index - win->top_index < LINES / 2) {
		prev = win->ops->prev(win, win->top, false);
		if (prev == NULL)
			break;

		if (win->ops->needs_blank(win, prev, win->top))
			win->top_index--;

		win->top = win->ops->prev(win, win->top, true);
		win->top_index--;
	}
}

static void tui_window_set_middle_next(struct tui_window *win, void *target)
{
	void *old, *next;
	int next_index;

	while (win->curr != target)
		tui_window_move_down(win);

	/* move next to the end of the page */
	old = next = win->curr;
	next_index = win->curr_index;

	while (next_index - win->top_index < LINES - 2) {
		next = win->ops->next(win, old, false);
		if (next == NULL)
			return;

		next_index++;

		if (win->ops->needs_blank(win, old, next))
			next_index++;

		old = next;
	}
	next = win->ops->prev(win, old, false);

	/* move the top down only if there's node at the end */
	while (win->curr_index - win->top_index >= LINES / 2) {
		next = win->ops->next(win, next, false);
		if (next == NULL)
			break;

		old = win->top;
		win->top = win->ops->next(win, old, true);
		win->top_index++;

		if (win->ops->needs_blank(win, old, win->top))
			win->top_index++;
	}
}

static void tui_window_set_middle(struct tui_window *win)
{
	int offset_from_top = win->curr_index - win->top_index;
	int offset_half = LINES / 2;

	if (offset_from_top < offset_half - 2)
		tui_window_set_middle_prev(win, win->curr);
	else if (offset_from_top > offset_half + 1)
		tui_window_set_middle_next(win, win->curr);
}

static bool tui_window_can_search(struct tui_window *win)
{
	return win->ops->search != NULL;
}

static char * tui_search_start(void)
{
	WINDOW *win;
	int w = COLS / 2;
	int h = 8;
	char buf[512];
	int n = 0;
	char *str = NULL;
	struct tui_graph *graph;

	win = newwin(h, w, (LINES - h) / 2, (COLS - w) / 2);
	box(win, 0, 0);

	mvwprintw(win, 1, 1, "Search function:");
	mvwprintw(win, 2, 2, "(press ESC to exit)");
	wrefresh(win);

	wmove(win, 5, 3);
	wrefresh(win);
	buf[0] = '\0';

	while (true) {
		int k = wgetch(win);

		switch (k) {
		case KEY_ESCAPE:
			goto out;
		case KEY_BACKSPACE:
		case KEY_DC:
		case 127:
		case '\b':
			if (n > 0) {
				mvwprintw(win, 5, 3, "%*s", n, "");
				buf[--n] = '\0';
			}
			break;
		case KEY_ENTER:
		case '\n':
			str = xstrdup(buf);
			goto out;
		default:
			if (isprint(k))
				buf[n++] = k;
			buf[n] = '\0';
			break;
		}
		mvwprintw(win, 5, 3, "%-.*s", w - 5, buf);
		wmove(win, 5, 3 + n);
		wrefresh(win);
	}

out:
	list_for_each_entry(graph, &tui_graph_list, list)
		graph->win.search_count = -1;
	partial_graph.win.search_count = -1;
	tui_report.win.search_count = -1;

	delwin(win);
	return str;
}

static void tui_window_search_count(struct tui_window *win)
{
	void *node;

	if (tui_search == NULL || win->ops->search == NULL)
		return;

	if (win->search_count != -1)
		return;

	win->search_count = 0;

	node = win->ops->top(win, false);
	while (node) {
		if (win->ops->search(win, node, tui_search))
			win->search_count++;

		node = win->ops->next(win, node, false);
	}
}

static void tui_window_search_prev(struct tui_window *win)
{
	void *node = win->curr;

	if (tui_search == NULL || win->ops->search == NULL)
		return;

	while (true) {
		node = win->ops->prev(win, node, false);
		if (node == NULL)
			return;

		if (win->ops->search(win, node, tui_search))
			break;
	}

	tui_window_set_middle_prev(win, node);
}

static void tui_window_search_next(struct tui_window *win)
{
	void *node = win->curr;

	if (tui_search == NULL || win->ops->search == NULL)
		return;

	while (true) {
		node = win->ops->next(win, node, false);
		if (node == NULL)
			return;

		if (win->ops->search(win, node, tui_search))
			break;
	}

	tui_window_set_middle_next(win, node);
}

static bool tui_window_change(struct tui_window *win,
			      struct tui_window *new_win)
{
	if (win == new_win)
		return false;

	tui_window_search_count(new_win);
	return true;
}

static bool tui_window_enter(struct tui_window *win,
			     struct tui_window *prev_win)
{
	if (win->ops->enter == NULL)
		return false;

	return win->ops->enter(win, win->curr);
}

static bool tui_window_collapse(struct tui_window *win, bool all)
{
	if (win->ops->collapse == NULL)
		return false;

	/* fold all the directly children */
	return win->ops->collapse(win, win->curr, all, 1);
}

static bool tui_window_expand(struct tui_window *win, bool all)
{
	if (win->ops->expand == NULL)
		return false;

	/* unfold all the directly children */
	return win->ops->expand(win, win->curr, all, 1);
}

static bool tui_window_move_parent(struct tui_window *win)
{
	void *parent = win->ops->parent(win, win->curr);

	if (parent == NULL)
		return false;

	while (win->curr != parent)
		tui_window_move_up(win);

	return tui_window_collapse(win, false);
}

static bool tui_window_longest_child(struct tui_window *win)
{
	if (win->ops->longest_child == NULL)
		return false;

	return win->ops->longest_child(win, win->curr);
}

static bool tui_window_open_editor(struct tui_window *win)
{
	struct debug_location *dloc;
	const char *editor = getenv("EDITOR");
	struct strv editor_strv;
	int pid, status;
	int ret;

	if (win->ops->location == NULL)
		return false;

	dloc = win->ops->location(win, win->curr);
	if (dloc == NULL || dloc->file == NULL)
		return false;

	/* can read file? */
	if (access(dloc->file->name, R_OK) < 0)
		return false;

	if (editor == NULL)
		editor = "vi";

	endwin();

	strv_split(&editor_strv, editor, " ");
	if (!strncmp(editor, "vi", 2) || !strncmp(editor, "emacs", 5)) {
		char buf[16];

		/* run 'vi +line file' */
		snprintf(buf, sizeof(buf), "+%d", dloc->line);
		strv_append(&editor_strv, buf);
		strv_append(&editor_strv, dloc->file->name);
	}
	else {
		/* I don't know what to do */
		strv_append(&editor_strv, dloc->file->name);
	}

	pid = fork();
	if (pid < 0) {
		int saved_errno = errno;

		endwin();

		errno = saved_errno;
		pr_err("forking editor failed");
	}

	if (pid == 0) {
		execvp(editor_strv.p[0], editor_strv.p);
		exit(1);
	}

	strv_free(&editor_strv);

	do {
		/* can return early by signal (e.g. SIGWINCH) */
		ret = waitpid(pid, &status, 0);
	}
	while (ret < 0 && errno == EINTR);

	refresh();
	return true;
}

static void tui_window_help(void)
{
	WINDOW *win;
	int w = 64;
	int h = ARRAY_SIZE(help) + 5;
	unsigned i;

	if (w > COLS)
		w = COLS;
	if (h > LINES)
		h = LINES;

	win = newwin(h, w, (LINES - h) / 2, (COLS - w) / 2);
	box(win, 0, 0);

	mvwprintw(win, 1, 1, "Help: (press any key to exit)");

	for (i = 0; i < ARRAY_SIZE(help); i++)
		mvwprintw(win, i + 3, 2, "%-*.*s", w-3, w-3, help[i]);

	mvwprintw(win, h-1, w-1, "");
	wrefresh(win);

	/* wait for key press */
	wgetch(win);

	delwin(win);
}

static inline void cancel_search()
{
	free(tui_search);
	tui_search = NULL;
}

static void tui_main_loop(struct opts *opts, struct uftrace_data *handle)
{
	int key = 0;
	bool full_redraw = true;
	struct tui_graph *graph;
	struct tui_report *report;
	struct tui_list *info;
	struct tui_list *session;
	struct tui_window *win;
	void *old_top;

	graph = tui_graph_init(opts);
	report = tui_report_init(opts);
	info = tui_info_init(opts, handle);
	session = tui_session_init(opts);

	/* start with graph only if there's one session */
	if (session->nr_node > 1)
		win = &session->win;
	else
		win = &graph->win;

	old_top = win->top;

	while (true) {
		switch (key) {
		case KEY_RESIZE:
			full_redraw = true;
			break;
		case KEY_UP:
		case 'k':
			cancel_search();
			tui_window_move_up(win);
			break;
		case KEY_DOWN:
		case 'j':
			cancel_search();
			tui_window_move_down(win);
			break;
		case KEY_PPAGE:
			cancel_search();
			tui_window_page_up(win);
			break;
		case KEY_NPAGE:
			cancel_search();
			tui_window_page_down(win);
			break;
		case KEY_HOME:
			cancel_search();
			tui_window_move_home(win);
			break;
		case KEY_END:
			cancel_search();
			tui_window_move_end(win);
			break;
		case KEY_ENTER:
		case '\n':
			full_redraw = tui_window_enter(win, win->curr);

			if (win == &session->win) {
				struct tui_list_node *cmd = win->curr;

				switch ((long)cmd->data) {
				case TUI_SESS_REPORT:
					win = &report->win;
					tui_window_move_home(win);
					break;
				case TUI_SESS_INFO:
					win = &info->win;
					tui_window_move_home(win);
					break;
				case TUI_SESS_HELP:
					tui_window_help();
					break;
				case TUI_SESS_QUIT:
					goto out;
				default:
					/* change window for the current graph */
					graph = get_current_graph(win->curr, NULL);
					win = &graph->win;
					tui_window_move_home(win);
					break;
				}
			}
			break;
		case KEY_ESCAPE:
			cancel_search();
			break;
		case 'G':
			if (tui_window_change(win, &graph->win)) {
				/* full graph mode */
				win = &graph->win;
				full_redraw = true;
			}
			break;
		case 'g':
			if (win == &graph->win || win == &partial_graph.win) {
				struct tui_report_node *func;
				struct tui_graph_node *curr = win->curr;

				func = (void *)report_find_node(&report->name_tree,
								curr->n.name);
				if (func == NULL)
					break;
				build_partial_graph(func, graph);
			}
			else if (win == &report->win) {
				build_partial_graph(win->curr, graph);
			}
			else {
				break;
			}

			win = &partial_graph.win;

			tui_window_move_home(win);
			tui_window_search_count(win);
			full_redraw = true;
			break;
		case 'R':
			if (tui_window_change(win, &report->win)) {
				win = &report->win;
				tui_window_move_home(win);
				full_redraw = true;
			}
			break;
		case 'r':
			if (tui_window_change(win, &report->win)) {
				struct tui_report_node *func;
				struct tui_graph_node *graph_curr = win->curr;

				func = (void *)report_find_node(&report->name_tree,
					       graph_curr->n.name);
				if (func == NULL)
					break;

				/* change to report window */
				win = &report->win;

				/* move focus on the same function */
				tui_window_move_home(win);
				tui_window_set_middle_next(win, func);

				full_redraw = true;
			}
			break;
		case 'I':
			if (tui_window_change(win, &info->win)) {
				win = &info->win;
				full_redraw = true;
			}
			break;
		case 'S':
			if (tui_window_change(win, &session->win)) {
				win = &session->win;
				full_redraw = true;
			}
			break;
		case 'O':
			full_redraw = tui_window_open_editor(win);
			break;
		case 'c':
			full_redraw = tui_window_collapse(win, false);
			break;
		case 'e':
			full_redraw = tui_window_expand(win, false);
			break;
		case 'C':
			full_redraw = tui_window_collapse(win, true);
			break;
		case 'E':
			full_redraw = tui_window_expand(win, true);
			break;
		case 'p':
			full_redraw = tui_window_move_prev(win);
			break;
		case 'n':
			full_redraw = tui_window_move_next(win);
			break;
		case 'u':
			full_redraw = tui_window_move_parent(win);
			break;
		case 'l':
			full_redraw = tui_window_longest_child(win);
			break;
		case 'z':
			tui_window_set_middle(win);
			break;
		case '/':
			if (tui_window_can_search(win)) {
				free(tui_search);
				tui_search = tui_search_start();
				tui_window_search_count(win);

				/* move to the next match if found */
				if (win->search_count > 0)
					tui_window_search_next(win);

				full_redraw = true;
			}
			break;
		case '<':
		case 'P':
			tui_window_search_prev(win);
			break;
		case '>':
		case 'N':
			tui_window_search_next(win);
			break;
		case 'v':
			tui_debug = !tui_debug;
			break;
		case 'h':
		case '?':
			tui_window_help();
			full_redraw = true;
			break;
		case 'q':
			goto out;
		default:
			break;
		}

		if (win->top != old_top)
			full_redraw = true;

		if (full_redraw)
			clear();

		tui_window_display(win, full_redraw, handle);
		refresh();

		full_redraw = false;

		win->old = win->curr;
		old_top = win->top;

		move(LINES-1, COLS-1);
		key = getch();
	}

out:
	tui_graph_finish();
	tui_report_finish();
	tui_info_finish();
	tui_session_finish();
}

int command_tui(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct uftrace_data handle;
	struct uftrace_task_reader *task;

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
		return -1;
	}

	setlocale(LC_ALL, "");

	initscr();
	init_colors();
	keypad(stdscr, true);
	noecho();

	atexit(tui_cleanup);

	tui_setup(&handle, opts);
	fstack_setup_filters(opts, &handle);

	while (read_rstack(&handle, &task) == 0 && !uftrace_done) {
		struct uftrace_record *rec = task->rstack;

		if (!fstack_check_opts(task, opts))
			continue;

		if (!fstack_check_filter(task))
			continue;

		ret = build_tui_node(task, rec);
		if (ret)
			break;
	}
	add_remaining_node(opts, &handle);

	tui_main_loop(opts, &handle);

	close_data_file(opts, &handle);

	tui_cleanup();
	return 0;
}

#else /* !HAVE_LIBNCURSES */

#include "uftrace.h"
#include "utils/utils.h"

int command_tui(int argc, char *argv[], struct opts *opts)
{
	pr_warn("TUI is unsupported (libncursesw.so is missing)\n");
	return 0;
}

#endif /* HAVE_LIBNCURSES */
