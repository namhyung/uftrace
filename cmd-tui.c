#ifdef HAVE_LIBNCURSES

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ncurses.h>
#include <locale.h>
#include <inttypes.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "utils/graph.h"
#include "utils/list.h"
#include "utils/rbtree.h"
#include "utils/field.h"

static bool tui_finished;
static bool tui_debug;

struct tui_graph_node {
	struct uftrace_graph_node n;
	struct list_head link; // for tui_report_node.head
	struct tui_graph *graph;
	bool folded;
};

struct tui_report_node {
	struct rb_node name_link;
	struct rb_node sort_link;
	struct list_head head; // links tui_graph_node.link
	char *name;
	uint64_t time;
	uint64_t min_time;
	uint64_t max_time;
	uint64_t self_time;
	uint64_t min_self_time;
	uint64_t max_self_time;
	uint64_t recursive_time;
	unsigned calls;
};

struct tui_report {
	struct list_head list;
	struct rb_root name_tree;
	struct rb_root sort_tree;
	struct tui_report_node *top;
	struct tui_report_node *curr;
	int top_index;
	int curr_index;
	int nr_sess;
	int nr_func;
};

struct tui_graph {
	struct uftrace_graph ug;
	struct list_head list;
	struct tui_graph_node *top;
	struct tui_graph_node *curr;
	int top_depth;
	int top_index;
	int curr_index;
	int curr_depth;
	bool *top_mask;
	bool *curr_mask;
	size_t mask_size;
};

static LIST_HEAD(tui_graph_list);
static LIST_HEAD(graph_output_fields);
static struct tui_report tui_report;
static struct tui_graph partial_graph;

#define FIELD_SPACE  2
#define FIELD_SEP  " :"

static void print_time(uint64_t ntime)
{
	char *units[] = { "us", "ms", " s", " m", " h", };
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

	printw("%3"PRIu64".%03"PRIu64" %s", ntime, fract, units[idx]);
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

static void tui_setup(struct ftrace_file_handle *handle, struct opts *opts)
{
	walk_sessions(&handle->sessions, create_data, NULL);

	tui_report.name_tree = RB_ROOT;
	tui_report.sort_tree = RB_ROOT;

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

static struct uftrace_graph * get_graph(struct ftrace_task_handle *task,
					uint64_t time, uint64_t addr)
{
	struct tui_graph *graph;
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

	list_for_each_entry(graph, &tui_graph_list, list) {
		if (graph->ug.sess == sess)
			return &graph->ug;
	}
	return NULL;
}

static struct tui_report_node * find_report_node(struct tui_report *report,
						 char *symname)
{
	struct tui_report_node *node;
	struct rb_node *parent = NULL;
	struct rb_node **p = &report->name_tree.rb_node;

	while (*p) {
		int cmp;

		parent = *p;
		node = rb_entry(parent, struct tui_report_node, name_link);

		cmp = strcmp(node->name, symname);
		if (cmp == 0)
			return node;

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	node = xzalloc(sizeof(*node));
	node->name = xstrdup(symname);
	INIT_LIST_HEAD(&node->head);

	rb_link_node(&node->name_link, parent, p);
	rb_insert_color(&node->name_link, &report->name_tree);
	report->nr_func++;

	return node;
}

static void prepare_report_node(struct tui_report_node *node)
{
	struct tui_graph_node *gn;

	list_for_each_entry(gn, &node->head, link) {
		node->time      += gn->n.time;
		node->self_time += gn->n.time - gn->n.child_time;
		node->calls     += gn->n.nr_calls;
	}

	node->time -= node->recursive_time;
}

static int cmp_report_node(struct tui_report_node *a, struct tui_report_node *b)
{
	/* TODO: apply sort key */
	if (a->time != b->time)
		return a->time > b->time ? 1 : -1;

	return 0;
}

static void sort_report_node(struct tui_report *report,
			     struct tui_report_node *node)
{
	struct tui_report_node *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &report->sort_tree.rb_node;

	prepare_report_node(node);

	while (*p) {
		int cmp;

		parent = *p;
		iter = rb_entry(parent, struct tui_report_node, sort_link);

		cmp = cmp_report_node(iter, node);
		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&node->sort_link, parent, p);
	rb_insert_color(&node->sort_link, &report->sort_tree);
}

static void sort_tui_report(struct tui_report *report)
{
	struct rb_node *node = rb_first(&report->name_tree);
	struct tui_report_node *tui_node;

	while (node) {
		tui_node = rb_entry(node, struct tui_report_node, name_link);
		sort_report_node(report, tui_node);

		node = rb_next(node);
	}
}

static bool list_is_none(struct list_head *list)
{
	return list->next == NULL && list->prev == NULL;
}

static int build_tui_node(struct ftrace_task_handle *task,
			  struct uftrace_record *rec)
{
	struct uftrace_task_graph *tg;
	struct uftrace_graph *graph;
	struct tui_graph_node *graph_node;
	struct sym *sym;
	char *name;

	tg = graph_get_task(task, sizeof(*tg));
	graph = get_graph(task, rec->time, rec->addr);

	if (tg->node == NULL || tg->graph != graph)
		tg->node = &graph->root;

	tg->graph = graph;

	sym = task_find_sym_addr(&task->h->sessions,
				 task, rec->time, rec->addr);
	name = symbol_getname(sym, rec->addr);

	if (rec->type == UFTRACE_EXIT) {
		struct fstack *fstack = &task->func_stack[task->stack_count];
		uint64_t total_time = fstack->total_time;
		uint64_t self_time = fstack->total_time - fstack->child_time;
		struct tui_report_node *node;
		int i;

		node = find_report_node(&tui_report, name);

		graph_node = (struct tui_graph_node *)tg->node;
		if (list_is_none(&graph_node->link))
			list_add_tail(&graph_node->link, &node->head);

		if (node->max_time < total_time)
			node->max_time = total_time;
		if (node->min_time == 0 || node->min_time > total_time)
			node->min_time = total_time;
		if (node->max_self_time < self_time)
			node->max_self_time = self_time;
		if (node->min_self_time == 0 || node->min_self_time > self_time)
			node->min_self_time = self_time;

		for (i = 0; i < task->stack_count; i++) {
			if (task->func_stack[i].addr == fstack->addr) {
				node->recursive_time += total_time;
				break;
			}
		}
	}

	graph_add_node(tg, rec->type, name, sizeof(struct tui_graph_node));
	if (tg->node && tg->node != &graph->root) {
		graph_node = (struct tui_graph_node *)tg->node;
		graph_node->graph = (struct tui_graph *)graph;
	}

	symbol_putname(sym, name);
	return 0;
}

static struct tui_graph_node * append_graph_node(struct uftrace_graph_node *dst,
						 char *name)
{
	struct tui_graph_node *node;

	node = xzalloc(sizeof(*node));

	node->n.name = xstrdup(name);
	INIT_LIST_HEAD(&node->n.head);

	node->n.parent = dst;
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

		if (list_no_entry(node, &dst->head, n.list))
			node = append_graph_node(dst, child->name);

		node->n.time       += child->time;
		node->n.child_time += child->child_time;
		node->n.nr_calls   += child->nr_calls;

		copy_graph_node(&node->n, child);
	}
}

static void build_partial_graph(struct tui_report_node *root_node,
				struct tui_graph *target)
{
	struct tui_graph *graph = &partial_graph;
	struct tui_graph_node *root, *node;
	char *str;

	graph_destroy(&graph->ug);

	graph->ug.sess = target->ug.sess;

	xasprintf(&str, "=== Function Call Graph for '%s' ===", root_node->name);

	graph->top = (struct tui_graph_node*) &graph->ug.root;
	graph->top->n.name = str;
	graph->top->n.parent = NULL;

	graph->top->n.time       = 0;
	graph->top->n.child_time = 0;
	graph->top->n.nr_calls   = 0;

	/* special node */
	root = append_graph_node(&graph->ug.root,
				 "========== Back-trace ==========");

	list_for_each_entry(node, &root_node->head, link) {
		struct tui_graph_node *tmp, *parent;

		if (node->graph != target)
			continue;

		tmp = root;
		parent = node;

		while (parent->n.parent) {
			tmp = append_graph_node(&tmp->n, parent->n.name);

			tmp->n.time       = node->n.time;
			tmp->n.child_time = node->n.child_time;
			tmp->n.nr_calls   = node->n.nr_calls;

			parent = (void *)parent->n.parent;
		}
	}

	/* special node */
	root = append_graph_node(&graph->ug.root,
				 "========== Call Graph ==========");

	root = append_graph_node(&root->n, root_node->name);

	list_for_each_entry(node, &root_node->head, link) {
		if (node->graph != target)
			continue;

		root->n.time       += node->n.time;
		root->n.child_time += node->n.child_time;
		root->n.nr_calls   += node->n.nr_calls;

		copy_graph_node(&root->n, &node->n);
	}

	graph->curr = graph->top;
	graph->curr_index = graph->top_index = 0;
	graph->top_depth = 0;

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

static void print_graph_header(struct ftrace_file_handle *handle,
			       struct tui_graph *graph)
{
	attron(A_REVERSE | A_BOLD);
	printw("%-*s", COLS, "uftrace graph TUI");
	attroff(A_REVERSE | A_BOLD);
}

static void print_graph_footer(struct ftrace_file_handle *handle,
			       struct tui_graph *graph)
{
	char buf[COLS + 1];
	struct uftrace_session *sess = graph->ug.sess;

	if (tui_debug) {
		snprintf(buf, COLS, "top: %d depth: %d, curr: %d depth: %d",
			 graph->top_index, graph->top_depth,
			 graph->curr_index, graph->curr_depth);
	}
	else {
		snprintf(buf, COLS, "session %.*s (%s)",
			 SESSION_ID_LEN, sess->sid, sess->exename);
	}
	buf[COLS] = '\0';

	move(LINES - 1, 0);
	attron(A_REVERSE | A_BOLD);
	printw("%-*s", COLS, buf);
	attroff(A_REVERSE | A_BOLD);
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
		if (!graph->curr_mask[i]) {
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

static void tui_graph_display(struct ftrace_file_handle *handle,
			      struct tui_graph *graph)
{
	int count = 0;
	struct tui_graph_node *node = graph->top;
	struct display_field *field;
	int d = graph->top_depth;
	int w = 0;

	if (LINES <= 2)
		return;

	memcpy(graph->curr_mask, graph->top_mask, graph->mask_size);

	print_graph_header(handle, graph);

	/* calculate width for fields */
	list_for_each_entry(field, &graph_output_fields, list) {
		w += field->length + FIELD_SPACE;
	}
	if (!list_empty(&graph_output_fields))
		w += strlen(FIELD_SEP);

	while (count < LINES - 2) {
		const char *fold_sign = node->folded ? "▶" : "─";
		struct tui_graph_node *parent = (void *)node->n.parent;
		struct tui_graph_node *next;
		bool single_child = false;

		if (parent && list_is_singular(&parent->n.head)) {
			single_child = true;
			if (!node->folded)
				fold_sign = " ";
		}
		if (parent == NULL)
			fold_sign = " ";

		move(count + 1, 0);

		if (node == graph->curr)
			attron(A_REVERSE);

		move(count + 1, 0);
		print_graph_field(&node->n);
		print_graph_indent(graph, node, d, single_child);

		if (is_special_node(&node->n))
			printw("%s", node->n.name);
		else
			printw("%s(%d) %s", fold_sign, node->n.nr_calls,
			       node->n.name);

		if (node == graph->curr) {
			int width = d * 3 + strlen(node->n.name) + w;
			char buf[32];

			/* 4 = fold_sign(1) + parenthesis(2) + space(1) */
			if (!is_special_node(&node->n)) {
				width += snprintf(buf, sizeof(buf),
						  "%d", node->n.nr_calls) + 4;
			}

			if (width < COLS)
				printw("%*s", COLS - width, "");

			graph->curr_depth = d;
			attroff(A_REVERSE);
		}

		next = graph_next_node(node, &d, graph->curr_mask);
		if (unlikely(next == NULL))
			break;

		count++;

		if (!is_first_child(node, next)) {
			move(count + 1, 0);
			print_graph_empty();
			print_graph_indent(graph, next, d, true);

			count++;
		}

		node = next;
	}

	print_graph_footer(handle, graph);
}

static void tui_graph_init(struct opts *opts)
{
	struct tui_graph *graph;
	struct uftrace_graph_node *node;

	list_for_each_entry(graph, &tui_graph_list, list) {
		/* top (root) is an artificial node, fill the info */
		graph->top = (struct tui_graph_node*)&graph->ug.root;
		graph->top->n.name = basename(graph->ug.sess->exename);

		list_for_each_entry(node, &graph->ug.root.head, list) {
			graph->top->n.time       += node->time;
			graph->top->n.child_time += node->time;
		}
		graph->top->n.nr_calls = 1;

		graph->curr = graph->top;
		graph->curr_index = graph->top_index;

		graph->mask_size = sizeof(*graph->top_mask) * opts->max_stack;

		graph->top_mask  = xzalloc(graph->mask_size);
		graph->curr_mask = xmalloc(graph->mask_size);
	}

	graph = list_first_entry(&tui_graph_list, typeof(*graph), list);

	partial_graph.mask_size = graph->mask_size;
	partial_graph.top_mask  = xzalloc(graph->mask_size);
	partial_graph.curr_mask = xmalloc(graph->mask_size);

	INIT_LIST_HEAD(&partial_graph.ug.root.head);
	INIT_LIST_HEAD(&partial_graph.ug.special_nodes);
}

static void tui_graph_finish(void)
{
	struct tui_graph *graph;

	list_for_each_entry(graph, &tui_graph_list, list) {
		graph_destroy(&graph->ug);
		free(graph->top_mask);
		free(graph->curr_mask);
	}

	graph_destroy(&partial_graph.ug);
	free(partial_graph.top_mask);
	free(partial_graph.curr_mask);
}

static void tui_graph_move_up(struct tui_graph *graph)
{
	int depth = 0;
	struct tui_graph_node *node;

	node = graph_prev_node(graph->curr, &depth, NULL);
	if (node == NULL)
		return;
	graph->curr_index--;

	if (!is_first_child(node, graph->curr))
		graph->curr_index--;

	if (graph->curr_index < graph->top_index) {
		graph->top = graph_prev_node(graph->top,
					     &graph->top_depth,
					     graph->top_mask);
		graph->top_index = graph->curr_index;
	}
	graph->curr = node;
}

static void tui_graph_move_down(struct tui_graph *graph)
{
	int depth = 0;
	struct tui_graph_node *node;

	node = graph_next_node(graph->curr, &depth, NULL);
	if (node == NULL)
		return;
	graph->curr_index++;

	if (!is_first_child(graph->curr, node))
		graph->curr_index++;

	graph->curr = node;

	while (graph->curr_index - graph->top_index >= LINES - 2) {
		node = graph_next_node(graph->top,
				       &graph->top_depth,
				       graph->top_mask);
		graph->top_index++;

		if (!is_first_child(graph->top, node))
			graph->top_index++;

		graph->top = node;
	}
}

static void tui_graph_page_up(struct tui_graph *graph)
{
	struct tui_graph_node *node;

	if (graph->curr != graph->top) {
		graph->curr = graph->top;
		graph->curr_index = graph->top_index;
		return;
	}

	node = graph->top;
	while (graph->top_index - graph->curr_index < LINES - 2) {
		node = graph_prev_node(graph->top,
				       &graph->top_depth,
				       graph->top_mask);
		if (node == NULL)
			break;
		graph->curr_index--;

		if (!is_first_child(node, graph->top))
			graph->curr_index--;

		graph->top = node;
	}
	graph->curr = graph->top;
	graph->top_index = graph->curr_index;
}

static void tui_graph_page_down(struct tui_graph *graph)
{
	int depth = 0;
	int orig_index;
	int next_index;
	struct tui_graph_node *node;

	orig_index = graph->top_index;
	next_index = graph->curr_index;

	node = graph_next_node(graph->curr, &depth, NULL);
	if (node == NULL)
		return;
	next_index++;

	if (!is_first_child(graph->curr, node))
		next_index++;

	if (next_index - graph->top_index >= LINES - 2) {
		/* we're already at the end of page - move to next page */
		orig_index = next_index;
	}

	do {
		/* move curr to the bottom from orig_index */
		graph->curr = node;
		graph->curr_index = next_index;

		node = graph_next_node(graph->curr, &depth, NULL);
		if (node == NULL)
			break;
		next_index++;

		if (!is_first_child(graph->curr, node))
			next_index++;
	}
	while (next_index - orig_index < LINES - 2);

	/* move top if page was moved */
	while (graph->curr_index - graph->top_index >= LINES - 2) {
		node = graph_next_node(graph->top,
				       &graph->top_depth,
				       graph->top_mask);
		graph->top_index++;

		if (!is_first_child(graph->top, node))
			graph->top_index++;

		graph->top = node;
	}
}

static void tui_graph_move_home(struct tui_graph *graph)
{
	graph->top = (struct tui_graph_node*)&graph->ug.root;
	graph->curr = graph->top;

	graph->top_index = graph->curr_index = 0;
	graph->top_depth = 0;
}

static void tui_graph_move_end(struct tui_graph *graph)
{
	int next_index;
	int next_depth;
	struct tui_graph_node *node;

	node = graph_next_node(graph->curr, &next_depth, NULL);
	if (node == NULL)
		return;

	next_depth = graph->top_depth;

	/* move to the last node */
	while (true) {
		/* use top node to keep the depth and mask */
		node = graph_next_node(graph->top, &next_depth,
				       graph->top_mask);
		if (node == NULL)
			break;
		graph->top_index++;

		if (!is_first_child(graph->top, node))
			graph->top_index++;

		graph->top = node;
		graph->top_depth = next_depth;
	}

	/* move back top to fill the screen */
	graph->curr = graph->top;
	graph->curr_index = graph->top_index;

	node = graph->top;
	next_index = graph->top_index;
	next_depth = graph->top_depth;
	memcpy(graph->curr_mask, graph->top_mask, graph->mask_size);

	do {
		/* change top node only if it's within the same page */
		graph->top = node;
		graph->top_index = next_index;
		graph->top_depth = next_depth;
		memcpy(graph->top_mask, graph->curr_mask, graph->mask_size);

		node = graph_prev_node(graph->top, &next_depth, graph->curr_mask);
		if (node == NULL)
			break;
		next_index--;

		if (!is_first_child(node, graph->top))
			next_index--;
	}
	while (graph->curr_index - next_index < LINES - 2);
}

static void tui_graph_enter(struct tui_graph *graph)
{
	/* root node is not foldable */
	if (graph->curr->n.parent == NULL)
		return;

	if (!list_empty(&graph->curr->n.head))
		graph->curr->folded = !graph->curr->folded;
}

static void tui_report_init(struct opts *opts)
{
	struct rb_node *node;

	sort_tui_report(&tui_report);

	node = rb_first(&tui_report.sort_tree);

	tui_report.top = rb_entry(node, struct tui_report_node, sort_link);
	tui_report.curr = tui_report.top;

	tui_report.top_index = tui_report.curr_index = 0;
}

static void tui_report_finish(void)
{
}

static void tui_report_move_up(struct tui_report *report)
{
	struct rb_node *prev = rb_prev(&report->curr->sort_link);

	if (prev == NULL)
		return;

	report->curr = rb_entry(prev, struct tui_report_node, sort_link);
	report->curr_index--;

	if (report->curr_index < report->top_index) {
		report->top = report->curr;
		report->top_index = report->curr_index;
	}
}

static void tui_report_move_down(struct tui_report *report)
{
	struct rb_node *next = rb_next(&report->curr->sort_link);

	if (next == NULL)
		return;

	report->curr = rb_entry(next, struct tui_report_node, sort_link);
	report->curr_index++;

	if (report->curr_index - report->top_index >= LINES - 2) {
		next = rb_next(&report->top->sort_link);
		report->top = rb_entry(next, struct tui_report_node, sort_link);
		report->top_index++;
	}
}

static void tui_report_page_up(struct tui_report *report)
{
	if (report->curr != report->top) {
		report->curr = report->top;
		report->curr_index = report->top_index;
		return;
	}

	while (report->top_index - report->curr_index < LINES - 2) {
		struct rb_node *prev = rb_prev(&report->curr->sort_link);
		if (prev == NULL)
			break;

		report->curr = rb_entry(prev, struct tui_report_node, sort_link);
		report->curr_index--;
	}

	report->top = report->curr;
	report->top_index = report->curr_index;
}

static void tui_report_page_down(struct tui_report *report)
{
	struct rb_node *next;
	int orig_index = report->top_index;
	int next_index = report->curr_index;

	next = rb_next(&report->curr->sort_link);
	if (next == NULL)
		return;
	next_index++;

	/* we're already at the end of page - move to next page */
	if (next_index - report->top_index >= LINES - 2)
		orig_index = next_index;

	do {
		/* move curr to the bottom from orig_index */
		report->curr = rb_entry(next, struct tui_report_node, sort_link);
		report->curr_index = next_index;

		next = rb_next(next);
		if (next == NULL)
			break;
		next_index++;
	}
	while (next_index - orig_index < LINES - 2);

	/* move top if page was moved */
	while (report->curr_index - report->top_index >= LINES - 2) {
		next = rb_next(&report->top->sort_link);
		report->top = rb_entry(next, struct tui_report_node, sort_link);
		report->top_index++;
	}
}

static void tui_report_move_home(struct tui_report *report)
{
	struct rb_node *node = rb_first(&report->sort_tree);

	report->top = rb_entry(node, struct tui_report_node, sort_link);
	report->curr = report->top;

	report->top_index = report->curr_index = 0;
}

static void tui_report_move_end(struct tui_report *report)
{
	struct rb_node *node = rb_last(&report->sort_tree);
	int next_index;

	report->curr = rb_entry(node, struct tui_report_node, sort_link);

	report->curr_index = next_index = report->nr_func - 1;

	while (report->curr_index - next_index < LINES - 2) {
		report->top = rb_entry(node, struct tui_report_node, sort_link);
		report->top_index = next_index;

		node = rb_prev(&report->top->sort_link);
		if (node == NULL)
			break;

		next_index--;
	}
}

static void tui_report_enter(struct tui_report *report)
{
	struct tui_graph_node *node;

	node = list_first_entry(&report->curr->head, typeof(*node), link);
	build_partial_graph(report->curr, node->graph);
}

static void print_report_header(struct ftrace_file_handle *handle,
				struct tui_report *report)
{
	attron(A_REVERSE | A_BOLD);
	printw("%-*s", COLS, "uftrace report TUI");
	attroff(A_REVERSE | A_BOLD);
}

static void print_report_footer(struct ftrace_file_handle *handle,
				struct tui_report *report)
{
	char buf[COLS + 1];

	if (tui_debug) {
		snprintf(buf, COLS, "top: %d, curr: %d",
			 report->top_index, report->curr_index);
	}
	else {
		snprintf(buf, COLS, "%s (%d sessions, %d functions)",
			 handle->dirname, report->nr_sess, report->nr_func);
	}
	buf[COLS] = '\0';

	move(LINES - 1, 0);
	attron(A_REVERSE | A_BOLD);
	printw("%-*s", COLS, buf);
	attroff(A_REVERSE | A_BOLD);
}

static void print_report_field(struct tui_report *report,
			       struct tui_report_node *node)
{
	printw("  ");
	print_time(node->time);
	printw("  ");
	print_time(node->self_time);
	printw("  ");
	printw("%10u", node->calls);
}

static void tui_report_display(struct ftrace_file_handle *handle,
			       struct tui_report *report)
{
	int count = 0;
	struct tui_report_node *node = report->top;

	if (LINES <= 2)
		return;

	print_report_header(handle, report);

	while (count < LINES - 2) {
		struct rb_node *next;

		move(count + 1, 0);

		if (node == report->curr)
			attron(A_REVERSE);

		print_report_field(report, node);
		printw("  ");
		printw("%-s", node->name);

		if (node == report->curr) {
			int width = 38 + strlen(node->name);

			if (width < COLS)
				printw("%*s", COLS - width, "");

			attroff(A_REVERSE);
		}

		next = rb_next(&node->sort_link);
		if (unlikely(next == NULL))
			break;

		node = rb_entry(next, struct tui_report_node, sort_link);
		count++;
	}

	print_report_footer(handle, report);
}

static void tui_main_loop(struct opts *opts, struct ftrace_file_handle *handle)
{
	int key = 0;
	bool graph_mode = true;
	struct tui_graph *graph;
	struct tui_report *report;

	tui_graph_init(opts);
	tui_report_init(opts);
	graph = list_first_entry(&tui_graph_list, typeof(*graph), list);
	report = &tui_report;

	while (true) {
		switch (key) {
		case KEY_UP:
		case 'k':
			if (graph_mode)
				tui_graph_move_up(graph);
			else
				tui_report_move_up(report);
			break;
		case KEY_DOWN:
		case 'j':
			if (graph_mode)
				tui_graph_move_down(graph);
			else
				tui_report_move_down(report);
			break;
		case KEY_PPAGE:
			if (graph_mode)
				tui_graph_page_up(graph);
			else
				tui_report_page_up(report);
			break;
		case KEY_NPAGE:
			if (graph_mode)
				tui_graph_page_down(graph);
			else
				tui_report_page_down(report);
			break;
		case KEY_HOME:
			if (graph_mode)
				tui_graph_move_home(graph);
			else
				tui_report_move_home(report);
			break;
		case KEY_END:
			if (graph_mode)
				tui_graph_move_end(graph);
			else
				tui_report_move_end(report);
			break;
		case KEY_ENTER:
		case '\n':
			if (graph_mode)
				tui_graph_enter(graph);
			else {
				tui_report_enter(report);
				graph = &partial_graph;
				graph_mode = true;  /* partial graph mode */
			}
			break;
		case 'g':
			graph_mode = true;  /* full graph mode */
			graph = list_first_entry(&tui_graph_list,
						 typeof(*graph), list);
			break;
		case 'r':
			graph_mode = false;  /* report mode */
			break;
		case 'v':
			tui_debug = !tui_debug;
			break;
		case 'q':
			return;
		default:
			break;
		}

		clear();
		if (graph_mode)
			tui_graph_display(handle, graph);
		else
			tui_report_display(handle, report);
		refresh();

		move(LINES-1, COLS-1);
		key = getch();
	}

	tui_graph_finish();
	tui_report_finish();
}

int command_tui(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
	struct ftrace_task_handle *task;

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
		return -1;
	}

	setlocale(LC_ALL, "");

	initscr();
	start_color();
	keypad(stdscr, true);

	atexit(tui_cleanup);

	tui_setup(&handle, opts);
	fstack_setup_filters(opts, &handle);

	while (read_rstack(&handle, &task) == 0 && !uftrace_done) {
		struct uftrace_record *rec = task->rstack;

		/* skip user functions if --kernel-only is set */
		if (opts->kernel_only && !is_kernel_record(task, rec))
			continue;

		if (opts->kernel_skip_out) {
			/* skip kernel functions outside user functions */
			if (!task->user_stack_count && is_kernel_record(task, rec))
				continue;
		}

		if (opts->event_skip_out) {
			/* skip event outside of user functions */
			if (!task->user_stack_count && rec->type == UFTRACE_EVENT)
				continue;
		}

		ret = build_tui_node(task, rec);
		if (ret)
			break;
	}

	tui_main_loop(opts, &handle);

	close_data_file(opts, &handle);

	tui_cleanup();
	return 0;
}

#else /* !HAVE_LIBNCURSES */

int comamnd_tui(int argc, char *argv[], struct opts *opts)
{
	pr_warn("TUI is not implemented (libncurses.so is missing)");
	return 0;
}

#endif /* HAVE_LIBNCURSES */
