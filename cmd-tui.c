#ifdef HAVE_LIBNCURSES

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ncurses.h>
#include <locale.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "utils/graph.h"
#include "utils/list.h"
#include "utils/rbtree.h"

static bool tui_finished;
static bool tui_debug;

struct tui_graph_node {
	struct uftrace_graph_node n;
	bool folded;
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

	return 0;
}

static void tui_setup(struct ftrace_file_handle *handle)
{
	walk_sessions(&handle->sessions, create_data, NULL);
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

static int build_tui_node(struct ftrace_task_handle *task,
			  struct uftrace_record *rec)
{
	struct uftrace_task_graph *tg;
	struct uftrace_graph *graph;
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

	graph_add_node(tg, rec->type, name, sizeof(struct tui_graph_node));

	symbol_putname(sym, name);
	return 0;
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
	    is_last_child(parent, node) && indent_mask)
		indent_mask[*depth - 1] = false;

	/* simple case: if it has children, move to it */
	if (!list_empty(&n->head) && (parent == NULL || !node->folded)) {
		if (!list_is_singular(&n->head)) {
			if (indent_mask)
				indent_mask[*depth] = true;
			*depth += 1;
		}

		n = list_first_entry(&n->head, typeof(*n), list);
		return (struct tui_graph_node *)n;
	}

	/* parent should not be folded */
	while (n->parent != NULL) {
		parent = (struct tui_graph_node *)n->parent;

		/* move to sibling if possible */
		if (!is_last_child(parent, (void *)n)) {
			n = list_next_entry(n, list);
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
	int d = graph->top_depth;

	if (LINES <= 2)
		return;

	memcpy(graph->curr_mask, graph->top_mask, graph->mask_size);

	print_graph_header(handle, graph);

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

		print_graph_indent(graph, node, d, single_child);

		printw("%s(%d) %s", fold_sign, node->n.nr_calls, node->n.name);

		if (node == graph->curr) {
			/* 4 = fold_sign(1) + parenthesis(2) + space(1) */
			int width = d * 3 + strlen(node->n.name) + 4;
			char buf[32];

			width += snprintf(buf, sizeof(buf), "%d", node->n.nr_calls);

			if (width < COLS)
				printw("%*s", COLS - width, "");

			graph->curr_depth = d;
			attroff(A_REVERSE);
		}

		next = graph_next_node(node, &d, graph->curr_mask);
		if (unlikely(next == NULL))
			break;

		count++;

		move(count + 1, 0);

		if (!is_first_child(node, next)) {
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
}

static void tui_graph_finish(void)
{
	struct tui_graph *graph;

	list_for_each_entry(graph, &tui_graph_list, list) {
		free(graph->top_mask);
		free(graph->curr_mask);
	}
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

static void tui_main_loop(struct opts *opts, struct ftrace_file_handle *handle)
{
	int key = 0;
	struct tui_graph *graph;

	tui_graph_init(opts);
	graph = list_first_entry(&tui_graph_list, typeof(*graph), list);

	while (true) {
		switch (key) {
		case KEY_UP:
		case 'k':
			tui_graph_move_up(graph);
			break;
		case KEY_DOWN:
		case 'j':
			tui_graph_move_down(graph);
			break;
		case KEY_PPAGE:
			tui_graph_page_up(graph);
			break;
		case KEY_NPAGE:
			tui_graph_page_down(graph);
			break;
		case KEY_HOME:
			tui_graph_move_home(graph);
			break;
		case KEY_END:
			tui_graph_move_end(graph);
			break;
		case KEY_ENTER:
		case '\n':
			tui_graph_enter(graph);
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
		tui_graph_display(handle, graph);
		refresh();

		move(LINES-1, COLS-1);
		key = getch();
	}

	tui_graph_finish();
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

	tui_setup(&handle);
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
