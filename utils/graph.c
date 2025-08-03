#include "utils/graph.h"
#include "utils/filter.h"
#include "utils/list.h"
#include "utils/rbtree.h"

static graph_fn entry_cb;
static graph_fn exit_cb;
static graph_fn event_cb;
static void *cb_arg;

static struct rb_root task_graph_root = RB_ROOT;

void graph_init(struct uftrace_graph *graph, struct uftrace_session *s)
{
	memset(graph, 0, sizeof(*graph));
	graph->sess = s;

	INIT_LIST_HEAD(&graph->root.head);
	INIT_LIST_HEAD(&graph->special_nodes);
}

void graph_init_callbacks(graph_fn entry_fn, graph_fn exit_fn, graph_fn event_fn, void *arg)
{
	entry_cb = entry_fn;
	exit_cb = exit_fn;
	event_cb = event_fn;

	cb_arg = arg;
}

struct uftrace_task_graph *graph_get_task(struct uftrace_task_reader *task, size_t tg_size)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &task_graph_root.rb_node;
	struct uftrace_task_graph *tg;

	while (*p) {
		parent = *p;
		tg = rb_entry(parent, struct uftrace_task_graph, link);

		if (tg->task->tid == task->tid)
			return tg;

		if (tg->task->tid > task->tid)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	tg = xzalloc(tg_size);
	tg->task = task;

	rb_link_node(&tg->link, parent, p);
	rb_insert_color(&tg->link, &task_graph_root);

	return tg;
}

static int add_graph_entry(struct uftrace_task_graph *tg, char *name, size_t node_size,
			   struct uftrace_dbg_loc *loc)
{
	struct uftrace_graph_node *node = NULL;
	struct uftrace_graph_node *curr = tg->node;
	struct uftrace_fstack *fstack;
	static uint32_t next_id = 1;

	if (tg->lost)
		return 1; /* ignore kernel functions after LOST */

	if (tg->new_sess) {
		curr = &tg->graph->root;
		pr_dbg2("starts new session graph for task %d\n", tg->task->tid);
		tg->new_sess = false;
	}

	fstack = fstack_get(tg->task, tg->task->stack_count - 1);
	if (curr == NULL || fstack == NULL)
		return -1;

	list_for_each_entry(node, &curr->head, list) {
		if (name && !strcmp(name, node->name))
			break;
	}

	if (list_no_entry(node, &curr->head, list)) {
		struct uftrace_session *sess = tg->graph->sess;

		node = xzalloc(node_size);

		node->id = next_id++;
		node->addr = fstack->addr;
		node->name = xstrdup(name ?: "none");
		INIT_LIST_HEAD(&node->head);

		node->parent = curr;
		list_add_tail(&node->list, &node->parent->head);
		node->parent->nr_edges++;

		node->loc = loc;

		if (sess && uftrace_match_filter(&sess->fixups, fstack->addr)) {
			struct uftrace_symbol *sym;
			struct uftrace_special_node *snode;
			enum uftrace_graph_node_type type = NODE_T_NORMAL;

			sym = find_symtabs(&sess->sym_info, fstack->addr);
			if (sym == NULL)
				goto out;

			if (!strcmp(sym->name, "fork") || !strcmp(sym->name, "vfork") ||
			    !strcmp(sym->name, "daemon"))
				type = NODE_T_FORK;
			else if (!strncmp(sym->name, "exec", 4))
				type = NODE_T_EXEC;
			else
				goto out;

			snode = xmalloc(sizeof(*snode));
			snode->node = node;
			snode->type = type;
			snode->pid = tg->task->t->pid;

			/* find recent one first */
			list_add(&snode->list, &tg->graph->special_nodes);
		}
	}

out:
	node->nr_calls++;
	tg->node = node;

	if (entry_cb)
		entry_cb(tg, cb_arg);

	return 0;
}

static void update_graph_node_times(struct uftrace_graph_node *node, struct uftrace_fstack *fstack)
{
	uint64_t self_time;

	node->time += fstack->total_time;
	node->child_time += fstack->child_time;

	self_time = fstack->total_time > fstack->child_time ?
			    fstack->total_time - fstack->child_time :
			    0;

	if (node->total.min > fstack->total_time || node->total.min == 0)
		node->total.min = fstack->total_time;
	if (node->total.max < fstack->total_time)
		node->total.max = fstack->total_time;

	if (node->self.min > self_time || node->self.min == 0)
		node->self.min = self_time;
	if (node->self.max < self_time)
		node->self.max = self_time;
}

static int add_graph_exit(struct uftrace_task_graph *tg)
{
	struct uftrace_fstack *fstack = fstack_get(tg->task, tg->task->stack_count);
	struct uftrace_graph_node *node = tg->node;

	if (node == NULL || fstack == NULL)
		return -1;

	if (tg->lost) {
		if (is_kernel_address(&tg->task->h->sessions.first->sym_info, fstack->addr))
			return 1;

		/*
		 * LOST only occurs in kernel, so clear tg->lost
		 * when return to userspace
		 */
		tg->lost = false;
	}

	if (node->addr != fstack->addr) {
		struct uftrace_special_node *snode, *tmp;

		list_for_each_entry_safe(snode, tmp, &tg->graph->special_nodes, list) {
			if (snode->node->addr == tg->task->rstack->addr &&
			    snode->type == NODE_T_FORK && snode->pid == tg->task->t->ppid) {
				node = snode->node;
				list_del(&snode->list);
				free(snode);
				pr_dbg("recover from fork\n");
				goto out;
			}
		}
		pr_dbg("broken graph - addresses not match\n");
	}

out:
	update_graph_node_times(node, fstack);

	if (exit_cb)
		exit_cb(tg, cb_arg);

	tg->node = node->parent;

	return 0;
}

static int add_graph_event(struct uftrace_task_graph *tg, size_t node_size)
{
	struct uftrace_record *rec = tg->task->rstack;

	if (event_cb)
		event_cb(tg, cb_arg);

	if (rec->addr == EVENT_ID_PERF_SCHED_OUT) {
		/* to match addr with sched-in */
		rec->addr = EVENT_ID_PERF_SCHED_IN;
		return add_graph_entry(tg, sched_sym.name, node_size, NULL);
	}
	else if (rec->addr == EVENT_ID_PERF_SCHED_OUT_PREEMPT) {
		/* to match addr with sched-in */
		rec->addr = EVENT_ID_PERF_SCHED_IN;
		return add_graph_entry(tg, sched_preempt_sym.name, node_size, NULL);
	}
	else if (rec->addr == EVENT_ID_PERF_SCHED_IN) {
		return add_graph_exit(tg);
	}

	return -1;
}

/* graph_add_node is not thread-safe due to static id of uftrace_graph_node */
int graph_add_node(struct uftrace_task_graph *tg, int type, char *name, size_t node_size,
		   struct uftrace_dbg_loc *loc)
{
	if (type == UFTRACE_ENTRY)
		return add_graph_entry(tg, name, node_size, loc);
	else if (type == UFTRACE_EXIT)
		return add_graph_exit(tg);
	else if (type == UFTRACE_EVENT)
		return add_graph_event(tg, node_size);
	else
		return 0;
}

struct uftrace_graph_node *graph_find_node(struct uftrace_graph_node *parent, uint64_t addr)
{
	struct uftrace_graph_node *node;

	list_for_each_entry(node, &parent->head, list) {
		if (addr == node->addr)
			return node;
	}

	return NULL;
}

static void graph_destroy_node(struct uftrace_graph_node *node)
{
	struct uftrace_graph_node *child, *tmp;

	list_for_each_entry_safe(child, tmp, &node->head, list)
		graph_destroy_node(child);

	list_del(&node->list);
	free(node->name);
	free(node);
}

void graph_destroy(struct uftrace_graph *graph)
{
	struct uftrace_graph_node *node, *tmp;
	struct uftrace_special_node *snode, *stmp;

	list_for_each_entry_safe(node, tmp, &graph->root.head, list)
		graph_destroy_node(node);

	list_for_each_entry_safe(snode, stmp, &graph->special_nodes, list) {
		list_del(&snode->list);
		free(snode);
	}
}

void graph_remove_task(void)
{
	struct rb_node *node;
	struct uftrace_task_graph *tg;

	while (!RB_EMPTY_ROOT(&task_graph_root)) {
		node = rb_first(&task_graph_root);
		tg = rb_entry(node, struct uftrace_task_graph, link);

		rb_erase(node, &task_graph_root);
		free(tg);
	}
}

#ifdef UNIT_TEST

struct test_data {
	int type;
	uint64_t addr;
	uint64_t total_time;
	uint64_t child_time;
	const char *name;
};

static void setup_fstack_and_graph(struct uftrace_graph *graph, struct test_data *data, size_t len)
{
	size_t i;
	struct uftrace_task_graph *tg;
	struct uftrace_graph_node *node;
	struct uftrace_task_reader task = {
		.tid = 1234,
	};

	tg = graph_get_task(&task, sizeof(*tg));
	tg->graph = graph;
	tg->new_sess = true;

	/* TODO: de-couple graph from fstack */
	task.func_stack = xcalloc(len, sizeof(*task.func_stack));

	for (i = 0; i < len; i++) {
		struct uftrace_fstack *fstack = NULL;

		if (data[i].type == UFTRACE_ENTRY)
			fstack = &task.func_stack[task.stack_count++];
		else if (data[i].type == UFTRACE_EXIT)
			fstack = &task.func_stack[--task.stack_count];

		if (fstack) {
			fstack->addr = data[i].addr;
			fstack->total_time = data[i].total_time;
			fstack->child_time = data[i].child_time;
		}

		graph_add_node(tg, data[i].type, (char *)data[i].name, sizeof(*node), NULL);
	}

	free(task.func_stack);
}

TEST_CASE(graph_basic)
{
	struct uftrace_graph graph;
	struct uftrace_graph_node *node;
	/*
	 * (root)
	 *  +-- (1) foo
	 *  |
	 *  +-- (1) bar
	 *      (1) baz
	 */
	struct test_data data[] = {
		{
			UFTRACE_ENTRY,
			0x1000,
			0,
			0,
			"foo",
		},
		{
			UFTRACE_EXIT,
			0x1000,
			100,
			0,
			"foo",
		},
		{
			UFTRACE_ENTRY,
			0x2000,
			0,
			0,
			"bar",
		},
		{
			UFTRACE_ENTRY,
			0x3000,
			0,
			0,
			"baz",
		},
		{
			UFTRACE_EXIT,
			0x3000,
			200,
			0,
			"baz",
		},
		{
			UFTRACE_EXIT,
			0x2000,
			500,
			200,
			"bar",
		},
	};

	pr_dbg("init graph and add data\n");
	graph_init(&graph, NULL);
	setup_fstack_and_graph(&graph, data, ARRAY_SIZE(data));

	pr_dbg("check graph root\n");
	TEST_EQ(graph.root.nr_edges, 2);

	pr_dbg("check graph node: foo\n");
	node = graph_find_node(&graph.root, data[1].addr);
	TEST_NE(node, NULL);
	TEST_STREQ(node->name, data[1].name);
	TEST_EQ(node->time, data[1].total_time);
	TEST_EQ(node->child_time, data[1].child_time);
	TEST_EQ(node->nr_calls, 1);

	pr_dbg("check graph node: bar\n");
	node = graph_find_node(&graph.root, data[5].addr);
	TEST_NE(node, NULL);
	TEST_STREQ(node->name, data[5].name);
	TEST_EQ(node->time, data[5].total_time);
	TEST_EQ(node->child_time, data[5].child_time);
	TEST_EQ(node->nr_calls, 1);

	pr_dbg("check graph node: baz\n");
	node = graph_find_node(node, data[4].addr);
	TEST_NE(node, NULL);
	TEST_STREQ(node->name, data[4].name);
	TEST_EQ(node->time, data[4].total_time);
	TEST_EQ(node->child_time, data[4].child_time);
	TEST_EQ(node->nr_calls, 1);

	pr_dbg("destroy graph and data\n");
	graph_destroy(&graph);
	graph_remove_task();

	return TEST_OK;
}

#endif /* UNIT_TEST */
