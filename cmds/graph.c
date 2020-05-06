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
#include "utils/field.h"
#include "utils/graph.h"

static LIST_HEAD(output_fields);
static LIST_HEAD(output_task_fields);

struct graph_backtrace {
	struct list_head list;
	int len;
	int hit;
	uint64_t time;
	uint64_t addr[];
};

struct session_graph {
	struct uftrace_graph ug;
	struct graph_backtrace *bt_curr;
	struct list_head bt_list;
	struct session_graph *next;
	char *func;
};

struct task_graph {
	struct uftrace_task_graph utg;
	struct graph_backtrace *bt_curr;
	int enabled;
};

static bool full_graph = false;
static struct session_graph *graph_list = NULL;

static void print_total_time(struct field_data *fd)
{
	struct uftrace_graph_node *node = fd->arg;
	uint64_t d;

	d = node->time;

	print_time_unit(d);
}

static void print_self_time(struct field_data *fd)
{
	struct uftrace_graph_node *node = fd->arg;
	uint64_t d;

	d = node->time - node->child_time;

	print_time_unit(d);
}

static void print_addr(struct field_data *fd)
{
	struct uftrace_graph_node *node = fd->arg;

	/* uftrace records (truncated) 48-bit addresses */
	int width = sizeof(long) == 4 ? 8 : 12;

	pr_out("%*"PRIx64, width, effective_addr(node->addr));
}

static struct display_field field_total_time= {
	.id      = GRAPH_F_TOTAL_TIME,
	.name    = "total-time",
	.alias   = "total",
	.header  = "TOTAL TIME",
	.length  = 10,
	.print   = print_total_time,
	.list    = LIST_HEAD_INIT(field_total_time.list),
};

static struct display_field field_self_time= {
	.id      = GRAPH_F_SELF_TIME,
	.name    = "self-time",
	.alias   = "self",
	.header  = " SELF TIME",
	.length  = 10,
	.print   = print_self_time,
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
	.print   = print_addr,
	.list    = LIST_HEAD_INIT(field_addr.list),
};

static void print_task_total_time(struct field_data *fd)
{
	struct uftrace_task *node = fd->arg;
	uint64_t d;

	d = node->time.run;

	print_time_unit(d);
}

static void print_task_self_time(struct field_data *fd)
{
	struct uftrace_task *node = fd->arg;
	uint64_t d;

	d = node->time.run - node->time.idle;

	print_time_unit(d);
}

static void print_task_tid(struct field_data *fd)
{
	struct uftrace_task *task = fd->arg;
	pr_out("[%6d]", task->tid);
}

static struct display_field field_task_total_time = {
	.id      = GRAPH_F_TASK_TOTAL_TIME,
	.name    = "total-time",
	.alias   = "total",
	.header  = "TOTAL TIME",
	.length  = 10,
	.print   = print_task_total_time,
	.list    = LIST_HEAD_INIT(field_task_total_time.list),
};

static struct display_field field_task_self_time = {
	.id      = GRAPH_F_TASK_SELF_TIME,
	.name    = "self-time",
	.alias   = "self",
	.header  = " SELF TIME",
	.length  = 10,
	.print   = print_task_self_time,
	.list    = LIST_HEAD_INIT(field_task_self_time.list),
};

static struct display_field field_task_tid = {
	.id      = GRAPH_F_TASK_TID,
	.name    = "tid",
	.header  = "   TID  ",
	.length  = 8,
	.print   = print_task_tid,
	.list    = LIST_HEAD_INIT(field_task_tid.list),
};

/* index of this table should be matched to display_field_id */
static struct display_field *field_table[] = {
	&field_total_time,
	&field_self_time,
	&field_addr,
};

/* index of this task table should be matched to display_field_id */
static struct display_field *field_task_table[] = {
	&field_task_total_time,
	&field_task_self_time,
	&field_task_tid,
};

static void setup_default_field(struct list_head *fields, struct opts *opts)
{
	add_field(fields, field_table[GRAPH_F_TOTAL_TIME]);
}

static void setup_default_task_field(struct list_head *fields, struct opts *opts)
{
	add_field(fields, field_task_table[GRAPH_F_TASK_TOTAL_TIME]);
	add_field(fields, field_task_table[GRAPH_F_TASK_SELF_TIME]);
	add_field(fields, field_task_table[GRAPH_F_TASK_TID]);
}

static void print_field(struct uftrace_graph_node *node)
{
	struct field_data fd = {
		.arg = node,
	};

	if (print_field_data(&output_fields, &fd, 2))
		pr_out(" : ");
}

static void print_task_field(struct uftrace_task *node)
{
	struct field_data fd = {
		.arg = node,
	};

	if (print_field_data(&output_task_fields, &fd, 2))
		pr_out(" : ");
}

static int create_graph(struct uftrace_session *sess, void *func)
{
	struct session_graph *graph = xzalloc(sizeof(*graph));

	pr_dbg("create graph for session %.*s (%s)\n",
	       SESSION_ID_LEN, sess->sid, sess->exename);

	graph->func = xstrdup(full_graph ? basename(sess->exename) : func);
	INIT_LIST_HEAD(&graph->bt_list);

	graph_init(&graph->ug, sess);
	graph->ug.root.name = graph->func;

	graph->next = graph_list;
	graph_list = graph;

	return 0;
}

static void setup_graph_list(struct uftrace_data *handle, struct opts *opts,
			     char *func)
{
	struct session_graph *graph;

	walk_sessions(&handle->sessions, create_graph, func);

	graph = graph_list;
	while (graph) {
		graph->ug.kernel_only = opts->kernel_only;
		graph = graph->next;
	}
}

static struct uftrace_graph * get_graph(struct uftrace_task_reader *task,
					uint64_t time, uint64_t addr)
{
	struct session_graph *graph;
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

	graph = graph_list;
	while (graph) {
		if (graph->ug.sess == sess)
			return &graph->ug;

		graph = graph->next;
	}
	return NULL;
}

static int start_graph(struct task_graph *tg);

static struct task_graph * get_task_graph(struct uftrace_task_reader *task,
					  uint64_t time, uint64_t addr)
{
	struct task_graph *tg;
	struct uftrace_graph *graph;

	tg = (struct task_graph *)graph_get_task(task, sizeof(*tg));

	graph = get_graph(task, time, addr);

	if (tg->utg.graph && tg->utg.graph != graph) {
		pr_dbg("detect new session: %.*s\n",
		       SESSION_ID_LEN, graph->sess->sid);
		tg->utg.new_sess = true;
	}
	tg->utg.graph = graph;

	if (full_graph && tg->utg.node == NULL)
		start_graph(tg);

	return tg;
}

static int save_backtrace_addr(struct task_graph *tg)
{
	int i;
	int skip = 0;
	struct graph_backtrace *bt;
	struct uftrace_task_reader *task = tg->utg.task;
	struct session_graph *graph = (struct session_graph *)tg->utg.graph;
	int len = task->stack_count;
	uint64_t addrs[len];

	if (graph->ug.kernel_only) {
		skip = task->user_stack_count;
		len -= skip;
	}

	if (len == 0)
		return 0;

	for (i = len - 1; i >= 0; i--) {
		struct fstack *fstack = fstack_get(task, i + skip);

		if (fstack != NULL)
			addrs[i] = fstack->addr;
		else
			addrs[i] = 0;
	}

	list_for_each_entry(bt, &graph->bt_list, list) {
		if (len == bt->len &&
		    !memcmp(addrs, bt->addr, len * sizeof(*addrs)))
			goto found;
	}

	bt = xmalloc(sizeof(*bt) + len * sizeof(*addrs));

	bt->len = len;
	bt->hit = 0;
	bt->time = 0;
	memcpy(bt->addr, addrs, len * sizeof(*addrs));

	list_add(&bt->list, &graph->bt_list);

found:
	bt->hit++;
	tg->bt_curr = bt;

	return 0;
}

static void save_backtrace_time(struct task_graph *tg)
{
	struct uftrace_task_reader *task = tg->utg.task;
	struct fstack *fstack = fstack_get(task, task->stack_count);

	if (tg->bt_curr != NULL && fstack != NULL)
		tg->bt_curr->time += fstack->total_time;

	tg->bt_curr = NULL;
}

static int print_backtrace(struct session_graph *graph)
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
			sym = find_symtabs(&graph->ug.sess->symtabs, bt->addr[k]);
			if (sym == NULL)
				sym = session_find_dlsym(graph->ug.sess,
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
	if (tg->utg.graph && !tg->enabled++) {
		save_backtrace_addr(tg);

		pr_dbg("start graph for task %d\n", tg->utg.task->tid);

		tg->utg.node = &tg->utg.graph->root;
		tg->utg.node->addr = tg->utg.task->rstack->addr;
		tg->utg.node->nr_calls++;
	}

	return 0;
}

static int end_graph(struct task_graph *tg)
{
	if (!tg->enabled)
		return 0;

	if (!--tg->enabled) {
		save_backtrace_time(tg);
		tg->utg.lost = false;

		pr_dbg("end graph for task %d\n", tg->utg.task->tid);
	}

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
			     struct uftrace_graph_node *node,
			     bool *indent_mask,
			     int indent, bool needs_line)
{
	char *symname = node->name;
	struct uftrace_graph_node *parent = node->parent;
	struct uftrace_graph_node *child;
	int orig_indent = indent;

	/* XXX: what if it clashes with existing function address */
	if (node->addr == EVENT_ID_PERF_SCHED_IN)
		symname = "linux:schedule";

	print_field(node);
	pr_indent(indent_mask, indent, needs_line);

	/* FIXME: it should count fork+exec properly */
	if (full_graph && node == &graph->root)
		pr_out("(%d) %s\n", 1, symname);
	else
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
			if (print_empty_field(&output_fields, 2))
				pr_out(" : ");
			pr_indent(indent_mask, indent, false);
			pr_out("\n");
		}
	}

	indent_mask[orig_indent] = false;
	pr_dbg2("del mask (%d) for %s\n", orig_indent, symname);
}

static int print_graph(struct session_graph *graph, struct opts *opts)
{
	bool *indent_mask;

	/* skip empty graph */
	if (list_empty(&graph->bt_list) && graph->ug.root.time == 0 &&
	    graph->ug.root.nr_edges == 0)
		return 0;

	pr_out("# Function Call Graph for '%s' (session: %.16s)\n",
	       graph->func, graph->ug.sess->sid);

	if (!full_graph && !list_empty(&graph->bt_list)) {
		pr_out("=============== BACKTRACE ===============\n");
		print_backtrace(graph);
	}

	setup_field(&output_fields, opts, &setup_default_field, field_table, ARRAY_SIZE(field_table));

	if (graph->ug.root.time || graph->ug.root.nr_edges) {
		pr_out("========== FUNCTION CALL GRAPH ==========\n");
		print_header(&output_fields, "# ", "FUNCTION", 2, true);
		indent_mask = xcalloc(opts->max_stack, sizeof(*indent_mask));
		print_graph_node(&graph->ug, &graph->ug.root, indent_mask, 0,
				 graph->ug.root.nr_edges > 1);
		free(indent_mask);
		pr_out("\n");
	}
	return 1;
}

static void build_graph_node(struct opts *opts,
			     struct uftrace_task_reader *task, uint64_t time,
			     uint64_t addr, int type, char *func)
{
	struct task_graph *tg;
	struct sym *sym = NULL;
	char *name;

	tg = get_task_graph(task, time, addr);
	if (unlikely(tg->utg.graph == NULL))
		return;

	sym = find_symtabs(&tg->utg.graph->sess->symtabs, addr);
	if (sym == NULL)
		sym = session_find_dlsym(tg->utg.graph->sess, time, addr);

	name = symbol_getname(sym, addr);

	/* skip it if --no-libcall is given */
	if (!opts->libcall && sym && sym->type == ST_PLT_FUNC)
		goto out;

	if (tg->enabled) {
		graph_add_node(&tg->utg, type, name,
			       sizeof(struct uftrace_graph_node));
	}

	/* cannot find a session for this record */
	if (tg->utg.graph == NULL)
		goto out;
	if (type == UFTRACE_EVENT)
		goto out;
	if (full_graph)
		goto out;

	if (!strcmp(name, func)) {
		if (type == UFTRACE_ENTRY)
			start_graph(tg);
		else if (type == UFTRACE_EXIT)
			end_graph(tg);
	}

out:
	symbol_putname(sym, name);
}

static void build_graph(struct opts *opts, struct uftrace_data *handle,
		       char *func)
{
	struct uftrace_task_reader *task;
	struct session_graph *graph;
	uint64_t prev_time = 0;
	int i;

	setup_graph_list(handle, opts, func);

	while (!read_rstack(handle, &task) && !uftrace_done) {
		struct uftrace_record *frs = task->rstack;
		uint64_t addr = frs->addr;

		if (!fstack_check_opts(task, opts))
			continue;

		if (!fstack_check_filter(task))
			continue;

		if (frs->type == UFTRACE_EVENT) {
			if (frs->addr != EVENT_ID_PERF_SCHED_IN &&
			    frs->addr != EVENT_ID_PERF_SCHED_OUT)
				continue;
		}

		if (is_kernel_record(task, frs)) {
			struct uftrace_session *fsess;

			fsess = task->h->sessions.first;
			addr = get_kernel_address(&fsess->symtabs, addr);
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

				fstack = fstack_get(task, task->stack_count);

				if (fstack_enabled && fstack && fstack->valid &&
				    !(fstack->flags & FSTACK_FL_NORECORD)) {
					build_graph_node(opts, task, prev_time,
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
			tg->utg.lost = true;

			if (tg->enabled && is_kernel_address(&fsess->symtabs,
							     tg->utg.node->addr))
				pr_dbg("not returning to user after LOST\n");

			continue;
		}

		if (prev_time > frs->time) {
			pr_warn("inverted time: broken data?\n");
			return;
		}
		prev_time = frs->time;

		build_graph_node(opts, task, frs->time, addr, frs->type, func);
		fstack_check_filter_done(task);
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
			fstack = fstack_get(task, task->stack_count);
			if (fstack == NULL)
				continue;

			if (fstack->addr == 0)
				continue;

			if (fstack->total_time > last_time)
				continue;

			fstack->total_time = last_time - fstack->total_time;
			if (fstack->child_time > fstack->total_time)
				fstack->total_time = fstack->child_time;

			if (task->stack_count > 0)
				fstack[-1].child_time += fstack->total_time;

			build_graph_node(opts, task, last_time, fstack->addr,
					 UFTRACE_EXIT, func);
		}
	}

	if (!full_graph || uftrace_done)
		return;

	/* account execution time of each graph */
	graph = graph_list;
	while (graph) {
		struct uftrace_graph_node *node;

		list_for_each_entry(node, &graph->ug.root.head, list) {
			graph->ug.root.time += node->time;
			graph->ug.root.child_time += node->time;
		}

		graph = graph->next;
	}
}

struct find_func_data {
	char *name;
	bool found;
};

static int find_func(struct uftrace_session *s, void *arg)
{
	struct find_func_data *data = arg;
	struct symtabs *symtabs = &s->symtabs;
	struct uftrace_mmap *map;

	for_each_map(symtabs, map) {
		if (map->mod == NULL)
			continue;

		if (find_symname(&map->mod->symtab, data->name)) {
			data->found = true;
			break;
		}
	}

	return data->found;
}

static void synthesize_depth_trigger(struct opts *opts,
				     struct uftrace_data *handle,
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

static void reset_task_runtime(struct uftrace_data *handle)
{
	struct uftrace_task *t;
	struct rb_node *n = rb_first(&handle->sessions.tasks);

	while (n != NULL) {
		t = rb_entry(n, struct uftrace_task, node);
		n = rb_next(n);

		t->time.run = 0;
		t->time.idle = 0;
		t->time.stamp = 0;
	}
}

static void graph_build_task(struct opts *opts, struct uftrace_data *handle)
{
	struct uftrace_task_reader *task;
	struct uftrace_task *t;
	int i;

	/*
	 * we need to know entire runtime, so not apply time filter now
	 * and it will be filtered when it's printed.
	 */
	handle->time_filter = 0;
	reset_task_runtime(handle);

	while (!read_rstack(handle, &task) && !uftrace_done) {
		struct uftrace_record *frs = task->rstack;

		if (!fstack_check_opts(task, opts))
			continue;

		if (!fstack_check_filter(task))
			continue;

		if (task->timestamp == 0)
			task->timestamp = frs->time;
		task->timestamp_last = frs->time;

		t = task->t;

		if (frs->type == UFTRACE_EVENT) {
			switch (frs->addr) {
			case EVENT_ID_PERF_SCHED_OUT:
				t->time.stamp = frs->time;
				break;
			case EVENT_ID_PERF_SCHED_IN:
				if (t->time.stamp)
					t->time.idle += frs->time - t->time.stamp;
				t->time.stamp = 0;
				break;
			}
		}

		fstack_check_filter_done(task);
	}

	/* update task time if some records were missing */
	for (i = 0; i < handle->nr_tasks; i++) {
		task = &handle->tasks[i];
		t = task->t;

		/* update idle time if last SCHED_IN event was missing */
		if (t->time.stamp)
			t->time.idle += task->timestamp_last - t->time.stamp;

		t->time.run = task->timestamp_last - task->timestamp;
	}
	handle->time_filter = opts->threshold;
}

/* returns true if any of child has more runtime than the filter */
static bool check_time_filter(struct uftrace_task *task, struct opts *opts)
{
	struct uftrace_task *child;

	list_for_each_entry(child, &task->children, siblings) {
		if (child->time.run >= opts->threshold)
			return true;
		if (check_time_filter(child, opts))
			return true;
	}
	return false;
}

static bool is_last_child(struct uftrace_task *task,
			  struct uftrace_task *parent,
			  struct opts *opts)
{
	if (list_is_singular(&parent->children) ||
	    parent->children.prev == &task->siblings)
		return true;

	/* any sibling satisfies the time filter? */
	list_for_each_entry_continue(task, &parent->children, siblings) {
		if (task->time.run >= opts->threshold ||
		    check_time_filter(task, opts))
			return false;
	}
	return true;
}

static bool print_task_node(struct uftrace_task *task,
			    struct uftrace_task *parent,
			    bool *indent_mask, int indent,
			    struct opts *opts)
{
	char *name = task->comm;
	struct uftrace_task *child;
	int orig_indent = indent;
	bool blank = false;

	if (uftrace_done)
		return false;

	print_task_field(task);
	pr_indent(indent_mask, indent, true);
	if (parent && parent->pid == task->pid) {
		/* print thread name in green color */
		pr_green("%s\n", name);
	}
	else {
		/* print process name */
		pr_out("%s\n", name);
	}

	if (list_empty(&task->children) || !check_time_filter(task, opts))
		return false;

	/* clear parent indent mask at the last node */
	if (parent && is_last_child(task, parent, opts)) {
		int parent_indent = orig_indent - 1;

		if (task->pid != parent->pid)
			parent_indent--;

		indent_mask[parent_indent] = false;
	}

	list_for_each_entry(child, &task->children, siblings) {
		/*
		 * Filter out if total time is less than time-filter.
		 * Note that child might live longer than parent.
		 * In that case we should print the parent even if it's
		 * shorter than the time filter to show a correct tree.
		 */
		if (opts->threshold > child->time.run &&
		    !check_time_filter(child, opts))
			continue;

		indent = orig_indent;

		indent_mask[indent++] = true;
		if (child->pid != task->pid) {
			/* print blank line before forked child */
			blank = true;
			indent++;
		}

		if (blank) {
			/* print blank line between siblings */
			if (print_empty_field(&output_task_fields, 2))
				pr_out(" : ");
			pr_indent(indent_mask, indent, false);
			pr_out("\n");

			blank = false;
		}

		blank |= print_task_node(child, task, indent_mask, indent, opts);

		if (&child->siblings != task->children.prev &&
		    child->pid != task->pid) {
			/* print blank line after forked child */
			blank = true;
		}
	}
	indent_mask[orig_indent] = false;
	return blank;
}

static int graph_print_task(struct uftrace_data *handle, struct opts *opts)
{
	bool *indent_mask;
	struct uftrace_task *task;

	if (uftrace_done)
		return 0;

	if (handle->nr_tasks <= 0)
		return 0;

	task = handle->sessions.first_task;

	setup_field(&output_task_fields, opts, &setup_default_task_field,
		    field_task_table, ARRAY_SIZE(field_task_table));

	pr_out("========== TASK GRAPH ==========\n");
	print_header(&output_task_fields, "# ", "TASK NAME", 2, true);

	indent_mask = xcalloc(handle->nr_tasks, sizeof(*indent_mask));

	/* filter out if total time is less than time-filter */
	if (opts->threshold <= task->time.run)
		print_task_node(task, NULL, indent_mask, 0, opts);

	free(indent_mask);
	pr_out("\n");
	return 1;
}

int command_graph(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct uftrace_data handle;
	struct session_graph *graph;
	char *func;
	struct graph_backtrace *bt, *btmp;

	__fsetlocking(outfp, FSETLOCKING_BYCALLER);
	__fsetlocking(logfp, FSETLOCKING_BYCALLER);

	if (argc > 0)
		func = argv[0];
	else {
		func = "_start";
		full_graph = true;
	}

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
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

	if (opts->show_task) {
		graph_build_task(opts, &handle);
		graph_print_task(&handle, opts);
		goto out;
	}

	build_graph(opts, &handle, func);

	graph = graph_list;
	while (graph && !uftrace_done) {
		ret += print_graph(graph, opts);
		graph = graph->next;
	}

	if (!ret && !uftrace_done) {
		pr_out("uftrace: cannot find graph for '%s'\n", func);
		if (opts_has_filter(opts))
			pr_out("\t please check your filter settings.\n");
	}

	while (graph_list) {
		graph = graph_list;
		graph_list = graph->next;

		free(graph->func);
		list_for_each_entry_safe(bt, btmp, &graph->bt_list, list) {
			list_del(&bt->list);
			free(bt);
		}
		graph_destroy(&graph->ug);
		free(graph);
	}
	graph_remove_task();

out:
	close_data_file(opts, &handle);

	return 0;
}
