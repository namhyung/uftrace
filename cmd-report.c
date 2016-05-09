#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"
#include "utils/list.h"
#include "utils/fstack.h"


enum {
	AVG_NONE,
	AVG_TOTAL,
	AVG_SELF,
} avg_mode = AVG_NONE;

struct trace_entry {
	int pid;
	struct sym *sym;
	uint64_t addr;
	uint64_t time_total;
	uint64_t time_self;
	uint64_t time_avg;
	uint64_t time_min;
	uint64_t time_max;
	unsigned long nr_called;
	struct rb_node link;
};

static void insert_entry(struct rb_root *root, struct trace_entry *te, bool thread)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	uint64_t entry_time = 0;

	pr_dbg3("%s: [%5d] %"PRIu64"/%"PRIu64" (%lu) %-s\n",
		__func__, te->pid, te->time_total, te->time_self, te->nr_called,
		te->sym ? te->sym->name : "<unknown>");

	while (*p) {
		int cmp;

		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (thread)
			cmp = te->pid - entry->pid;
		else
			cmp = te->addr - entry->addr;

		if (cmp == 0) {
			entry->time_total += te->time_total;
			entry->time_self  += te->time_self;
			entry->nr_called  += te->nr_called;

			if (avg_mode == AVG_TOTAL)
				entry_time = te->time_total;
			else if (avg_mode == AVG_SELF)
				entry_time = te->time_self;

			if (entry->time_min > entry_time)
				entry->time_min = entry_time;
			if (entry->time_max < entry_time)
				entry->time_max = entry_time;

			if (entry->sym == NULL && te->sym)
				entry->sym = te->sym;

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
	entry->addr = te->addr;
	entry->time_total = te->time_total;
	entry->time_self  = te->time_self;
	entry->nr_called  = te->nr_called;

	if (avg_mode == AVG_TOTAL)
		entry_time = te->time_total;
	else if (avg_mode == AVG_SELF)
		entry_time = te->time_self;

	entry->time_min = entry_time;
	entry->time_max = entry_time;

	rb_link_node(&entry->link, parent, p);
	rb_insert_color(&entry->link, root);
}

static void build_function_tree(struct ftrace_file_handle *handle,
				struct rb_root *root)
{
	struct sym *sym;
	struct trace_entry te;
	struct ftrace_ret_stack *rstack;
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

		sym = find_symtabs(&sess->symtabs, rstack->addr);

		fstack = &task->func_stack[rstack->depth];

		te.pid = task->tid;
		te.sym = sym;
		te.addr = rstack->addr;
		te.time_total = fstack->total_time;
		te.time_self = te.time_total - fstack->child_time;
		te.nr_called = 1;

		insert_entry(root, &te, false);
	}
}

struct sort_item {
	const char *name;
	int (*cmp)(struct trace_entry *a, struct trace_entry *b);
	int avg_mode;
	struct list_head list;
};

#define SORT_ITEM(_name, _field, _mode)					\
static int cmp_##_field(struct trace_entry *a, struct trace_entry *b) 	\
{									\
	if (a->_field == b->_field)					\
		return 0;						\
	return a->_field > b->_field ? 1 : -1;				\
}									\
static struct sort_item sort_##_field = {				\
	.name = _name,							\
	.cmp = cmp_##_field,						\
	.avg_mode = _mode,						\
	LIST_HEAD_INIT(sort_##_field.list)				\
}

SORT_ITEM("total", time_total, AVG_NONE);
SORT_ITEM("self", time_self, AVG_NONE);
SORT_ITEM("call", nr_called, AVG_NONE);
SORT_ITEM("avg", time_avg, AVG_TOTAL);
SORT_ITEM("min", time_min, AVG_TOTAL);
SORT_ITEM("max", time_max, AVG_TOTAL);

struct sort_item *all_sort_items[] = {
	&sort_time_total,
	&sort_time_self,
	&sort_nr_called,
	&sort_time_avg,
	&sort_time_min,
	&sort_time_max,
};

static LIST_HEAD(sort_list);

static int cmp_entry(struct trace_entry *a, struct trace_entry *b)
{
	int ret;
	struct sort_item *item;

	list_for_each_entry(item, &sort_list, list) {
		ret = item->cmp(a, b);
		if (ret)
			return ret;
	}
	return 0;
}

static void sort_entries(struct rb_root *root, struct trace_entry *te)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (cmp_entry(entry, te) < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&te->link, parent, p);
	rb_insert_color(&te->link, root);
}

static void setup_sort(char *sort_keys)
{
	char *keys = xstrdup(sort_keys);
	char *k, *p = keys;
	unsigned i;

	while ((k = strtok(p, ",")) != NULL) {
		for (i = 0; i < ARRAY_SIZE(all_sort_items); i++) {
			if (strcmp(k, all_sort_items[i]->name))
				continue;

			if (all_sort_items[i]->avg_mode != (avg_mode != AVG_NONE)) {
				pr_out("ftrace: '%s' sort key %s be used with %s or %s.\n",
				       all_sort_items[i]->name,
				       avg_mode == AVG_NONE ? "should" : "cannot",
				       "--avg-total", "--avg-self");
				exit(1);
			}

			list_add_tail(&all_sort_items[i]->list, &sort_list);
			break;
		}

		if (i == ARRAY_SIZE(all_sort_items)) {
			pr_out("ftrace: Unknown sort key '%s'\n", k);
			pr_out("ftrace:   Possible keys:");
			for (i = 0; i < ARRAY_SIZE(all_sort_items); i++)
				pr_out(" %s", all_sort_items[i]->name);
			pr_out("\n");
			exit(1);
		}
		p = NULL;
	}
	free(keys);
}

static void print_function(struct trace_entry *entry)
{
	char *symname = symbol_getname(entry->sym, entry->addr);

	if (avg_mode == AVG_NONE) {
		pr_out(" ");
		print_time_unit(entry->time_total);
		pr_out(" ");
		print_time_unit(entry->time_self);
		pr_out("  %10lu  %-s\n", entry->nr_called, symname);
	} else {
		pr_out(" ");
		print_time_unit(entry->time_avg);
		pr_out(" ");
		print_time_unit(entry->time_min);
		pr_out(" ");
		print_time_unit(entry->time_max);
		pr_out("  %-s\n", symname);
	}

	symbol_putname(entry->sym, symname);
}

static void report_functions(struct ftrace_file_handle *handle)
{
	struct rb_root name_tree = RB_ROOT;
	struct rb_root sort_tree = RB_ROOT;
	struct rb_node *node;
	const char f_format[] = "  %10.10s  %10.10s  %10.10s  %-s\n";
	const char line[] = "====================================";

	build_function_tree(handle, &name_tree);

	while (!RB_EMPTY_ROOT(&name_tree)) {
		struct trace_entry *entry;

		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		entry = rb_entry(node, struct trace_entry, link);
		if (avg_mode == AVG_TOTAL)
			entry->time_avg = entry->time_total / entry->nr_called;
		else if (avg_mode == AVG_SELF)
			entry->time_avg = entry->time_self / entry->nr_called;

		sort_entries(&sort_tree, entry);
	}

	if (avg_mode == AVG_NONE)
		pr_out(f_format, "Total time", "Self time", "Nr. called", "Function");
	else if (avg_mode == AVG_TOTAL)
		pr_out(f_format, "Avg total", "Min total", "Max total", "Function");
	else if (avg_mode == AVG_SELF)
		pr_out(f_format, "Avg self", "Min self", "Max self", "Function");

	pr_out(f_format, line, line, line, line);

	for (node = rb_first(&sort_tree); node; node = rb_next(node)) {
		struct trace_entry *entry;

		entry = rb_entry(node, struct trace_entry, link);
		print_function(entry);
	}

	while (!RB_EMPTY_ROOT(&sort_tree)) {
		node = rb_first(&sort_tree);
		rb_erase(node, &sort_tree);

		free(rb_entry(node, struct trace_entry, link));
	}
}

static struct sym * find_task_sym(struct ftrace_file_handle *handle,
				  struct ftrace_task_handle *task,
				  struct ftrace_ret_stack *rstack)
{
	struct sym *sym;
	struct ftrace_task_handle *main_task = &handle->tasks[0];
	struct ftrace_session *sess = find_task_session(task->tid, rstack->time);
	struct symtabs *symtabs = &sess->symtabs;

	if (task->func)
		return task->func;

	if (sess == NULL) {
		pr_dbg("cannot find session for tid %d\n", task->tid);
		return NULL;
	}

	if (task == main_task) {
		/* This is the main thread */
		task->func = sym = find_symname(&symtabs->symtab, "main");
		if (sym)
			return sym;

		pr_dbg("no main thread???\n");
		/* fall through */
	}

	task->func = sym = find_symtabs(symtabs, rstack->addr);
	if (sym == NULL)
		pr_dbg("cannot find symbol for %lx\n", rstack->addr);

	return sym;
}

static void report_threads(struct ftrace_file_handle *handle)
{
	struct trace_entry te;
	struct ftrace_ret_stack *rstack;
	struct rb_root name_tree = RB_ROOT;
	struct rb_node *node;
	struct ftrace_task_handle *task;
	struct fstack *fstack;
	const char t_format[] = "  %5.5s  %10.10s  %10.10s  %-s\n";
	const char line[] = "====================================";

	while (read_rstack(handle, &task) >= 0) {
		rstack = task->rstack;
		if (rstack->type == FTRACE_ENTRY && task->func)
			continue;
		if (rstack->type == FTRACE_LOST)
			continue;

		fstack = &task->func_stack[rstack->depth];

		te.pid = task->tid;
		te.sym = find_task_sym(handle, task, rstack);
		te.addr = rstack->addr;

		if (rstack->type == FTRACE_ENTRY) {
			te.time_total = te.time_self = 0;
			te.nr_called = 0;
		}
		else {
			te.time_total = fstack->total_time;
			te.time_self = te.time_total - fstack->child_time;
			te.nr_called = 1;
		}

		insert_entry(&name_tree, &te, true);
	}

	pr_out(t_format, "TID", "Run time", "Num funcs", "Start function");
	pr_out(t_format, line, line, line, line);

	while (!RB_EMPTY_ROOT(&name_tree)) {
		char *symname;
		struct trace_entry *entry;

		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		entry = rb_entry(node, struct trace_entry, link);
		symname = symbol_getname(entry->sym, entry->addr);

		pr_out("  %5d ", entry->pid);
		print_time_unit(entry->time_self);
		pr_out("  %10lu  %-s\n", entry->nr_called, symname);

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

	if (opts->avg_total && opts->avg_self) {
		pr_out("--avg-total and --avg-self options should not be used together.\n");
		exit(1);
	} else if (opts->avg_total)
		avg_mode = AVG_TOTAL;
	else if (opts->avg_self)
		avg_mode = AVG_SELF;

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

	if (opts->tid)
		setup_task_filter(opts->tid, &handle);

	if (opts->sort_keys)
		setup_sort(opts->sort_keys);

	/* default: sort by total time */
	if (list_empty(&sort_list)) {
		if (avg_mode == AVG_NONE)
			list_add(&sort_time_total.list, &sort_list);
		else
			list_add(&sort_time_avg.list, &sort_list);
	}

	if (opts->report_thread)
		report_threads(&handle);
	else
		report_functions(&handle);

	if (handle.kern)
		finish_kernel_data(handle.kern);

	close_data_file(opts, &handle);

	return ret;
}
