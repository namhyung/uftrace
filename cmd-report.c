#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

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
	uint64_t time_recursive;
	uint64_t time_avg;
	uint64_t time_min;
	uint64_t time_max;
	unsigned long nr_called;
	struct trace_entry *pair;
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

			entry->time_recursive += te->time_recursive;

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
	entry->pair = NULL;

	if (avg_mode == AVG_TOTAL)
		entry_time = te->time_total;
	else if (avg_mode == AVG_SELF)
		entry_time = te->time_self;

	entry->time_min = entry_time;
	entry->time_max = entry_time;
	entry->time_recursive = te->time_recursive;

	rb_link_node(&entry->link, parent, p);
	rb_insert_color(&entry->link, root);
}

static void build_function_tree(struct ftrace_file_handle *handle,
				struct rb_root *root, struct opts *opts)
{
	struct sym *sym;
	struct trace_entry te;
	struct ftrace_ret_stack *rstack;
	struct ftrace_task_handle *task;
	struct ftrace_session *sess;
	struct fstack *fstack;
	int i;

	while (read_rstack(handle, &task) >= 0) {
		rstack = task->rstack;

		if (!fstack_check_filter(task))
			continue;

		if (rstack->type != FTRACE_EXIT)
			continue;

		/* skip user functions if --kernel-only is set */
		if (opts->kernel_only && !is_kernel_address(rstack->addr))
			continue;

		if (opts->kernel_skip_out) {
			/* skip kernel functions outside user functions */
			if (is_kernel_address(task->func_stack[0].addr) &&
			    is_kernel_address(rstack->addr))
				continue;
		}

		if (rstack == &task->kstack)
			sess = first_session;
		else
			sess = find_task_session(task->tid, rstack->time);

		if (sess == NULL)
			continue;

		sym = find_symtabs(&sess->symtabs, rstack->addr);

		fstack = &task->func_stack[task->stack_count];

		te.pid = task->tid;
		te.sym = sym;
		te.addr = rstack->addr;
		te.time_total = fstack->total_time;
		te.time_self = te.time_total - fstack->child_time;
		te.nr_called = 1;

		/* some LOST entries make invalid self tiem */
		if (te.time_self > te.time_total)
			te.time_self = te.time_total;

		te.time_recursive = 0;
		for (i = 0; i < task->stack_count; i++) {
			if (rstack->addr == task->func_stack[i].addr) {
				te.time_recursive = te.time_total;
				break;
			}
		}

		insert_entry(root, &te, false);
	}
}

struct sort_item {
	const char *name;
	int (*cmp)(struct trace_entry *a, struct trace_entry *b);
	int avg_mode;
	struct list_head list;
};

#define SORT_ITEM_BASE(_name, _field, _mode)				\
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

#define SORT_ITEM_DIFF(_name, _field, _mode)				\
static int cmp_diff_##_field(struct trace_entry *a,			\
			     struct trace_entry *b)			\
{									\
	double pcnt_a = 100.0 * (int64_t) a->pair->_field / a->_field;	\
	double pcnt_b = 100.0 * (int64_t) b->pair->_field / b->_field;	\
									\
	if (pcnt_a == pcnt_b)						\
		return 0;						\
	return pcnt_a > pcnt_b ? 1: -1;					\
}									\
static struct sort_item sort_diff_##_field = {				\
	.name = _name "_diff",						\
	.cmp = cmp_diff_##_field,					\
	.avg_mode = _mode,						\
	LIST_HEAD_INIT(sort_diff_##_field.list)				\
}

#define SORT_ITEM(_name, _field, _mode)					\
	SORT_ITEM_BASE(_name, _field, _mode);				\
	SORT_ITEM_DIFF(_name, _field, _mode)				\

/* call count is not shown as percentage */
static int cmp_diff_nr_called(struct trace_entry *a,
			      struct trace_entry *b)
{
	long call_diff_a = a->pair->nr_called - a->nr_called;
	long call_diff_b = b->pair->nr_called - b->nr_called;

	if (call_diff_a == call_diff_b) {
		/* call count used to same, compare original count then */
		if (a->nr_called == b->nr_called)
			return 0;

		return a->nr_called > b->nr_called ? 1 : -1;
	}

	return call_diff_a > call_diff_b ? 1 : -1;
}

static struct sort_item sort_diff_nr_called = {
	.name = "call_diff",
	.cmp = cmp_diff_nr_called,
	.avg_mode = AVG_NONE,
	LIST_HEAD_INIT(sort_diff_nr_called.list)
};

/* exclude recursive time from total time */
static int cmp_time_total(struct trace_entry *a, struct trace_entry *b)
{
	uint64_t a_time = a->time_total - a->time_recursive;
	uint64_t b_time = b->time_total - b->time_recursive;

	if (a_time == b_time)
		return 0;
	return a_time > b_time ? 1 : -1;
}

static struct sort_item sort_time_total = {
	.name = "total",
	.cmp = cmp_time_total,
	.avg_mode = AVG_NONE,
	LIST_HEAD_INIT(sort_time_total.list)
};

static int cmp_diff_time_total(struct trace_entry *a, struct trace_entry *b)
{
	uint64_t a_time = a->time_total - a->time_recursive;
	uint64_t b_time = b->time_total - b->time_recursive;
	uint64_t a_pair_time = a->pair->time_total - a->pair->time_recursive;
	uint64_t b_pair_time = b->pair->time_total - b->pair->time_recursive;
	double a_pcnt = 100.0 * a_pair_time / a_time;
	double b_pcnt = 100.0 * b_pair_time / b_time;

	if (a_pcnt == b_pcnt)
		return 0;
	return a_pcnt > b_pcnt ? 1 : -1;
}

static struct sort_item sort_diff_time_total = {
	.name = "total_diff",
	.cmp = cmp_diff_time_total,
	.avg_mode = AVG_NONE,
	LIST_HEAD_INIT(sort_diff_time_total.list)
};

//SORT_ITEM("total", time_total, AVG_NONE);
SORT_ITEM("self", time_self, AVG_NONE);
SORT_ITEM_BASE("call", nr_called, AVG_NONE);
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

struct sort_item *diff_sort_items[] = {
	&sort_diff_time_total,
	&sort_diff_time_self,
	&sort_diff_nr_called,
	&sort_diff_time_avg,
	&sort_diff_time_min,
	&sort_diff_time_max,
};

static LIST_HEAD(sort_list);
static LIST_HEAD(diff_sort_list);

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

static int cmp_diff_entry(struct trace_entry *a, struct trace_entry *b,
			  int sort_column)
{
	int ret;
	struct sort_item *item;
	struct list_head *sort_list_head = &sort_list;
	struct trace_entry *entry_a = a;
	struct trace_entry *entry_b = b;

	switch (sort_column) {
	case 0:
		sort_list_head = &sort_list;
		entry_a = a;
		entry_b = b;
		break;
	case 1:
		sort_list_head = &sort_list;
		entry_a = a->pair;
		entry_b = b->pair;
		break;
	case 2:
		sort_list_head = &diff_sort_list;
		entry_a = a;
		entry_b = b;
		break;
	default:
		/* this should not happend */
		assert(0);
		break;
	}

	list_for_each_entry(item, sort_list_head, list) {
		ret = item->cmp(entry_a, entry_b);
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

static void sort_diff_entries(struct rb_root *root, struct trace_entry *te,
			      int sort_column)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (cmp_diff_entry(entry, te, sort_column) < 0)
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
			list_add_tail(&diff_sort_items[i]->list, &diff_sort_list);
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

static void print_and_delete(struct rb_root *root,
			     void (*print_func)(struct trace_entry *))
{
	while (!RB_EMPTY_ROOT(root)) {
		struct rb_node *node;
		struct trace_entry *entry;

		node = rb_first(root);
		rb_erase(node, root);

		entry = rb_entry(node, struct trace_entry, link);
		print_func(entry);

		if (entry->pair)
			free(entry->pair);
		free(entry);
	}
}

static void print_function(struct trace_entry *entry)
{
	char *symname = symbol_getname(entry->sym, entry->addr);

	if (avg_mode == AVG_NONE) {
		pr_out(" ");
		print_time_unit(entry->time_total - entry->time_recursive);
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

static void report_functions(struct ftrace_file_handle *handle, struct opts *opts)
{
	struct rb_root name_tree = RB_ROOT;
	struct rb_root sort_tree = RB_ROOT;
	const char f_format[] = "  %10.10s  %10.10s  %10.10s  %-s\n";
	const char line[] = "====================================";

	build_function_tree(handle, &name_tree, opts);

	while (!RB_EMPTY_ROOT(&name_tree)) {
		struct rb_node *node;
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
		pr_out(f_format, "Total time", "Self time", "Calls", "Function");
	else if (avg_mode == AVG_TOTAL)
		pr_out(f_format, "Avg total", "Min total", "Max total", "Function");
	else if (avg_mode == AVG_SELF)
		pr_out(f_format, "Avg self", "Min self", "Max self", "Function");

	pr_out(f_format, line, line, line, line);

	print_and_delete(&sort_tree, print_function);
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

static void print_thread(struct trace_entry *entry)
{
	char *symname = symbol_getname(entry->sym, entry->addr);

	pr_out("  %5d ", entry->pid);
	print_time_unit(entry->time_self);
	pr_out("  %10lu  %-s\n", entry->nr_called, symname);

	symbol_putname(entry->sym, symname);
}

static void report_threads(struct ftrace_file_handle *handle, struct opts *opts)
{
	struct trace_entry te;
	struct ftrace_ret_stack *rstack;
	struct rb_root name_tree = RB_ROOT;
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

		/* skip user functions if --kernel-only is set */
		if (opts->kernel_only && !is_kernel_address(rstack->addr))
			continue;

		if (opts->kernel_skip_out) {
			/* skip kernel functions outside user functions */
			if (is_kernel_address(task->func_stack[0].addr) &&
			    is_kernel_address(rstack->addr))
				continue;
		}

		fstack = &task->func_stack[task->stack_count];

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

	print_and_delete(&name_tree, print_thread);
}

struct diff_data {
	char				*dirname;
	struct rb_root			root;
	struct ftrace_file_handle	handle;
};

static void sort_by_name(struct rb_root *root, struct trace_entry *te)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	int ret;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (!entry->sym || !te->sym) {
			if (entry->addr < te->addr)
				p = &parent->rb_left;
			else
				p = &parent->rb_right;
			continue;
		}

		ret = strcmp(entry->sym->name, te->sym->name);
		if (ret == 0) {
			entry->time_total += te->time_total;
			entry->time_self  += te->time_self;
			entry->nr_called  += te->nr_called;

			if (avg_mode == AVG_TOTAL)
				entry->time_avg = entry->time_total / entry->nr_called;
			else if (avg_mode == AVG_SELF)
				entry->time_avg = entry->time_self / entry->nr_called;

			if (entry->time_min > te->time_min)
				entry->time_min = te->time_min;
			if (entry->time_max < te->time_max)
				entry->time_max = te->time_max;

			free(te);
			return;
		};

		if (ret < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&te->link, parent, p);
	rb_insert_color(&te->link, root);
}

static struct trace_entry * find_by_name(struct rb_root *root, char *name)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (strcmp(entry->sym->name, name) == 0)
			return entry;

		if (strcmp(entry->sym->name, name) < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	return NULL;
}

static void sort_function_name(struct rb_root *root_in,
			       struct rb_root *root_out)
{
	struct rb_root no_name = RB_ROOT;

	while (!RB_EMPTY_ROOT(root_in)) {
		struct rb_node *node;
		struct trace_entry *entry;

		node = rb_first(root_in);
		rb_erase(node, root_in);

		entry = rb_entry(node, struct trace_entry, link);
		if (avg_mode == AVG_TOTAL)
			entry->time_avg = entry->time_total / entry->nr_called;
		else if (avg_mode == AVG_SELF)
			entry->time_avg = entry->time_self / entry->nr_called;

		if (entry->sym)
			sort_by_name(root_out, entry);
		else
			insert_entry(&no_name, entry, false);
	}

	*root_in = no_name;
}

static void calculate_diff(struct rb_root *base, struct rb_root *pair,
			   struct rb_root *diff, struct rb_root *remaining,
			   int sort_column)
{
	struct rb_root tmp = RB_ROOT;

	while (!RB_EMPTY_ROOT(base)) {
		struct rb_node *node;
		struct trace_entry *e, *p;

		node = rb_first(base);
		rb_erase(node, base);

		e = rb_entry(node, struct trace_entry, link);
		p = find_by_name(pair, e->sym->name);
		if (p == NULL) {
			sort_entries(remaining, e);
			continue;
		}

		rb_erase(&p->link, pair);
		RB_CLEAR_NODE(&p->link);

		e->pair = p;
		p->pair = e;

		sort_diff_entries(diff, e, sort_column);
	}

	/* sort remaining pair entries by time */
	while (!RB_EMPTY_ROOT(pair)) {
		struct rb_node *node;
		struct trace_entry *entry;

		node = rb_first(pair);
		rb_erase(node, pair);

		entry = rb_entry(node, struct trace_entry, link);
		sort_entries(&tmp, entry);
	}

	*pair = tmp;
}

static void print_diff(struct trace_entry *entry)
{
	char *symname = symbol_getname(entry->sym, entry->addr);
	struct trace_entry *pair = entry->pair;

	if (avg_mode == AVG_NONE) {
		pr_out(" ");
		print_time_unit(entry->time_total);
		pr_out(" ");
		print_time_unit(pair->time_total);
		pr_out(" ");
		print_diff_percent(entry->time_total, pair->time_total);

		pr_out("  ");
		print_time_unit(entry->time_self);
		pr_out(" ");
		print_time_unit(pair->time_self);
		pr_out(" ");
		print_diff_percent(entry->time_self, pair->time_self);

		pr_out("    %9lu  %9lu  %+9ld   %-s\n",
		       entry->nr_called, pair->nr_called,
		       (long)(pair->nr_called - entry->nr_called), symname);
	} else {
		pr_out(" ");
		print_time_unit(entry->time_avg);
		pr_out(" ");
		print_time_unit(pair->time_avg);
		pr_out(" ");
		print_diff_percent(entry->time_avg, pair->time_avg);

		pr_out("  ");
		print_time_unit(entry->time_min);
		pr_out(" ");
		print_time_unit(pair->time_min);
		pr_out(" ");
		print_diff_percent(entry->time_min, pair->time_min);

		pr_out("  ");
		print_time_unit(entry->time_max);
		pr_out(" ");
		print_time_unit(pair->time_max);
		pr_out(" ");
		print_diff_percent(entry->time_max, pair->time_max);

		pr_out("   %-s\n", symname);
	}

	symbol_putname(entry->sym, symname);
}

#define NODATA  "-"
static void print_remaining(struct trace_entry *entry)
{
	char *symname = symbol_getname(entry->sym, entry->addr);

	if (avg_mode == AVG_NONE) {
		pr_out(" ");
		print_time_unit(entry->time_total);
		pr_out("  %10s  %8s  ", NODATA, NODATA);

		print_time_unit(entry->time_self);
		pr_out("  %10s  %8s ",  NODATA, NODATA);

		pr_out("  %10lu  %9s  %9s   %-s\n",
		       entry->nr_called, NODATA, NODATA, symname);
	} else {
		pr_out(" ");
		print_time_unit(entry->time_avg);
		pr_out("  %10s  %8s  ", NODATA, NODATA);

		print_time_unit(entry->time_min);
		pr_out("  %10s  %8s  ", NODATA, NODATA);

		print_time_unit(entry->time_max);
		pr_out("  %10s  %8s   %-s\n",  NODATA, NODATA, symname);
	}

	symbol_putname(entry->sym, symname);
}

static void print_remaining_pair(struct trace_entry *entry)
{
	char *symname = symbol_getname(entry->sym, entry->addr);

	if (avg_mode == AVG_NONE) {
		pr_out("  %10s ", NODATA);
		print_time_unit(entry->time_total);
		pr_out("  %8s ", NODATA);

		pr_out("  %10s ", NODATA);
		print_time_unit(entry->time_self);
		pr_out("  %8s ", NODATA);

		pr_out("  %10s %10lu %10s   %-s\n",
		       NODATA, entry->nr_called, NODATA, symname);
	} else {

		pr_out("  %10s ", NODATA);
		print_time_unit(entry->time_avg);
		pr_out("  %8s ", NODATA);

		pr_out("  %10s ", NODATA);
		print_time_unit(entry->time_min);
		pr_out("  %8s ", NODATA);

		pr_out("  %10s ",  NODATA);
		print_time_unit(entry->time_max);
		pr_out("  %8s ", NODATA);

		pr_out("  %-s\n", symname);
	}

	symbol_putname(entry->sym, symname);
}

static void report_diff(struct ftrace_file_handle *handle, struct opts *opts)
{
	struct opts dummy_opts = {
		.dirname = opts->diff,
		.kernel  = opts->kernel,
		.depth   = opts->depth,
	};
	struct diff_data data = {
		.dirname = opts->diff,
		.root    = RB_ROOT,
	};
	struct rb_root tmp = RB_ROOT;
	struct rb_root name_tree = RB_ROOT;
	struct rb_root diff_tree = RB_ROOT;
	struct rb_root remaining = RB_ROOT;
	const char format[] = "  %32.32s   %32.32s   %32.32s   %-s\n";
	const char line[] = "====================================";

	build_function_tree(handle, &tmp, opts);
	sort_function_name(&tmp, &name_tree);

	remaining = tmp;
	tmp = RB_ROOT;

	open_data_file(&dummy_opts, &data.handle);
	fstack_setup_filters(&dummy_opts, &data.handle);
	build_function_tree(&data.handle, &tmp, &dummy_opts);
	sort_function_name(&tmp, &data.root);

	calculate_diff(&name_tree, &data.root, &diff_tree, &remaining, opts->sort_column);

	pr_out("#\n");
	pr_out("# uftrace diff\n");
	pr_out("#  [%d] base: %s\t(from %s)\n", 0, handle->dirname, handle->info.cmdline);
	pr_out("#  [%d] diff: %s\t(from %s)\n", 1, opts->diff, data.handle.info.cmdline);
	pr_out("#\n");

	if (avg_mode == AVG_NONE)
		pr_out(format, "Total time (diff)", "Self time (diff)",
		       "Nr. called (diff)", "Function");
	else if (avg_mode == AVG_TOTAL)
		pr_out(format, "Avg total (diff)", "Min total (diff)",
		       "Max total (diff)", "Function");
	else if (avg_mode == AVG_SELF)
		pr_out(format, "Avg self (diff)", "Min self (diff)",
		       "Max self (diff)", "Function");

	pr_out(format, line, line, line, line);

	print_and_delete(&remaining, print_remaining);
	print_and_delete(&data.root, print_remaining_pair);
	print_and_delete(&diff_tree, print_diff);

	close_data_file(&dummy_opts, &data.handle);
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
		kern.skip_out = opts->kernel_skip_out;
		if (setup_kernel_data(&kern) == 0) {
			handle.kern = &kern;
			load_kernel_symbol();
		}
	}

	fstack_setup_filters(opts, &handle);

	if (opts->sort_keys)
		setup_sort(opts->sort_keys);

	/* default: sort by total time */
	if (list_empty(&sort_list)) {
		if (avg_mode == AVG_NONE) {
			list_add(&sort_time_total.list, &sort_list);
			list_add(&sort_diff_time_total.list, &diff_sort_list);
		}
		else {
			list_add(&sort_time_avg.list, &sort_list);
			list_add(&sort_diff_time_avg.list, &diff_sort_list);
		}
	}

	if (opts->report_thread)
		report_threads(&handle, opts);
	else if (opts->diff)
		report_diff(&handle, opts);
	else
		report_functions(&handle, opts);

	if (handle.kern)
		finish_kernel_data(handle.kern);

	close_data_file(opts, &handle);

	return ret;
}
