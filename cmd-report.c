#include <stdio.h>
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

/* this will be used when pair entry wasn't found for diff */
static struct trace_entry dummy_entry;

/* show percentage rather than value of diff */
static bool diff_percent = true;

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

static bool fill_entry(struct trace_entry *te, struct ftrace_task_handle *task,
		       uint64_t time, uint64_t addr, struct opts *opts)
{
	struct uftrace_session_link *sessions = &task->h->sessions;
	struct uftrace_session *sess;
	struct sym *sym;
	struct fstack *fstack;
	int i;

	sess = sessions->first;

	/* skip user functions if --kernel-only is set */
	if (opts->kernel_only && !is_kernel_address(&sess->symtabs, addr))
		return false;

	if (opts->kernel_skip_out) {
		/* skip kernel functions outside user functions */
		if (task->user_stack_count == 0 &&
		    is_kernel_address(&sess->symtabs, addr))
			return false;
	}

	sym = task_find_sym_addr(sessions, task, time, addr);

	fstack = &task->func_stack[task->stack_count];

	te->pid  = task->tid;
	te->sym  = sym;
	te->addr = addr;
	te->time_total = fstack->total_time;
	te->time_self  = te->time_total - fstack->child_time;
	te->nr_called  = 1;

	/* some LOST entries make invalid self tiem */
	if (te->time_self > te->time_total)
		te->time_self = te->time_total;

	te->time_recursive = 0;
	for (i = 0; i < task->stack_count; i++) {
		if (addr == task->func_stack[i].addr) {
			te->time_recursive = te->time_total;
			break;
		}
	}

	return true;
}

static void build_function_tree(struct ftrace_file_handle *handle,
				struct rb_root *root, struct opts *opts)
{
	struct trace_entry te;
	struct uftrace_record *rstack;
	struct ftrace_task_handle *task;
	struct fstack *fstack;
	int i;

	while (read_rstack(handle, &task) >= 0 && !uftrace_done) {
		rstack = task->rstack;

		if (rstack->type != UFTRACE_LOST)
			task->timestamp_last = rstack->time;

		if (!fstack_check_filter(task))
			continue;

		if (rstack->type == UFTRACE_ENTRY ||
		    rstack->type == UFTRACE_EVENT)
			continue;

		if (rstack->type == UFTRACE_LOST) {
			/* add partial duration of functions before LOST */
			while (task->stack_count >= task->user_stack_count) {
				fstack = &task->func_stack[task->stack_count];

				if (fstack_enabled && fstack->valid &&
				    !(fstack->flags & FSTACK_FL_NORECORD) &&
				    fill_entry(&te, task, task->timestamp_last,
					       fstack->addr, opts)) {
					insert_entry(root, &te, false);
				}

				fstack_exit(task);
				task->stack_count--;
			}
			continue;
		}

		/* rstack->type == UFTRACE_EXIT */
		if (fill_entry(&te, task, rstack->time, rstack->addr, opts))
			insert_entry(root, &te, false);
	}

	if (uftrace_done)
		return;

	/* add duration of remaining functions */
	for (i = 0; i < handle->nr_tasks; i++) {
		uint64_t last_time;

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

			if (fill_entry(&te, task, last_time, fstack->addr, opts))
				insert_entry(root, &te, false);
		}
	}
}

struct sort_item {
	const char *name;
	int (*cmp)(struct trace_entry *a, struct trace_entry *b, int column);
	int avg_mode;
	struct list_head list;
};

#define SORT_ITEM_BASE(_name, _field, _mode)				\
static int cmp_##_field(struct trace_entry *a, struct trace_entry *b,	\
		int sort_column)					\
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
			     struct trace_entry *b,			\
			     int sort_column)				\
{									\
	double pcnt_a, pcnt_b;						\
	int64_t diff_a, diff_b;						\
									\
	if (sort_column != 2) {						\
		if (a->_field == b->_field)				\
			return 0;					\
		return a->_field > b->_field ? 1 : -1;			\
	}								\
									\
	diff_a = a->pair->_field - a->_field;				\
	diff_b = b->pair->_field - b->_field;				\
									\
	if (!diff_percent) {						\
		if (diff_a == diff_b)					\
			return 0;					\
		return diff_a > diff_b ? 1: -1;				\
	}								\
									\
	pcnt_a = 100.0 * (int64_t) diff_a / a->_field;			\
	pcnt_b = 100.0 * (int64_t) diff_b / b->_field;			\
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
			      struct trace_entry *b,
			      int sort_column)
{
	long call_diff_a, call_diff_b;
	double pcnt_a, pcnt_b;

	if (sort_column != 2) {
		if (a->nr_called == b->nr_called)
			return 0;
		return a->nr_called > b->nr_called ? 1 : -1;
	}

	call_diff_a = a->pair->nr_called - a->nr_called;
	call_diff_b = b->pair->nr_called - b->nr_called;

	if (!diff_percent) {
		if (call_diff_a == call_diff_b)
			return 0;
		return call_diff_a > call_diff_b ? 1 : -1;
	}

	pcnt_a = 100.0 * call_diff_a / a->nr_called;
	pcnt_b = 100.0 * call_diff_b / b->nr_called;

	if (pcnt_a == pcnt_b)
		return 0;
	return pcnt_a > pcnt_b ? 1 : -1;
}

static struct sort_item sort_diff_nr_called = {
	.name = "call_diff",
	.cmp = cmp_diff_nr_called,
	.avg_mode = AVG_NONE,
	LIST_HEAD_INIT(sort_diff_nr_called.list)
};

/* exclude recursive time from total time */
static int cmp_time_total(struct trace_entry *a, struct trace_entry *b,
			  int sort_column)
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

static int cmp_diff_time_total(struct trace_entry *a, struct trace_entry *b,
			       int sort_column)
{
	uint64_t a_time = a->time_total - a->time_recursive;
	uint64_t b_time = b->time_total - b->time_recursive;
	uint64_t a_pair_time = a->pair->time_total - a->pair->time_recursive;
	uint64_t b_pair_time = b->pair->time_total - b->pair->time_recursive;
	int64_t a_diff, b_diff;
	double a_pcnt, b_pcnt;

	if (sort_column != 2) {
		if (a_time == b_time)
			return 0;
		return a_time > b_time ? 1 : -1;
	}

	a_diff = a_pair_time - a_time;
	b_diff = b_pair_time - b_time;

	if (!diff_percent) {
		if (a_diff == b_diff)
			return 0;
		return a_diff > b_diff ? 1 : -1;
	}

	a_pcnt = 100.0 * a_diff / a_time;
	b_pcnt = 100.0 * b_diff / b_time;

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
		ret = item->cmp(a, b, 0);
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
		ret = item->cmp(entry_a, entry_b, sort_column);
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
				pr_out("uftrace: '%s' sort key %s be used with %s or %s.\n",
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
			pr_out("uftrace: Unknown sort key '%s'\n", k);
			pr_out("uftrace:   Possible keys:");
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

		if (entry->pair && entry->pair != &dummy_entry)
			free(entry->pair);
		free(entry);
	}
}

static void print_function(struct trace_entry *entry)
{
	char *symname = symbol_getname(entry->sym, entry->addr);

	if (avg_mode == AVG_NONE) {
		pr_out("  ");
		print_time_unit(entry->time_total - entry->time_recursive);
		pr_out("  ");
		print_time_unit(entry->time_self);
		pr_out("  %10lu  %-s\n", entry->nr_called, symname);
	} else {
		pr_out("  ");
		print_time_unit(entry->time_avg);
		pr_out("  ");
		print_time_unit(entry->time_min);
		pr_out("  ");
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

	while (!RB_EMPTY_ROOT(&name_tree) && !uftrace_done) {
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

	if (uftrace_done)
		return;

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
				  struct uftrace_record *rstack)
{
	struct sym *sym;
	struct ftrace_task_handle *main_task = &handle->tasks[0];
	struct uftrace_session *sess = find_task_session(&handle->sessions,
							 task->tid, rstack->time);
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

	pr_out("  %5d  ", entry->pid);
	print_time_unit(entry->time_self);
	pr_out("  %10lu  %-s\n", entry->nr_called, symname);

	symbol_putname(entry->sym, symname);
}

static void report_threads(struct ftrace_file_handle *handle, struct opts *opts)
{
	struct trace_entry te;
	struct uftrace_record *rstack;
	struct rb_root name_tree = RB_ROOT;
	struct ftrace_task_handle *task;
	struct fstack *fstack;
	const char t_format[] = "  %5.5s  %10.10s  %10.10s  %-s\n";
	const char line[] = "====================================";

	while (read_rstack(handle, &task) >= 0 && !uftrace_done) {
		rstack = task->rstack;
		if (rstack->type == UFTRACE_ENTRY && task->func)
			continue;
		if (rstack->type == UFTRACE_LOST)
			continue;

		/* skip user functions if --kernel-only is set */
		if (opts->kernel_only && !is_kernel_record(task, rstack))
			continue;

		if (opts->kernel_skip_out) {
			/* skip kernel functions outside user functions */
			if (task->user_stack_count == 0 &&
			    is_kernel_record(task, rstack))
				continue;
		}

		fstack = &task->func_stack[task->stack_count];

		te.pid = task->tid;
		te.sym = find_task_sym(handle, task, rstack);
		te.addr = rstack->addr;
		te.time_recursive = 0;

		if (rstack->type == UFTRACE_ENTRY) {
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

	if (uftrace_done)
		return;

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

static struct trace_entry * find_by_name(struct rb_root *root,
					 struct trace_entry *base)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	char *name;

	if (base->sym == NULL)
		return NULL;

	name = base->sym->name;
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (entry->sym == NULL) {
			if (entry->addr < base->addr)
				p = &parent->rb_left;
			else
				p = &parent->rb_right;
			continue;
		}

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

	while (!RB_EMPTY_ROOT(root_in) && !uftrace_done) {
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
			   struct rb_root *diff, int sort_column)
{
	while (!RB_EMPTY_ROOT(base) && !uftrace_done) {
		struct rb_node *node;
		struct trace_entry *e, *p;

		node = rb_first(base);
		rb_erase(node, base);

		e = rb_entry(node, struct trace_entry, link);
		p = find_by_name(pair, e);
		if (p != NULL) {
			rb_erase(&p->link, pair);
			RB_CLEAR_NODE(&p->link);
		}
		else
			p = &dummy_entry;

		e->pair = p;
		p->pair = e;

		sort_diff_entries(diff, e, sort_column);
	}

	/* sort remaining pair entries with zero entry */
	while (!RB_EMPTY_ROOT(pair) && !uftrace_done) {
		struct rb_node *node;
		struct trace_entry *entry, *zero;

		node = rb_first(pair);
		rb_erase(node, pair);

		entry = rb_entry(node, struct trace_entry, link);

		zero = xzalloc(sizeof(*zero));
		zero->sym = entry->sym;
		zero->addr = entry->addr;
		zero->pair = entry;
		entry->pair = zero;

		sort_diff_entries(diff, zero, sort_column);
	}
}

#define NODATA "-"

static void print_time_or_dash(uint64_t time_nsec)
{
	if (time_nsec)
		print_time_unit(time_nsec);
	else
		pr_out("%10s", NODATA);
}

static void print_function_diff(struct trace_entry *entry)
{
	char *symname = symbol_getname(entry->sym, entry->addr);
	struct trace_entry *pair = entry->pair;

	if (avg_mode == AVG_NONE) {
		pr_out("  ");
		print_time_or_dash(entry->time_total - entry->time_recursive);
		pr_out("  ");
		print_time_or_dash(pair->time_total - pair->time_recursive);
		pr_out("  ");

		if (diff_percent)
			print_diff_percent(entry->time_total - entry->time_recursive,
					   pair->time_total - pair->time_recursive);
		else
			print_diff_time_unit(entry->time_total - entry->time_recursive,
					     pair->time_total - pair->time_recursive);

		pr_out("   ");
		print_time_or_dash(entry->time_self);
		pr_out("  ");
		print_time_or_dash(pair->time_self);
		pr_out("  ");

		if (diff_percent)
			print_diff_percent(entry->time_self, pair->time_self);
		else
			print_diff_time_unit(entry->time_self, pair->time_self);

		pr_out("    %9lu  %9lu  ", entry->nr_called, pair->nr_called);
		print_diff_count(entry->nr_called, pair->nr_called);
		pr_out("   %-s\n", symname);
	} else {
		pr_out("  ");
		print_time_unit(entry->time_avg);
		pr_out("  ");
		print_time_unit(pair->time_avg);
		pr_out("  ");
		print_diff_percent(entry->time_avg, pair->time_avg);

		pr_out("   ");
		print_time_unit(entry->time_min);
		pr_out("  ");
		print_time_unit(pair->time_min);
		pr_out("  ");
		print_diff_percent(entry->time_min, pair->time_min);

		pr_out("   ");
		print_time_unit(entry->time_max);
		pr_out("  ");
		print_time_unit(pair->time_max);
		pr_out(" ");
		print_diff_percent(entry->time_max, pair->time_max);

		pr_out("   %-s\n", symname);
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
	const char *formats[] = {
		"  %35.35s   %35.35s   %32.32s   %-s\n",  /* diff numbers */
		"  %32.32s   %32.32s   %32.32s   %-s\n",  /* diff percent */
	};
	const char line[] = "================================================";
	const char *headers[][3] = {
		{ "Total time (diff)", "Self time (diff)", "Calls (diff)" },
		{ "Avg total (diff)", "Min total (diff)", "Max total (diff)" },
		{ "Avg self (diff)", "Min self (diff)", "Max self (diff)" },
	};
	int h_idx = (avg_mode == AVG_NONE) ? 0 : (avg_mode == AVG_TOTAL) ? 1 : 2;
	int f_idx = diff_percent ? 1 : 0;

	build_function_tree(handle, &tmp, opts);
	sort_function_name(&tmp, &name_tree);

	tmp = RB_ROOT;

	open_data_file(&dummy_opts, &data.handle);
	fstack_setup_filters(&dummy_opts, &data.handle);
	build_function_tree(&data.handle, &tmp, &dummy_opts);
	sort_function_name(&tmp, &data.root);

	calculate_diff(&name_tree, &data.root, &diff_tree, opts->sort_column);

	if (uftrace_done)
		goto out;

	pr_out("#\n");
	pr_out("# uftrace diff\n");
	pr_out("#  [%d] base: %s\t(from %s)\n", 0, handle->dirname, handle->info.cmdline);
	pr_out("#  [%d] diff: %s\t(from %s)\n", 1, opts->diff, data.handle.info.cmdline);
	pr_out("#\n");
	pr_out(formats[f_idx], headers[h_idx][0], headers[h_idx][1], headers[h_idx][2], "Function");
	pr_out(formats[f_idx], line, line, line, line);

	print_and_delete(&diff_tree, print_function_diff);

out:
	close_data_file(&dummy_opts, &data.handle);
}

int command_report(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;

	if (opts->avg_total && opts->avg_self) {
		pr_use("--avg-total and --avg-self options should not be used together.\n");
		exit(1);
	} else if (opts->avg_total)
		avg_mode = AVG_TOTAL;
	else if (opts->avg_self)
		avg_mode = AVG_SELF;

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		pr_err("cannot open data: %s", opts->dirname);

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

	close_data_file(opts, &handle);

	return ret;
}
