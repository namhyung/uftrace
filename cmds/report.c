#include <inttypes.h>
#include <stdio.h>

#include "uftrace.h"
#include "utils/field.h"
#include "utils/fstack.h"
#include "utils/list.h"
#include "utils/rbtree.h"
#include "utils/report.h"
#include "utils/symbol.h"
#include "utils/utils.h"

enum avg_mode avg_mode = AVG_NONE;

/* maximum length of symbol */
static int maxlen = 20;

static LIST_HEAD(output_fields);

static void print_field(struct uftrace_report_node *node, int space)
{
	struct field_data fd = {
		.arg = node,
	};

	print_field_data(&output_fields, &fd, space);
}

static void insert_node(struct rb_root *root, struct uftrace_task_reader *task, char *symname,
			struct uftrace_dbg_loc *loc)
{
	struct uftrace_report_node *node;

	node = report_find_node(root, symname);
	if (node == NULL) {
		node = xzalloc(sizeof(*node));
		report_add_node(root, symname, node);
	}
	report_update_node(node, task, loc);
}

static void find_insert_node(struct rb_root *root, struct uftrace_task_reader *task,
			     uint64_t timestamp, uint64_t addr, bool needs_srcline)
{
	struct uftrace_symbol *sym;
	char *symname;
	struct uftrace_dbg_loc *loc = NULL;

	sym = task_find_sym_addr(&task->h->sessions, task, timestamp, addr);
	if (needs_srcline)
		loc = task_find_loc_addr(&task->h->sessions, task, timestamp, addr);

	symname = symbol_getname(sym, addr);
	insert_node(root, task, symname, loc);
	symbol_putname(sym, symname);
}

static void add_lost_fstack(struct rb_root *root, struct uftrace_task_reader *task,
			    struct uftrace_opts *opts)
{
	struct uftrace_fstack *fstack;

	while (task->stack_count >= task->user_stack_count) {
		fstack = fstack_get(task, task->stack_count);

		if (fstack_enabled && fstack && fstack->valid &&
		    !(fstack->flags & FSTACK_FL_NORECORD)) {
			find_insert_node(root, task, task->timestamp_last, fstack->addr,
					 opts->srcline);
		}

		fstack_exit(task);
		task->stack_count--;
	}
}

static void add_remaining_fstack(struct uftrace_data *handle, struct rb_root *root,
				 struct uftrace_opts *opts)
{
	struct uftrace_task_reader *task;
	struct uftrace_fstack *fstack;
	int i;

	for (i = 0; i < handle->nr_tasks; i++) {
		uint64_t last_time;

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

			if (fstack->total_time > last_time)
				continue;

			fstack->total_time = last_time - fstack->total_time;
			if (fstack->child_time > fstack->total_time)
				fstack->total_time = fstack->child_time;

			if (task->stack_count > 0)
				fstack[-1].child_time += fstack->total_time;

			if (fstack->addr == EVENT_ID_PERF_SCHED_IN)
				insert_node(root, task, sched_sym.name, NULL);
			else
				find_insert_node(root, task, last_time, fstack->addr,
						 opts->srcline);
		}
	}
}

static void build_function_tree(struct uftrace_data *handle, struct rb_root *root,
				struct uftrace_opts *opts)
{
	struct uftrace_session_link *sessions = &handle->sessions;
	struct uftrace_symbol *sym = NULL;
	struct uftrace_record *rstack;
	struct uftrace_task_reader *task;
	uint64_t addr;

	while (read_rstack(handle, &task) >= 0 && !uftrace_done) {
		rstack = task->rstack;

		if (rstack->type != UFTRACE_LOST)
			task->timestamp_last = rstack->time;

		if (!fstack_check_opts(task, opts))
			continue;

		if (!fstack_check_filter(task))
			continue;

		if (rstack->type == UFTRACE_ENTRY) {
			fstack_check_filter_done(task);
			continue;
		}

		if (rstack->type == UFTRACE_EVENT) {
			if (rstack->addr == EVENT_ID_PERF_SCHED_IN)
				insert_node(root, task, sched_sym.name, NULL);
			continue;
		}

		if (rstack->type == UFTRACE_LOST) {
			/* add partial duration of functions before LOST */
			add_lost_fstack(root, task, opts);
			continue;
		}

		/* rstack->type == UFTRACE_EXIT */
		addr = rstack->addr;
		if (is_kernel_record(task, rstack)) {
			struct uftrace_session *fsess;

			fsess = sessions->first;
			addr = get_kernel_address(&fsess->sym_info, rstack->addr);
		}

		/* skip it if --no-libcall is given */
		sym = task_find_sym(sessions, task, rstack);
		if (!opts->libcall && sym && sym->type == ST_PLT_FUNC) {
			fstack_check_filter_done(task);
			continue;
		}

		find_insert_node(root, task, rstack->time, addr, opts->srcline);

		fstack_check_filter_done(task);
	}

	if (uftrace_done)
		return;

	add_remaining_fstack(handle, root, opts);
}

static void print_and_delete(struct rb_root *root, bool sorted, void *arg,
			     void (*print_func)(struct uftrace_report_node *, void *, int space),
			     int space)
{
	while (!RB_EMPTY_ROOT(root)) {
		struct rb_node *n;
		struct uftrace_report_node *node;

		n = rb_first(root);
		rb_erase(n, root);

		if (sorted)
			node = rb_entry(n, typeof(*node), sort_link);
		else
			node = rb_entry(n, typeof(*node), name_link);

		print_func(node, arg, space);
		free(node->name);
		free(node);
	}
}

static void print_function(struct uftrace_report_node *node, void *unused, int space)
{
	print_field(node, space);

	pr_out("%*s", space, " ");
	pr_out("%-s", node->name);

	if (node->loc)
		pr_gray(" [%s:%d]", node->loc->file->name, node->loc->line);

	pr_out("\n");
}

static void print_line(struct list_head *output_fields, int space)
{
	struct display_field *field;
	const char line[] = "=================================================";

	/* do not print anything if not needed */
	if (list_empty(output_fields))
		return;

	list_for_each_entry(field, output_fields, list) {
		pr_out("%*s", space, "");
		pr_out("%-.*s", field->length, line);
	}

	pr_out("%*s", space, " ");
	pr_out("%-.*s\n", maxlen, line);
}

static void report_functions(struct uftrace_data *handle, struct uftrace_opts *opts)
{
	struct rb_root name_root = RB_ROOT;
	struct rb_root sort_root = RB_ROOT;
	const int field_space = 2;

	build_function_tree(handle, &name_root, opts);
	report_calc_avg(&name_root);
	report_sort_nodes(&name_root, &sort_root);

	if (uftrace_done)
		return;

	setup_report_field(&output_fields, opts, avg_mode);

	print_header_align(&output_fields, "  ", "Function", field_space, ALIGN_RIGHT, false);
	if (!list_empty(&output_fields)) {
		if (opts->srcline)
			pr_gray(" [Source]");
		pr_out("\n");
	}

	print_line(&output_fields, field_space);
	print_and_delete(&sort_root, true, NULL, print_function, field_space);
}

static void add_remaining_task_fstack(struct uftrace_data *handle, struct rb_root *root)
{
	struct uftrace_task_reader *task;
	struct uftrace_fstack *fstack;
	char buf[10];
	int i;

	for (i = 0; i < handle->nr_tasks; i++) {
		uint64_t last_time;

		task = &handle->tasks[i];

		if (task->stack_count == 0)
			continue;

		last_time = task->timestamp_last;

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

			if (fstack->addr == EVENT_ID_PERF_SCHED_IN) {
				if (task->t->time.stamp) {
					task->t->time.idle += last_time - fstack->total_time;
				}
				task->t->time.stamp = 0;
			}

			fstack->total_time = last_time - fstack->total_time;
			if (fstack->child_time > fstack->total_time)
				fstack->total_time = fstack->child_time;

			if (task->stack_count > 0)
				fstack[-1].child_time += fstack->total_time;

			snprintf(buf, sizeof(buf), "%d", task->tid);
			insert_node(root, task, buf, NULL);
		}
	}
}

static void adjust_task_runtime(struct uftrace_data *handle, struct rb_root *root)
{
	struct uftrace_task *t;
	struct uftrace_report_node *node;
	struct rb_node *n = rb_first(root);
	int tid;

	while (n != NULL) {
		node = rb_entry(n, struct uftrace_report_node, name_link);
		n = rb_next(n);

		tid = strtol(node->name, NULL, 0);
		t = find_task(&handle->sessions, tid);

		/* total = runtime, self = cputime (= total - idle) */
		memcpy(&node->total, &node->self, sizeof(node->self));
		memset(&node->self, 0, sizeof(node->self));
		node->self.sum = node->total.sum - t->time.idle;
	}
}

static void print_task(struct uftrace_report_node *node, void *arg, int space)
{
	int pid;
	struct uftrace_task *t;
	struct uftrace_data *handle = arg;

	pid = strtol(node->name, NULL, 10);
	t = find_task(&handle->sessions, pid);

	print_field(node, space);

	pr_out("%*s", space, " ");
	pr_out("%-16s\n", t->comm);
}

static void report_task(struct uftrace_data *handle, struct uftrace_opts *opts)
{
	struct uftrace_record *rstack;
	struct rb_root task_tree = RB_ROOT;
	struct rb_root sort_tree = RB_ROOT;
	struct uftrace_task_reader *task;
	char buf[10];
	int field_space = 2;

	while (read_rstack(handle, &task) >= 0 && !uftrace_done) {
		rstack = task->rstack;
		if (rstack->type == UFTRACE_ENTRY || rstack->type == UFTRACE_LOST)
			continue;

		if (!fstack_check_opts(task, opts))
			continue;

		if (!fstack_check_filter(task))
			continue;

		task->timestamp_last = rstack->time;

		if (rstack->type == UFTRACE_EVENT) {
			if (rstack->addr == EVENT_ID_PERF_SCHED_OUT) {
				task->t->time.stamp = rstack->time;
				continue;
			}
			else if (rstack->addr == EVENT_ID_PERF_SCHED_IN) {
				if (task->t->time.stamp) {
					task->t->time.idle += rstack->time - task->t->time.stamp;
				}
				task->t->time.stamp = 0;
			}
			else {
				continue;
			}
		}

		/* UFTRACE_EXIT */
		snprintf(buf, sizeof(buf), "%d", task->tid);
		insert_node(&task_tree, task, buf, NULL);
	}

	if (uftrace_done)
		return;

	add_remaining_task_fstack(handle, &task_tree);
	adjust_task_runtime(handle, &task_tree);
	report_sort_tasks(handle, &task_tree, &sort_tree);

	setup_report_field(&output_fields, opts, avg_mode);

	print_header_align(&output_fields, "  ", "Task name", field_space, ALIGN_RIGHT, true);

	print_line(&output_fields, field_space);
	print_and_delete(&sort_tree, true, handle, print_task, field_space);
}

struct diff_data {
	char *dirname;
	struct rb_root root;
	struct uftrace_data handle;
};

static void report_diff(struct uftrace_data *handle, struct uftrace_opts *opts)
{
	struct uftrace_opts dummy_opts = {
		.dirname = opts->diff,
		.kernel = opts->kernel,
		.depth = opts->depth,
		.libcall = opts->libcall,
	};
	struct diff_data data = {
		.dirname = opts->diff,
		.root = RB_ROOT,
	};
	struct rb_root base_tree = RB_ROOT;
	struct rb_root pair_tree = RB_ROOT;
	struct rb_root diff_tree = RB_ROOT;
	int field_space = 3;

	build_function_tree(handle, &base_tree, opts);
	report_calc_avg(&base_tree);

	if (open_data_file(&dummy_opts, &data.handle) < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->diff);
		goto out;
	}

	fstack_setup_filters(&dummy_opts, &data.handle);
	build_function_tree(&data.handle, &pair_tree, &dummy_opts);
	report_calc_avg(&pair_tree);

	report_diff_nodes(&base_tree, &pair_tree, &diff_tree, opts->sort_column);

	if (uftrace_done)
		goto out;

	pr_out("#\n");
	pr_out("# uftrace diff\n");
	pr_out("#  [%d] base: %s\t(from %s)\n", 0, handle->dirname, handle->info.cmdline);
	pr_out("#  [%d] diff: %s\t(from %s)\n", 1, opts->diff, data.handle.info.cmdline);
	pr_out("#\n");

	setup_report_field(&output_fields, opts, avg_mode);

	print_header_align(&output_fields, "  ", "Function", field_space, ALIGN_RIGHT, false);
	if (!list_empty(&output_fields)) {
		if (opts->srcline)
			pr_gray(" [Source]");
		pr_out("\n");
	}

	print_line(&output_fields, field_space);
	print_and_delete(&diff_tree, true, NULL, print_function, field_space);
out:
	destroy_diff_nodes(&base_tree, &pair_tree);
	__close_data_file(&dummy_opts, &data.handle, false);
}

int command_report(int argc, char *argv[], struct uftrace_opts *opts)
{
	int ret;
	char *sort_keys;
	struct uftrace_data handle;

	if (opts->avg_total && opts->avg_self) {
		pr_use("--avg-total and --avg-self options should not be used together.\n");
		exit(1);
	}
	else if (opts->fields && (opts->avg_self || opts->avg_total)) {
		pr_warn("--avg-total and --avg-self options are ignored when used with -f option.\n");
	}
	else if (opts->avg_total) {
		avg_mode = AVG_TOTAL;
	}
	else if (opts->avg_self) {
		avg_mode = AVG_SELF;
	}

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
		return -1;
	}

	fstack_setup_filters(opts, &handle);

	if (opts->diff) {
		sort_keys = convert_sort_keys(opts->sort_keys, avg_mode);
		ret = report_setup_diff(sort_keys);
	}
	else if (opts->show_task) {
		if (opts->sort_keys == NULL)
			sort_keys = xstrdup(OPT_SORT_KEYS);
		else
			sort_keys = xstrdup(opts->sort_keys);
		ret = report_setup_task(sort_keys);
	}
	else {
		sort_keys = convert_sort_keys(opts->sort_keys, avg_mode);
		ret = report_setup_sort(sort_keys);
	}
	free(sort_keys);

	if (ret < 0) {
		pr_use("invalid sort key: %s\n", opts->sort_keys);
		return -1;
	}

	if (opts->diff_policy)
		apply_diff_policy(opts->diff_policy);

	if (format_mode == FORMAT_HTML)
		pr_out(HTML_HEADER);

	if (opts->show_task)
		report_task(&handle, opts);
	else if (opts->diff)
		report_diff(&handle, opts);
	else
		report_functions(&handle, opts);

	if (format_mode == FORMAT_HTML)
		pr_out(HTML_FOOTER);

	close_data_file(opts, &handle);

	return 0;
}
