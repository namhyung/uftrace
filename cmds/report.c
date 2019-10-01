#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"
#include "utils/list.h"
#include "utils/fstack.h"
#include "utils/report.h"

enum {
	AVG_NONE,
	AVG_TOTAL,
	AVG_SELF,
	AVG_ANY,
} avg_mode = AVG_NONE;

/* maximum length of symbol */
static int maxlen = 20;

static void insert_node(struct rb_root *root, struct uftrace_task_reader *task,
			char *symname)
{
	struct uftrace_report_node *node;

	node = report_find_node(root, symname);
	if (node == NULL) {
		node = xzalloc(sizeof(*node));
		report_add_node(root, symname, node);
	}
	report_update_node(node, task);
}

static void find_insert_node(struct rb_root *root, struct uftrace_task_reader *task,
			     uint64_t timestamp, uint64_t addr)
{
	struct sym *sym;
	char *symname;

	sym = task_find_sym_addr(&task->h->sessions, task, timestamp, addr);
	symname = symbol_getname(sym, addr);
	insert_node(root, task, symname);
	symbol_putname(sym, symname);
}

static void add_lost_fstack(struct rb_root *root, struct uftrace_task_reader *task)
{
	struct fstack *fstack;

	while (task->stack_count >= task->user_stack_count) {
		fstack = &task->func_stack[task->stack_count];

		if (fstack_enabled && fstack->valid &&
		    !(fstack->flags & FSTACK_FL_NORECORD)) {
			find_insert_node(root, task, task->timestamp_last,
					 fstack->addr);
		}

		fstack_exit(task);
		task->stack_count--;
	}
}

static void add_remaining_fstack(struct uftrace_data *handle,
				 struct rb_root *root)
{
	struct uftrace_task_reader *task;
	struct fstack *fstack;
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
			fstack = &task->func_stack[task->stack_count];

			if (fstack->total_time > last_time)
				continue;

			fstack->total_time = last_time - fstack->total_time;
			if (fstack->child_time > fstack->total_time)
				fstack->total_time = fstack->child_time;

			if (task->stack_count > 0)
				fstack[-1].child_time += fstack->total_time;

			if (fstack->addr == EVENT_ID_PERF_SCHED_IN)
				insert_node(root, task, sched_sym.name);
			else
				find_insert_node(root, task, last_time,
						 fstack->addr);
		}
	}
}

static void build_function_tree(struct uftrace_data *handle,
				struct rb_root *root, struct opts *opts)
{
	struct uftrace_session_link *sessions = &handle->sessions;
	struct sym *sym = NULL;
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

		if (rstack->type == UFTRACE_ENTRY)
			continue;

		if (rstack->type == UFTRACE_EVENT) {
			if (rstack->addr == EVENT_ID_PERF_SCHED_IN)
				insert_node(root, task, sched_sym.name);
			continue;
		}

		if (rstack->type == UFTRACE_LOST) {
			/* add partial duration of functions before LOST */
			add_lost_fstack(root, task);
			continue;
		}

		/* rstack->type == UFTRACE_EXIT */
		addr = rstack->addr;
		if (is_kernel_record(task, rstack)) {
			struct uftrace_session *fsess;

			fsess = sessions->first;
			addr = get_kernel_address(&fsess->symtabs, rstack->addr);
		}

		/* skip it if --no-libcall is given */
		sym = task_find_sym(sessions, task, rstack);
		if (!opts->libcall && sym && sym->type == ST_PLT_FUNC)
			continue;

		find_insert_node(root, task, rstack->time, addr);
	}

	if (uftrace_done)
		return;

	add_remaining_fstack(handle, root);
}

static void print_and_delete(struct rb_root *root, bool sorted, void *arg,
			     void (*print_func)(struct uftrace_report_node *, void *))
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

		print_func(node, arg);
		free(node->name);
		free(node);
	}
}

static void print_function(struct uftrace_report_node *node, void *unused)
{
	if (avg_mode == AVG_NONE) {
		pr_out("  ");
		print_time_unit(node->total.sum);
		pr_out("  ");
		print_time_unit(node->self.sum);
		pr_out("  %10lu  %-s\n", node->call, node->name);
	}
	else {
		uint64_t time_avg, time_min, time_max;

		if (avg_mode == AVG_TOTAL) {
			time_avg = node->total.avg;
			time_min = node->total.min;
			time_max = node->total.max;
		}
		else {
			time_avg = node->self.avg;
			time_min = node->self.min;
			time_max = node->self.max;
		}
		pr_out("  ");
		print_time_unit(time_avg);
		pr_out("  ");
		print_time_unit(time_min);
		pr_out("  ");
		print_time_unit(time_max);
		pr_out("  %-s\n", node->name);
	}
}

static void report_functions(struct uftrace_data *handle, struct opts *opts)
{
	struct rb_root name_root = RB_ROOT;
	struct rb_root sort_root = RB_ROOT;
	const char f_format[] = "  %10.10s  %10.10s  %10.10s  %-.*s\n";
	const char line[] = "=================================================";

	build_function_tree(handle, &name_root, opts);
	report_calc_avg(&name_root);
	report_sort_nodes(&name_root, &sort_root);

	if (uftrace_done)
		return;

	if (avg_mode == AVG_NONE)
		pr_out(f_format, "Total time", "Self time", "Calls", maxlen, "Function");
	else if (avg_mode == AVG_TOTAL)
		pr_out(f_format, "Avg total", "Min total", "Max total", maxlen, "Function");
	else if (avg_mode == AVG_SELF)
		pr_out(f_format, "Avg self", "Min self", "Max self", maxlen, "Function");

	pr_out(f_format, line, line, line, maxlen, line);

	print_and_delete(&sort_root, true, NULL, print_function);
}

static void add_remaining_task_fstack(struct uftrace_data *handle,
				      struct rb_root *root)
{
	struct uftrace_task_reader *task;
	struct fstack *fstack;
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
			fstack = &task->func_stack[task->stack_count];

			if (fstack->addr == 0)
				continue;

			if (fstack->total_time > last_time)
				continue;

			if (fstack->addr == EVENT_ID_PERF_SCHED_IN) {
				if (task->t->time.stamp) {
					task->t->time.idle += last_time -
						fstack->total_time;
				}
				task->t->time.stamp = 0;
			}

			fstack->total_time = last_time - fstack->total_time;
			if (fstack->child_time > fstack->total_time)
				fstack->total_time = fstack->child_time;

			if (task->stack_count > 0)
				fstack[-1].child_time += fstack->total_time;

			snprintf(buf, sizeof(buf), "%d", task->tid);
			insert_node(root, task, buf);
		}
	}
}

static void adjust_task_runtime(struct uftrace_data *handle,
				struct rb_root *root)
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

static void print_thread(struct uftrace_report_node *node, void *arg)
{
	int pid;
	struct uftrace_task *t;
	struct uftrace_data *handle = arg;

	pid = strtol(node->name, NULL, 10);
	t = find_task(&handle->sessions, pid);

	pr_out("  ");
	print_time_unit(node->total.sum);
	pr_out("  ");
	print_time_unit(node->self.sum);
	pr_out("  %10lu  %6d  %-s\n", node->call, pid, t->comm);
}

static void report_task(struct uftrace_data *handle, struct opts *opts)
{
	struct uftrace_record *rstack;
	struct rb_root task_tree = RB_ROOT;
	struct rb_root sort_tree = RB_ROOT;
	struct uftrace_task_reader *task;
	const char t_format[] = "  %10.10s  %10.10s  %10.10s  %6.6s  %-16.16s\n";
	const char line[] = "=================================================";
	char buf[10];

	while (read_rstack(handle, &task) >= 0 && !uftrace_done) {
		rstack = task->rstack;
		if (rstack->type == UFTRACE_ENTRY ||
		    rstack->type == UFTRACE_LOST)
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
					task->t->time.idle += rstack->time -
						task->t->time.stamp;
				}
				task->t->time.stamp = 0;
			}
			else {
				continue;
			}
		}

		/* UFTRACE_EXIT */
		snprintf(buf, sizeof(buf), "%d", task->tid);
		insert_node(&task_tree, task, buf);
	}

	if (uftrace_done)
		return;

	add_remaining_task_fstack(handle, &task_tree);
	adjust_task_runtime(handle, &task_tree);
	report_sort_tasks(handle, &task_tree, &sort_tree);

	pr_out(t_format, "Total time", "Self time", "Num funcs", "TID", "Task name");
	pr_out(t_format, line, line, line, line, line);

	print_and_delete(&sort_tree, true, handle, print_thread);
}

struct diff_data {
	char				*dirname;
	struct rb_root			root;
	struct uftrace_data		handle;
};

#define NODATA "-"

static void print_time_or_dash(uint64_t time_nsec)
{
	if (time_nsec)
		print_time_unit(time_nsec);
	else
		pr_out("%10s", NODATA);
}

static void print_function_diff(struct uftrace_report_node *node, void *arg)
{
	struct uftrace_report_node *pair = node->pair;

	if (avg_mode == AVG_NONE) {
		pr_out("  ");

		if (diff_policy.full) {
			print_time_or_dash(node->total.sum);
			pr_out("  ");
			print_time_or_dash(pair->total.sum);
			pr_out("  ");
		}
		else if (diff_policy.percent)
			pr_out("   ");

		if (diff_policy.percent)
			print_diff_percent(node->total.sum, pair->total.sum);
		else
			print_diff_time_unit(node->total.sum, pair->total.sum);

		pr_out("   ");

		if (diff_policy.full) {
			print_time_or_dash(node->self.sum);
			pr_out("  ");
			print_time_or_dash(pair->self.sum);
			pr_out("  ");
		}
		else if (diff_policy.percent)
			pr_out("   ");

		if (diff_policy.percent)
			print_diff_percent(node->self.sum, pair->self.sum);
		else
			print_diff_time_unit(node->self.sum, pair->self.sum);

		pr_out("   ");

		if (diff_policy.full)
			pr_out(" %9lu  %9lu", node->call, pair->call);

		pr_out("  ");

		print_diff_count(node->call, pair->call);
		pr_out("   %-s\n", node->name);
	}
	else {
		uint64_t time_avg, time_min, time_max;
		uint64_t pair_avg, pair_min, pair_max;

		if (avg_mode == AVG_TOTAL) {
			time_avg = node->total.avg;
			time_min = node->total.min;
			time_max = node->total.max;
			pair_avg = pair->total.avg;
			pair_min = pair->total.min;
			pair_max = pair->total.max;
		}
		else {
			time_avg = node->self.avg;
			time_min = node->self.min;
			time_max = node->self.max;
			pair_avg = pair->self.avg;
			pair_min = pair->self.min;
			pair_max = pair->self.max;
		}

		pr_out("  ");

		if (diff_policy.full) {
			print_time_unit(time_avg);
			pr_out("  ");
			print_time_unit(time_avg);
			pr_out("  ");
		}
		else if (diff_policy.percent)
			pr_out("   ");

		if (diff_policy.percent)
			print_diff_percent(time_avg, pair_avg);
		else
			print_diff_time_unit(time_avg, pair_avg);

		pr_out("   ");

		if (diff_policy.full) {
			print_time_unit(time_min);
			pr_out("  ");
			print_time_unit(pair_min);
			pr_out("  ");
		}
		else if (diff_policy.percent)
			pr_out("   ");

		if (diff_policy.percent)
			print_diff_percent(time_min, pair_min);
		else
			print_diff_time_unit(time_min, pair_min);

		pr_out("   ");

		if (diff_policy.full) {
			print_time_unit(time_max);
			pr_out("  ");
			print_time_unit(pair_max);
			pr_out("  ");
		}
		else if (diff_policy.percent)
			pr_out("   ");

		if (diff_policy.percent)
			print_diff_percent(time_max, pair_max);
		else
			print_diff_time_unit(time_max, pair_max);

		pr_out("   %-s\n", node->name);
	}
}

static void report_diff(struct uftrace_data *handle, struct opts *opts)
{
	struct opts dummy_opts = {
		.dirname = opts->diff,
		.kernel  = opts->kernel,
		.depth   = opts->depth,
		.libcall = opts->libcall,
	};
	struct diff_data data = {
		.dirname = opts->diff,
		.root    = RB_ROOT,
	};
	struct rb_root base_tree = RB_ROOT;
	struct rb_root pair_tree = RB_ROOT;
	struct rb_root diff_tree = RB_ROOT;
	const char *formats[] = {
		"  %35.35s   %35.35s   %32.32s   %-.*s\n",  /* diff numbers */
		"  %32.32s   %32.32s   %32.32s   %-.*s\n",  /* diff percent */
		"  %35.35s   %35.35s   %35.35s   %-.*s\n",  /* diff avg numbers */
		"  %11.11s   %11.11s   %11.11s   %-.*s\n",  /* diff compact */
	};
	const char line[] = "=================================================";
	const char *headers[][3] = {
		{ "Total time (diff)", "Self time (diff)", "Calls (diff)" },
		{ "Avg total (diff)", "Min total (diff)", "Max total (diff)" },
		{ "Avg self (diff)", "Min self (diff)", "Max self (diff)" },
		{ "Total time", "Self time", "Calls" },
		{ "Avg total", "Min total", "Max total" },
		{ "Avg self", "Min self", "Max self" },
	};
	int h_idx = (avg_mode == AVG_NONE) ? 0 : (avg_mode == AVG_TOTAL) ? 1 : 2;
	int f_idx = diff_policy.percent ? 1 : (avg_mode == AVG_NONE) ? 0 : 2;

	if (!diff_policy.full) {
		h_idx += 3;
		f_idx = 3;
	}

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
	pr_out(formats[f_idx], headers[h_idx][0], headers[h_idx][1], headers[h_idx][2],
	       maxlen, "Function");
	pr_out(formats[f_idx], line, line, line, maxlen, line);

	print_and_delete(&diff_tree, true, NULL, print_function_diff);

out:
	destroy_diff_nodes(&diff_tree);
	close_data_file(&dummy_opts, &data.handle);
}

char * convert_sort_keys(char *sort_keys)
{
	const char *default_sort_key[] = { OPT_SORT_KEYS,
					   "total_avg", "self_avg" };
	struct strv keys = STRV_INIT;
	char *new_keys;
	char *k;
	int i;

	if (sort_keys == NULL)
		return xstrdup(default_sort_key[avg_mode]);

	if (avg_mode == AVG_NONE)
		return xstrdup(sort_keys);

	strv_split(&keys, sort_keys, ",");

	strv_for_each(&keys, k, i) {
		if (!strcmp(k, "avg")) {
			strv_replace(&keys, i, avg_mode == AVG_TOTAL ?
				     "total_avg" : "self_avg");
		}
		else if (!strcmp(k, "min")) {
			strv_replace(&keys, i, avg_mode == AVG_TOTAL ?
				     "total_min" : "self_min");
		}
		else if (!strcmp(k, "max")) {
			strv_replace(&keys, i, avg_mode == AVG_TOTAL ?
				     "total_max" : "self_max");
		}
	}

	new_keys = strv_join(&keys, ",");
	strv_free(&keys);

	return new_keys;
}

int command_report(int argc, char *argv[], struct opts *opts)
{
	int ret;
	char *sort_keys;
	struct uftrace_data handle;

	if (opts->avg_total && opts->avg_self) {
		pr_use("--avg-total and --avg-self options should not be used together.\n");
		exit(1);
	}
	else if (opts->avg_total)
		avg_mode = AVG_TOTAL;
	else if (opts->avg_self)
		avg_mode = AVG_SELF;

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
		return -1;
	}

	fstack_setup_filters(opts, &handle);

	if (opts->diff) {
		sort_keys = convert_sort_keys(opts->sort_keys);
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
		sort_keys = convert_sort_keys(opts->sort_keys);
		ret = report_setup_sort(sort_keys);
	}
	free(sort_keys);

	if (ret < 0) {
		pr_use("invalid sort key: %s\n", opts->sort_keys);
		return -1;
	}

	if (opts->diff_policy)
		apply_diff_policy(opts->diff_policy);

	if (opts->show_task)
		report_task(&handle, opts);
	else if (opts->diff)
		report_diff(&handle, opts);
	else
		report_functions(&handle, opts);

	close_data_file(opts, &handle);

	return 0;
}
