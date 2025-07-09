#include <byteswap.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "fstack"
#define PR_DOMAIN DBG_FSTACK

#include "libmcount/mcount.h"
#include "uftrace.h"
#include "utils/arch.h"
#include "utils/event.h"
#include "utils/filter.h"
#include "utils/fstack.h"
#include "utils/kernel.h"
#include "utils/rbtree.h"
#include "utils/utils.h"

bool fstack_enabled = true;
bool live_disabled = false;

static struct uftrace_triggers_info fstack_triggers;

static inline int fstack_get_filter_mode(void)
{
	int filter_count = fstack_triggers.filter_count;
	return filter_count > 0 ? FILTER_MODE_IN : FILTER_MODE_OUT;
}

static inline int fstack_get_loc_mode(void)
{
	int loc_count = fstack_triggers.loc_count;
	return loc_count > 0 ? FILTER_MODE_IN : FILTER_MODE_OUT;
}

static int __read_task_ustack(struct uftrace_task_reader *task);

struct uftrace_task_reader *get_task_handle(struct uftrace_data *handle, int tid)
{
	int i;

	for (i = 0; i < handle->nr_tasks; i++) {
		if (handle->tasks[i].tid == tid)
			return &handle->tasks[i];
	}
	return NULL;
}

static void setup_task_handle(struct uftrace_data *handle, struct uftrace_task_reader *task,
			      int tid)
{
	int i;
	int max_stack;

	task->stack_count = 0;
	task->display_depth = 0;
	task->column_index = -1;
	task->filter.depth = handle->depth;
	task->event_color = DEFAULT_EVENT_COLOR;

	/*
	 * set display depth to non-zero only when trace-on trigger (with --trace=off
	 * option) or time range is set.
	 */
	task->display_depth_set = (fstack_enabled && !live_disabled && !handle->time_range.start);

	max_stack = handle->hdr.max_stack;
	task->func_stack = xcalloc(1, sizeof(*task->func_stack) * max_stack);

	/* FIXME: save filter depth at fork() and restore */
	for (i = 0; i < max_stack; i++)
		task->func_stack[i].orig_depth = handle->depth;
}

void reset_task_handle(struct uftrace_data *handle)
{
	int i;
	struct uftrace_task_reader *task;

	for (i = 0; i < handle->nr_tasks; i++) {
		task = &handle->tasks[i];

		task->done = true;

		if (task->fp) {
			fclose(task->fp);
			task->fp = NULL;
		}

		free(task->args.data);
		task->args.data = NULL;

		free(task->func_stack);
		task->func_stack = NULL;

		reset_rstack_list(&task->rstack_list);
		reset_rstack_list(&task->event_list);
	}

	free(handle->tasks);
	handle->tasks = NULL;

	handle->nr_tasks = 0;
}

static void prepare_task_handle(struct uftrace_data *handle, struct uftrace_task_reader *task,
				int tid)
{
	char *filename;

	memset(task, 0, sizeof(*task));
	task->tid = tid;
	task->h = handle;
	task->t = find_task(&handle->sessions, tid);

	xasprintf(&filename, "%s/%d.dat", handle->dirname, tid);
	task->fp = fopen(filename, "rb");
	if (task->fp == NULL) {
		pr_dbg("cannot open task data file: %s: %m\n", filename);
		task->done = true;
	}
	else
		pr_dbg2("opening %s\n", filename);

	free(filename);

	setup_rstack_list(&task->rstack_list);
	setup_rstack_list(&task->event_list);
}

static void update_first_timestamp(struct uftrace_data *handle, struct uftrace_task_reader *task,
				   struct uftrace_record *rstack)
{
	uint64_t first = handle->time_range.first;

	if (task->stack_count == 0 && rstack->type == UFTRACE_EVENT &&
	    handle->time_range.event_skip_out)
		return;

	if (task->stack_count == 0 && is_kernel_record(task, rstack) &&
	    handle->time_range.kernel_skip_out)
		return;

	if (first == 0 || first > rstack->time)
		handle->time_range.first = rstack->time;
}

/**
 * fstack_setup_task - setup task filters using tid
 * @tid_filter - CSV of tid (or possibly separated by  ':')
 * @handle     - file handle
 *
 * This function sets up task filters using @tid_filter.
 * Tasks not listed will be ignored.
 */
void fstack_setup_task(char *tid_filter, struct uftrace_data *handle)
{
	int i, k;
	int nr_filters = 0;
	int *filter_tids = NULL;
	char *p = tid_filter;

	if (tid_filter == NULL)
		goto setup;

	do {
		int id;

		if (*p == ',' || *p == ';')
			p++;

		id = strtol(p, &p, 10);

		filter_tids = xrealloc(filter_tids, (nr_filters + 1) * sizeof(int));
		filter_tids[nr_filters++] = id;

	} while (*p);

	pr_dbg("setup filters for %d task(s)\n", nr_filters);

setup:
	handle->nr_tasks = handle->info.nr_tid;
	handle->tasks = xmalloc(sizeof(*handle->tasks) * handle->nr_tasks);

	for (i = 0; i < handle->nr_tasks; i++) {
		bool found;
		int tid;
		struct uftrace_task_reader *task;

		if (handle->info.tids == NULL)
			pr_err_ns("The info file is broken: missing tids\n");

		found = !tid_filter;
		tid = handle->info.tids[i];
		task = &handle->tasks[i];

		prepare_task_handle(handle, task, tid);

		for (k = 0; k < nr_filters; k++) {
			if (tid == filter_tids[k]) {
				found = true;
				break;
			}
		}

		if (!found) {
			task->done = true;

			/* need to read the data to check elapsed time */
			if (task->fp) {
				if (!__read_task_ustack(task)) {
					update_first_timestamp(handle, task, &task->ustack);
				}
				fclose(task->fp);
				task->fp = NULL;
			}
			continue;
		}

		setup_task_handle(handle, task, tid);
	}

	free(filter_tids);
}

static int setup_filters(struct uftrace_session *s, void *arg)
{
	struct uftrace_filter_setting *setting = arg;

	fstack_triggers.root = s->filters;
	uftrace_setup_filter(setting->info_str, &s->sym_info, &fstack_triggers, setting);
	s->filters = fstack_triggers.root;
	return 0;
}

static int setup_trigger(struct uftrace_session *s, void *arg)
{
	struct uftrace_filter_setting *setting = arg;

	fstack_triggers.root = s->filters;
	uftrace_setup_trigger(setting->info_str, &s->sym_info, &fstack_triggers, setting);
	s->filters = fstack_triggers.root;
	return 0;
}

static int setup_callers(struct uftrace_session *s, void *arg)
{
	struct uftrace_filter_setting *setting = arg;

	fstack_triggers.root = s->filters;
	uftrace_setup_caller_filter(setting->info_str, &s->sym_info, &fstack_triggers, setting);
	s->filters = fstack_triggers.root;
	return 0;
}

static int setup_hides(struct uftrace_session *s, void *arg)
{
	struct uftrace_filter_setting *setting = arg;

	fstack_triggers.root = s->filters;
	uftrace_setup_hide_filter(setting->info_str, &s->sym_info, &fstack_triggers, setting);
	s->filters = fstack_triggers.root;
	return 0;
}

static int setup_locs(struct uftrace_session *s, void *arg)
{
	struct uftrace_filter_setting *setting = arg;

	fstack_triggers.root = s->filters;
	uftrace_setup_loc_filter(setting->info_str, &s->sym_info, &fstack_triggers, setting);
	s->filters = fstack_triggers.root;
	return 0;
}

static int count_filters(struct uftrace_session *s, void *arg)
{
	int *count = arg;
	struct rb_node *node = rb_first(&s->filters);

	while (node) {
		(*count)++;
		node = rb_next(node);
	}
	return 0;
}

static int count_callers(struct uftrace_session *s, void *arg)
{
	*(int *)arg += uftrace_count_filter(&s->filters, TRIGGER_FL_CALLER);
	return 0;
}

static int count_hides(struct uftrace_session *s, void *arg)
{
	*(int *)arg += uftrace_count_filter(&s->filters, TRIGGER_FL_HIDE);
	return 0;
}

static int count_locs(struct uftrace_session *s, void *arg)
{
	*(int *)arg += uftrace_count_filter(&s->filters, TRIGGER_FL_LOC);
	return 0;
}

/**
 * setup_fstack_filters - setup symbol filters and triggers
 * @handle      - handle for uftrace data
 * @filter_str  - filter symbol names
 * @trigger_str - trigger definitions
 * @caller_str  - caller filter symbol names
 * @hide_str    - hide filter symbol names
 * @loc_str     - source location filter symbol names
 * @setting     - filter setting
 *
 * This function sets up the symbol filters and triggers using following syntax:
 *   filter_strs = filter | filter ";" filter_strs
 *   filter      = symbol | symbol "@" trigger
 *   trigger     = trigger_def | trigger_def "," trigger
 *   trigger_def = "depth=" NUM | "backtrace"
 */
static int setup_fstack_filters(struct uftrace_data *handle, char *filter_str, char *trigger_str,
				char *caller_str, char *hide_str, char *loc_str,
				struct uftrace_filter_setting *setting)
{
	int count = 0;
	struct uftrace_session_link *sessions = &handle->sessions;

	if (filter_str) {
		setting->info_str = filter_str;
		walk_sessions(sessions, setup_filters, setting);
		walk_sessions(sessions, count_filters, &count);

		if (count == 0)
			return -1;

		pr_dbg("setup filters for %d function(s)\n", count);
	}

	if (trigger_str) {
		int prev = count;

		setting->info_str = trigger_str;
		walk_sessions(sessions, setup_trigger, setting);
		walk_sessions(sessions, count_filters, &count);

		if (prev == count)
			return -1;

		pr_dbg("setup triggers for %d function(s)\n", count - prev);
	}

	if (caller_str) {
		int prev = count;

		setting->info_str = caller_str;
		walk_sessions(sessions, setup_callers, setting);
		walk_sessions(sessions, count_callers, &count);

		if (prev == count)
			return -1;

		handle->caller_filter = true;
		pr_dbg("setup caller filters for %d function(s)\n", count - prev);
	}

	if (hide_str) {
		int prev = count;

		setting->info_str = hide_str;
		walk_sessions(sessions, setup_hides, setting);
		walk_sessions(sessions, count_hides, &count);

		if (prev == count)
			return -1;

		pr_dbg("setup hide filters for %d function(s)\n", count - prev);
	}

	if (loc_str) {
		int prev = count;

		setting->info_str = loc_str;
		walk_sessions(sessions, setup_locs, setting);
		walk_sessions(sessions, count_locs, &count);

		if (prev == count)
			return -1;

		pr_dbg("setup location filters for %d function(s)\n", count - prev);
	}

	return 0;
}

static const char *fixup_syms[] = {
	"execl",      "execlp",	       "execle",  "execv",     "execve",      "execvp",
	"execvpe",    "setjmp",	       "_setjmp", "sigsetjmp", "__sigsetjmp", "longjmp",
	"siglongjmp", "__longjmp_chk", "fork",	  "vfork",     "daemon",      "posix.fork",
};

static int setjmp_depth;
static int setjmp_count;

static int build_fixup_filter(struct uftrace_session *s, void *arg)
{
	size_t i;
	struct uftrace_filter_setting setting = {
		.ptype = PATT_SIMPLE,
		.auto_args = false,
	};
	struct uftrace_triggers_info fixups = {
		.root = s->fixups,
	};

	pr_dbg("fixup for some special functions\n");

	for (i = 0; i < ARRAY_SIZE(fixup_syms); i++) {
		uftrace_setup_trigger((char *)fixup_syms[i], &s->sym_info, &fixups, &setting);
	}
	s->fixups = fixups.root;
	return 0;
}

/**
 * fstack_prepare_fixup - setup special filters for fixup routines
 * @handle: handle for uftrace data
 *
 * This function sets up special symbol filter tables which need
 * special handling like fork/exec, setjmp/longjmp cases.
 */
static void fstack_prepare_fixup(struct uftrace_data *handle)
{
	walk_sessions(&handle->sessions, build_fixup_filter, NULL);
}

static int build_arg_spec(struct uftrace_session *s, void *arg)
{
	struct uftrace_filter_setting *setting = arg;
	struct uftrace_triggers_info triggers = {
		.root = s->filters,
	};

	if (setting->info_str) {
		uftrace_setup_argument(setting->info_str, &s->sym_info, &triggers, setting);
		s->filters = triggers.root;
	}

	return 0;
}

static int build_ret_spec(struct uftrace_session *s, void *arg)
{
	struct uftrace_filter_setting *setting = arg;
	struct uftrace_triggers_info triggers = {
		.root = s->filters,
	};

	if (setting->info_str) {
		uftrace_setup_retval(setting->info_str, &s->sym_info, &triggers, setting);
		s->filters = triggers.root;
	}

	return 0;
}

/**
 * setup_fstack_args - setup argument and return value spec
 * @argspec: spec string describes function arguments
 * @retspec: spec string describes function return values
 * @handle: handle for uftrace data
 * @auto_args: whether current spec is auto-spec
 * @patt_type: filter match pattern (regex or glob)
 *
 * This functions sets up argument and return value information
 * provided by user at the time of recording.
 */
void setup_fstack_args(char *argspec, char *retspec, struct uftrace_data *handle,
		       struct uftrace_filter_setting *setting)
{
	if (argspec == NULL && retspec == NULL && !setting->auto_args)
		return;

	pr_dbg("setup argspec and/or retspec\n");

	setting->info_str = argspec;
	walk_sessions(&handle->sessions, build_arg_spec, setting);

	setting->info_str = retspec;
	walk_sessions(&handle->sessions, build_ret_spec, setting);

	/* old data does not have separated retspec */
	if (argspec && strstr(argspec, "retval")) {
		setting->info_str = argspec;
		walk_sessions(&handle->sessions, build_ret_spec, setting);
	}
}

/**
 * fstack_setup_filters - setup necessary filters for processing data
 * @opts: uftrace user options
 * @handle: handle for uftrace data
 *
 * This function sets up all kind of filters given by user.
 */
int fstack_setup_filters(struct uftrace_opts *opts, struct uftrace_data *handle)
{
	if (opts->filter || opts->trigger || opts->caller || opts->hide || opts->loc_filter) {
		struct uftrace_filter_setting setting = {
			.ptype = opts->patt_type,
			.allow_kernel = true,
			.lp64 = data_is_lp64(handle),
			.arch = handle->arch,
		};

		if (setup_fstack_filters(handle, opts->filter, opts->trigger, opts->caller,
					 opts->hide, opts->loc_filter, &setting) < 0) {
			char * or = "";
			pr_use("failed to set filter or trigger: ");
			if (opts->filter) {
				pr_out("%s%s", or, opts->filter);
				or = " or ";
			}
			if (opts->trigger) {
				pr_out("%s%s", or, opts->trigger);
				or = " or ";
			}
			if (opts->caller) {
				pr_out("%s%s", or, opts->caller);
				or = " or ";
			}
			if (opts->hide) {
				pr_out("%s%s", or, opts->hide);
				or = " or ";
			}
			if (opts->loc_filter) {
				pr_out("%s%s", or, opts->loc_filter);
				or = " or ";
			}
			pr_out("\n");
		}
	}

	if (opts->trace == TRACE_STATE_OFF)
		fstack_enabled = false;

	fstack_setup_task(opts->tid, handle);

	fstack_prepare_fixup(handle);
	return 0;
}

/**
 * fstack_get - retrieve func_stack entry in a task
 * @task - tracee task
 * @idx  - stack index
 *
 * This function returns a pointer to func_stack in @task or %NULL if it has
 * no function call stack or @idx is out of the boundary.
 */
struct uftrace_fstack *fstack_get(struct uftrace_task_reader *task, int idx)
{
	if (task->func_stack == NULL)
		return NULL;

	if (task->h && idx >= task->h->hdr.max_stack) {
		if (!task->fstack_warned) {
			pr_dbg("call stack overflow (task: %d)\n", task->tid);
			task->fstack_warned = true;
		}
		return NULL;
	}

	if (idx < 0) {
		if (!task->fstack_warned) {
			pr_dbg("negative call stack count (task: %d)\n", task->tid);
			task->fstack_warned = true;
		}
		return NULL;
	}

	return &task->func_stack[idx];
}

/**
 * fstack_entry - function entry handler
 * @task    - tracee task
 * @rstack  - function return stack
 * @tr      - trigger data
 *
 * This function should be called when replaying a recorded session.
 * It updates function stack, filter status, trigger result and
 * determine how to react. Callers can do whatever they want based
 * on the trigger result.
 *
 * This function returns -1 if it should be skipped, 0 otherwise.
 */
int fstack_entry(struct uftrace_task_reader *task, struct uftrace_record *rstack,
		 struct uftrace_trigger *tr)
{
	struct uftrace_fstack *fstack;
	struct uftrace_session_link *sessions = &task->h->sessions;
	struct uftrace_session *sess;
	uint64_t addr = rstack->addr;

	/* stack_count was increased in __read_rstack */
	fstack = fstack_get(task, task->stack_count - 1);
	if (fstack == NULL)
		return -1;

	pr_dbg2("ENTRY: [%*d] stack: %d, depth: %d, disp: %d, I: %d, O: %d, D: %d, flags = %lx %s\n",
		TASK_ID_LEN, task->tid, task->stack_count - 1, rstack->depth, task->display_depth,
		task->filter.in_count, task->filter.out_count, task->filter.depth, fstack->flags,
		rstack->more ? "more" : "");

	fstack->orig_depth = task->filter.depth;
	fstack->flags = 0;

	if (task->filter.out_count > 0) {
		fstack->flags |= FSTACK_FL_NORECORD;
		return -1;
	}

	sess = find_task_session(sessions, task->t, rstack->time);

	if (is_kernel_record(task, rstack)) {
		if (sess == NULL)
			sess = sessions->first;

		addr = get_kernel_address(&sess->sym_info, addr);
	}

	if (sess) {
		struct uftrace_filter *fixup;

		fixup = uftrace_match_filter(addr, &sess->fixups, tr);
		if (unlikely(fixup)) {
			if (!strncmp(fixup->name, "exec", 4))
				fstack->flags |= FSTACK_FL_EXEC;
			else if (strstr(fixup->name, "setjmp")) {
				setjmp_depth = task->display_depth + 1;
				setjmp_count = task->stack_count;
			}
			else if (strstr(fixup->name, "longjmp")) {
				fstack->flags |= FSTACK_FL_LONGJMP;
			}
			else if (strstr(fixup->name, "fork") || !strcmp(fixup->name, "daemon") ||
				 !strcmp(fixup->name, "posix.fork")) {
				task->fork_display_depth = task->display_depth + 1;
			}
		}

		uftrace_match_filter(addr, &sess->filters, tr);
	}

	if (tr->flags & TRIGGER_FL_FILTER) {
		if (tr->fmode == FILTER_MODE_IN) {
			task->filter.in_count++;
			fstack->flags |= FSTACK_FL_FILTERED;
		}
		else {
			task->filter.out_count++;
			fstack->flags |= FSTACK_FL_NOTRACE | FSTACK_FL_NORECORD;
			return -1;
		}

		/* restore default filter depth */
		task->filter.depth = task->h->depth;
	}
	else {
		if (fstack_get_filter_mode() == FILTER_MODE_IN && task->filter.in_count == 0) {
			fstack->flags |= FSTACK_FL_NORECORD;
			return -1;
		}
	}

	if (tr->flags & TRIGGER_FL_LOC) {
		if (tr->lmode == FILTER_MODE_OUT) {
			fstack->flags |= FSTACK_FL_NORECORD;
			return -1;
		}
	}
	else {
		if (fstack_get_loc_mode() == FILTER_MODE_IN) {
			fstack->flags |= FSTACK_FL_NORECORD;
			return -1;
		}
	}

	if (tr->flags & TRIGGER_FL_DEPTH)
		task->filter.depth = tr->depth;

	if (tr->flags & TRIGGER_FL_TRACE_ON)
		fstack_enabled = true;

	if (tr->flags & TRIGGER_FL_TRACE_OFF) {
		fstack_enabled = false;
		task->display_depth_set = false;
	}

	if (!fstack_enabled) {
		/*
		 * don't set NORECORD flag so that it can be printed
		 * when trace-on again
		 */
		return -1;
	}

	if (task->filter.depth <= 0 || tr->flags & TRIGGER_FL_HIDE) {
		fstack->flags |= FSTACK_FL_NORECORD;
		return -1;
	}

	task->filter.depth--;

	if (!task->display_depth_set) {
		task->display_depth = task->stack_count - 1;
		task->display_depth_set = true;

		if (unlikely(task->display_depth < 0))
			task->display_depth = 0;
	}

	return 0;
}

/**
 * fstack_exit - function exit handler
 * @task - tracee task
 *
 * This function should be paired with fstack_entry().
 */
void fstack_exit(struct uftrace_task_reader *task)
{
	struct uftrace_fstack *fstack;

	fstack = fstack_get(task, task->stack_count);
	if (fstack == NULL)
		return;

	pr_dbg2("EXIT : [%*d] stack: %d, depth: %d, disp: %d, I: %d, O: %d, D: %d, flags = %lx\n",
		TASK_ID_LEN, task->tid, task->stack_count, task->rstack->depth, task->display_depth,
		task->filter.in_count, task->filter.out_count, task->filter.depth, fstack->flags);

	if (fstack->flags & FSTACK_FL_FILTERED)
		task->filter.in_count--;
	else if (fstack->flags & FSTACK_FL_NOTRACE)
		task->filter.out_count--;

	fstack->flags = 0;
	task->filter.depth = fstack->orig_depth;
}

/**
 * fstack_update - Update fstack related info
 * @type   - UFTRACE_ENTRY or UFTRACE_EXIT
 * @task   - tracee task
 * @fstack - function tracing stack
 *
 * This function updates current display depth according to @type and
 * flags of @fstack, and return a new depth.
 */
int fstack_update(int type, struct uftrace_task_reader *task, struct uftrace_fstack *fstack)
{
	if (fstack == NULL)
		return task->display_depth;

	if (type == UFTRACE_ENTRY) {
		if (fstack->flags & FSTACK_FL_EXEC) {
			task->display_depth = 0;
			task->stack_count = 0;
			/* these are user functions */
			task->user_display_depth = 0;
			task->user_stack_count = 0;
		}
		else if (fstack->flags & FSTACK_FL_LONGJMP) {
			task->display_depth = setjmp_depth;
			task->stack_count = setjmp_count;
			/* these are user functions */
			task->user_display_depth = setjmp_depth;
			task->user_stack_count = setjmp_count;
		}
		else {
			task->display_depth++;
			if (task->ctx == FSTACK_CTX_USER)
				task->user_display_depth++;
		}

		fstack->flags &= ~(FSTACK_FL_EXEC | FSTACK_FL_LONGJMP);
	}
	else if (type == UFTRACE_EXIT) {
		/* fork'ed child starts with an exit record */
		if (!task->display_depth_set) {
			task->display_depth = task->stack_count + 1;
			task->display_depth_set = true;
		}

		if (task->display_depth > 0)
			task->display_depth--;
		else
			task->display_depth = 0;

		if (task->ctx == FSTACK_CTX_USER) {
			if (task->user_display_depth > 0)
				task->user_display_depth--;
			else
				task->user_display_depth = 0;
		}
	}
	else {
		pr_err_ns("wrong type of fstack entry: %d\n", type);
	}
	return task->display_depth;
}

/* returns -1 if it can skip the rstack */
static int fstack_check_skip(struct uftrace_task_reader *task, struct uftrace_record *rstack)
{
	struct uftrace_session_link *sessions = &task->h->sessions;
	struct uftrace_session *sess;
	uint64_t addr = rstack->addr;
	struct uftrace_trigger tr = { 0 };
	int depth = task->filter.depth;
	struct uftrace_fstack *fstack;

	if (task->filter.out_count > 0)
		return -1;

	if (rstack->type == UFTRACE_EXIT) {
		if (task->stack_count < 1)
			return 0;

		/* fstack_consume() is not called yet */
		fstack = fstack_get(task, task->stack_count - 1);
		if (fstack == NULL)
			return -1;

		if (fstack->flags & FSTACK_FL_NORECORD)
			return -1;

		return 0;
	}

	sess = find_task_session(sessions, task->t, rstack->time);
	if (sess == NULL) {
		struct uftrace_session *fsess = sessions->first;
		if (is_kernel_record(task, rstack))
			sess = fsess;
		else
			return -1;

		addr = get_kernel_address(&fsess->sym_info, addr);
	}

	uftrace_match_filter(addr, &sess->filters, &tr);

	if (tr.flags & TRIGGER_FL_FILTER) {
		if (tr.fmode == FILTER_MODE_OUT)
			return -1;

		depth = task->h->depth;
	}
	else if (tr.flags & TRIGGER_FL_LOC) {
		if (tr.fmode == FILTER_MODE_OUT)
			return -1;
	}
	else if ((fstack_get_filter_mode() == FILTER_MODE_IN ||
		  fstack_get_loc_mode() == FILTER_MODE_IN) &&
		 task->filter.in_count == 0) {
		return -1;
	}

	if (tr.flags & (TRIGGER_FL_DEPTH | TRIGGER_FL_TRACE_ON))
		return 1;

	if (tr.flags & (TRIGGER_FL_TRACE_OFF | TRIGGER_FL_HIDE) || depth <= 0)
		return -1;

	return 0;
}

/**
 * fstack_skip - Skip filtered record as many as possible
 * @handle     - file handle
 * @task       - tracee task
 * @curr_depth - current rstack depth
 * @opts       - options
 *
 * This function checks next rstack and skip if it's filtered out.
 * The intention is to merge EXIT record after skipped ones.  It
 * returns updated @task pointer which contains next non-filtered
 * rstack or NULL if it's the last record.
 */
struct uftrace_task_reader *fstack_skip(struct uftrace_data *handle,
					struct uftrace_task_reader *task, int curr_depth,
					struct uftrace_opts *opts)
{
	struct uftrace_task_reader *next = NULL;
	struct uftrace_fstack *fstack;
	struct uftrace_record *curr_stack = task->rstack;
	struct uftrace_session_link *sessions = &handle->sessions;

	fstack = fstack_get(task, task->stack_count - 1);
	if (fstack == NULL)
		return NULL;

	if (fstack->flags & (FSTACK_FL_EXEC | FSTACK_FL_LONGJMP))
		return NULL;

	if (peek_rstack(handle, &next) < 0)
		return NULL;

	while (true) {
		struct uftrace_record *next_stack = next->rstack;
		struct uftrace_trigger tr = { 0 };
		struct uftrace_symbol *sym = task_find_sym(sessions, task, next_stack);

		/* skip filtered entries until current matching EXIT records */
		if (next == task && curr_stack == next_stack && curr_depth >= next_stack->depth)
			break;

		/* skip kernel functions outside user functions */
		if (is_kernel_record(next, next_stack)) {
			if (has_kernel_data(handle->kernel) && !next->user_stack_count &&
			    handle->kernel->skip_out)
				goto next;
		}

		if (next_stack->type == UFTRACE_EVENT) {
			if (!next->user_stack_count && opts->event_skip_out)
				goto next;
		}

		if (next_stack->type == UFTRACE_LOST)
			return NULL;

		/* skip it if --no-libcall is given */
		if (!opts->libcall && sym && sym->type == ST_PLT_FUNC)
			goto next;

		/* return if it's not filtered */
		if (fstack_check_skip(next, next_stack) >= 0)
			break;

next:
		/* consume the filtered rstack */
		fstack_consume(handle, next);

		/*
		 * call fstack_entry/exit() after read_rstack() so
		 * that it can changes stack_count properly.
		 */
		if (next_stack->type == UFTRACE_ENTRY)
			fstack_entry(next, next_stack, &tr);
		else if (next_stack->type == UFTRACE_EXIT)
			fstack_exit(next);

		if (!fstack_enabled)
			return NULL;

		/* and then read next */
		if (peek_rstack(handle, &next) < 0)
			return NULL;
	}

	return next;
}

/**
 * fstack_check_filter - Check filter for current function
 * @task       - tracee task
 *
 * This function checks @task->func_stack and returns whether it
 * should be filtered out or not.  True means it's ok to process
 * this function and false means it should be skipped.
 */
bool fstack_check_filter(struct uftrace_task_reader *task)
{
	struct uftrace_fstack *fstack;
	struct uftrace_trigger tr = {};

	if (task->rstack->type == UFTRACE_ENTRY) {
		fstack = fstack_get(task, task->stack_count - 1);
		if (fstack == NULL)
			return false;

		if (fstack_entry(task, task->rstack, &tr) < 0)
			return false;
	}
	else if (task->rstack->type == UFTRACE_EXIT) {
		fstack = fstack_get(task, task->stack_count);
		if (fstack == NULL)
			return false;

		if ((fstack->flags & FSTACK_FL_NORECORD) || !fstack_enabled) {
			fstack_exit(task);
			return false;
		}

		fstack_update(UFTRACE_EXIT, task, fstack);
	}
	else if (task->rstack->type == UFTRACE_EVENT) {
		/* don't change filter state, just check it */
		if (task->filter.out_count > 0 || task->filter.depth <= 0 ||
		    (fstack_get_filter_mode() == FILTER_MODE_IN && task->filter.in_count == 0))
			return false;

		if (task->rstack->addr == EVENT_ID_PERF_SCHED_IN ||
		    task->rstack->addr == EVENT_ID_PERF_SCHED_OUT) {
			int idx = task->stack_count;
			const char *sched = "IN";

			if (task->rstack->addr == EVENT_ID_PERF_SCHED_OUT) {
				idx--;
				sched = "OUT";
			}

			fstack = fstack_get(task, idx);
			if (fstack == NULL)
				return false;

			pr_dbg2("SCHED: [%*d] stack: %d, depth: %d, disp: %d, I: %d, O: %d, D: %d, %s\n",
				TASK_ID_LEN, task->tid, idx, fstack->orig_depth,
				task->display_depth, task->filter.in_count, task->filter.out_count,
				task->filter.depth, sched);
		}
	}

	return true;
}

/**
 * fstack_check_filter_done - post-process filter settings
 * @task       - tracee task
 *
 * This function should be called after fstack_check_filter() returned
 * true and uftrace handled the fstack.
 */
void fstack_check_filter_done(struct uftrace_task_reader *task)
{
	struct uftrace_fstack *fstack;

	if (task->rstack->type == UFTRACE_ENTRY) {
		fstack = fstack_get(task, task->stack_count - 1);
		if (fstack == NULL)
			return;

		fstack_update(UFTRACE_ENTRY, task, fstack);
	}
	else if (task->rstack->type == UFTRACE_EXIT) {
		fstack = fstack_get(task, task->stack_count);
		if (fstack == NULL)
			return;

		fstack_exit(task);
	}
}

/**
 * is_sched_event - check whether the given address is a schedule event
 * @addr       - address to check whether it's a schedule event or now
 *
 * This function returns true if the given address is a schedule event otherwise
 * returns false.
 */
bool is_sched_event(uint64_t addr)
{
	if (addr == EVENT_ID_PERF_SCHED_IN || addr == EVENT_ID_PERF_SCHED_OUT ||
	    addr == EVENT_ID_PERF_SCHED_OUT_PREEMPT || addr == EVENT_ID_PERF_SCHED_BOTH ||
	    addr == EVENT_ID_PERF_SCHED_BOTH_PREEMPT)
		return true;
	return false;
}

/**
 * is_preempt_sched_event - check whether the given task is schedule preempt event
 * @task               - tracee task
 * @addr               - address to check whether it's a schedule event to be filtered or not
 *
 * This function returns true if the given address is a schedule preempt event or
 * given address is a EVENT_ID_PERF_SCHED_IN right after schedule preempt event otherwise
 * returns false
 */
bool is_sched_preempt_event(struct uftrace_task_reader *task, uint64_t addr)
{
	if (addr == EVENT_ID_PERF_SCHED_OUT_PREEMPT || addr == EVENT_ID_PERF_SCHED_BOTH_PREEMPT) {
		task->sched_preempt_seen = true;
		return true;
	}

	if (addr == EVENT_ID_PERF_SCHED_IN && task->sched_preempt_seen) {
		task->sched_preempt_seen = false;
		return true;
	}

	return false;
}

/**
 * fstack_check_opt - Check filter options for current function
 * @task       - tracee task
 * @opts       - options given by user
 *
 * This function checks @task->func_stack with @opts and returns
 * whether it should be filtered out or not.  True means it's ok to
 * process this function and false means it should be skipped.
 */
bool fstack_check_opts(struct uftrace_task_reader *task, struct uftrace_opts *opts)
{
	struct uftrace_record *rec = task->rstack;

	/* skip user functions if --kernel-only is set */
	if (opts->kernel_only) {
		if (!is_kernel_record(task, rec) && rec->type != UFTRACE_LOST)
			return false;
	}

	if (opts->kernel_skip_out) {
		/* skip kernel functions outside user functions */
		if (!task->user_stack_count && is_kernel_record(task, rec))
			return false;
	}

	if (opts->event_skip_out) {
		/* skip event outside of user functions */
		if (!task->user_stack_count && rec->type == UFTRACE_EVENT)
			return false;
	}

	if (opts->no_event && !opts->event && rec->type == UFTRACE_EVENT)
		return false;

	if (opts->no_sched && is_sched_event(rec->addr))
		return false;

	if (opts->no_sched_preempt && is_sched_preempt_event(task, rec->addr)) {
		return false;
	}

	return true;
}

void setup_rstack_list(struct uftrace_rstack_list *list)
{
	INIT_LIST_HEAD(&list->read);
	INIT_LIST_HEAD(&list->unused);
	list->count = 0;
}

void add_to_rstack_list(struct uftrace_rstack_list *list, struct uftrace_record *rstack,
			struct uftrace_fstack_args *args)
{
	struct uftrace_rstack_list_node *node;

	if (list_empty(&list->unused)) {
		node = xmalloc(sizeof(*node));
		node->args.data = NULL;
	}
	else {
		node = list_first_entry(&list->unused, typeof(*node), list);
		list_del(&node->list);
	}

	memcpy(&node->rstack, rstack, sizeof(*rstack));
	if (rstack->more) {
		memcpy(&node->args, args, sizeof(*args));
		node->args.data = xmalloc(args->len);
		memcpy(node->args.data, args->data, args->len);
	}

	list_add_tail(&node->list, &list->read);
	list->count++;
}

struct uftrace_record *get_first_rstack_list(struct uftrace_rstack_list *list)
{
	struct uftrace_rstack_list_node *node;

	ASSERT(list->count > 0);

	node = list_first_entry(&list->read, typeof(*node), list);
	return &node->rstack;
}

void consume_first_rstack_list(struct uftrace_rstack_list *list)
{
	struct uftrace_rstack_list_node *node;

	ASSERT(list->count > 0);

	node = list_first_entry(&list->read, typeof(*node), list);
	list_move(&node->list, &list->unused);

	if (node->rstack.more)
		ASSERT(node->args.data == NULL);

	list->count--;
}

void delete_last_rstack_list(struct uftrace_rstack_list *list)
{
	struct uftrace_rstack_list_node *node;

	ASSERT(list->count > 0);

	node = list_last_entry(&list->read, typeof(*node), list);
	if (node->rstack.more) {
		free(node->args.data);
		node->args.data = NULL;
	}

	list_move(&node->list, &list->unused);
	list->count--;
}

void reset_rstack_list(struct uftrace_rstack_list *list)
{
	while (!list_empty(&list->read)) {
		struct uftrace_rstack_list_node *node;

		node = list_first_entry(&list->read, typeof(*node), list);
		list_del(&node->list);
		free(node);
	}

	while (!list_empty(&list->unused)) {
		struct uftrace_rstack_list_node *node;

		node = list_first_entry(&list->unused, typeof(*node), list);
		list_del(&node->list);
		free(node);
	}
}

static void swap_byte_order(struct uftrace_record *rstack)
{
	uint64_t *ptr = (void *)rstack;

	ptr[0] = bswap_64(ptr[0]);
	ptr[1] = bswap_64(ptr[1]);
}

static void swap_bitfields(struct uftrace_record *rstack)
{
	uint64_t *ptr = (void *)rstack;
	uint64_t data = ptr[1];

	rstack->type = (data >> 0) & 0x3;
	rstack->more = (data >> 2) & 0x1;
	rstack->magic = (data >> 3) & 0x7;
	rstack->depth = (data >> 6) & 0x3ff;
	rstack->addr = (data >> 16) & 0xffffffffffffULL;
}

static int __read_task_ustack(struct uftrace_task_reader *task)
{
	FILE *fp = task->fp;

	if (fread(&task->ustack, sizeof(task->ustack), 1, fp) != 1) {
		if (feof(fp))
			return -1;

		pr_warn("error reading rstack: %s\n", strerror(errno));
		return -1;
	}

	if (task->h->needs_byte_swap)
		swap_byte_order(&task->ustack);
	if (task->h->needs_bit_swap)
		swap_bitfields(&task->ustack);

	if (task->ustack.magic != RECORD_MAGIC) {
		pr_warn("invalid rstack read\n");
		return -1;
	}

	return 0;
}

static int read_task_arg(struct uftrace_task_reader *task, struct uftrace_arg_spec *spec)
{
	FILE *fp = task->fp;
	struct uftrace_fstack_args *args = &task->args;
	unsigned size = spec->size;
	int rem;

	if (spec->size == 0)
		return 0;

	if (spec->fmt == ARG_FMT_STR || spec->fmt == ARG_FMT_STD_STRING) {
		args->data = xrealloc(args->data, args->len + 2);

		if (fread(args->data + args->len, 2, 1, fp) != 1) {
			if (feof(fp))
				return -1;
		}

		size = *(unsigned short *)(args->data + args->len);
		args->len += 2;
	}

	if (spec->fmt == ARG_FMT_INT_PTR) {
		size = sizeof(int);
	}

	rem = (args->len + size) % 4;

	if (rem)
		size += 4 - rem;

	args->data = xrealloc(args->data, args->len + size);

	if (fread(args->data + args->len, size, 1, fp) != 1) {
		if (feof(fp))
			return -1;
	}

	args->len += size;

	return 0;
}

/**
 * read_task_args - read arguments of current function of the task
 * @task: tracee task
 * @rstack: uftrace_record
 * @is_retval: 0 reads argument, 1 reads return value
 *
 * This function reads argument records of @task's current function
 * according to the @spec.
 */
int read_task_args(struct uftrace_task_reader *task, struct uftrace_record *rstack, bool is_retval)
{
	struct uftrace_session *sess;
	struct uftrace_trigger tr = {};
	struct uftrace_filter *fl;
	struct uftrace_arg_spec *arg;
	int rem;

	task->args.len = 0;
	task->args.args = NULL;
	/* keep args.data for realloc() */

	sess = find_task_session(&task->h->sessions, task->t, rstack->time);
	if (sess == NULL) {
		pr_dbg("cannot find session\n");
		return -1;
	}

	fl = uftrace_match_filter(rstack->addr, &sess->filters, &tr);
	if (fl == NULL) {
		pr_dbg("cannot find filter: %lx\n", rstack->addr);
		return -1;
	}
	if (!(tr.flags & (TRIGGER_FL_ARGUMENT | TRIGGER_FL_RETVAL))) {
		pr_dbg("cannot find arg spec\n");
		return -1;
	}

	task->args.args = &fl->args;

	list_for_each_entry(arg, &fl->args, list) {
		/* skip unwanted arguments or retval */
		if (is_retval != (arg->idx == RETVAL_IDX))
			continue;

		if (read_task_arg(task, arg) < 0)
			return -1;
	}

	rem = task->args.len % 8;
	if (rem)
		fseek(task->fp, 8 - rem, SEEK_CUR);

	return 0;
}

static int read_task_event_size(struct uftrace_task_reader *task, void *buf, size_t buflen)
{
	uint16_t len;

	if (fread(&len, sizeof(len), 1, task->fp) != 1)
		return -1;

	ASSERT(len == buflen);

	if (fread(buf, len, 1, task->fp) != 1)
		return -1;

	return 0;
}

static int read_task_watch_event(struct uftrace_task_reader *task,
				 struct uftrace_watch_event *watch, uint16_t *plen)
{
	uint16_t len;

	memset(&watch->var, 0, sizeof(watch->var));

	if (fread(&len, sizeof(len), 1, task->fp) != 1)
		return -1;

	*plen = len;

	if (data_is_lp64(task->h)) {
		if (fread(&watch->var.addr, 8, 1, task->fp) != 1)
			return -1;

		len -= 8;
	}
	else {
		if (fread(&watch->var.addr, 4, 1, task->fp) != 1)
			return -1;

		len -= 4;
	}

	if (fread(&watch->var.data, len, 1, task->fp) != 1)
		return -1;

	return 0;
}

static void save_task_event(struct uftrace_task_reader *task, void *buf, size_t buflen)
{
	int rem;

	/* abuse task->args */
	task->args.args = (void *)1;
	task->args.len = buflen;
	task->args.data = xrealloc(task->args.data, buflen);

	memcpy(task->args.data, buf, buflen);

	/* ensure 8-byte alignment */
	rem = (buflen + 2) % 8;
	if (rem)
		fseek(task->fp, 8 - rem, SEEK_CUR);
}

int read_task_event(struct uftrace_task_reader *task, struct uftrace_record *rec)
{
	union {
		struct uftrace_proc_statm statm;
		struct uftrace_page_fault pgfault;
		struct uftrace_pmu_cycle cycle;
		struct uftrace_pmu_cache cache;
		struct uftrace_pmu_branch branch;
		struct uftrace_watch_event watch;
	} u;
	uint16_t len;

	switch (rec->addr) {
	case EVENT_ID_READ_PROC_STATM:
	case EVENT_ID_DIFF_PROC_STATM:
		if (read_task_event_size(task, &u.statm, sizeof(u.statm)) < 0)
			return -1;

		if (task->h->needs_byte_swap) {
			u.statm.vmsize = bswap_64(u.statm.vmsize);
			u.statm.vmrss = bswap_64(u.statm.vmrss);
			u.statm.shared = bswap_64(u.statm.shared);
		}

		save_task_event(task, &u.statm, sizeof(u.statm));
		break;

	case EVENT_ID_READ_PAGE_FAULT:
	case EVENT_ID_DIFF_PAGE_FAULT:
		if (read_task_event_size(task, &u.pgfault, sizeof(u.pgfault)) < 0)
			return -1;

		if (task->h->needs_byte_swap) {
			u.pgfault.major = bswap_64(u.pgfault.major);
			u.pgfault.minor = bswap_64(u.pgfault.minor);
		}

		save_task_event(task, &u.pgfault, sizeof(u.pgfault));
		break;

	case EVENT_ID_READ_PMU_CYCLE:
	case EVENT_ID_DIFF_PMU_CYCLE:
		if (read_task_event_size(task, &u.cycle, sizeof(u.cycle)) < 0)
			return -1;

		if (task->h->needs_byte_swap) {
			u.cycle.cycles = bswap_64(u.cycle.cycles);
			u.cycle.instrs = bswap_64(u.cycle.instrs);
		}

		save_task_event(task, &u.cycle, sizeof(u.cycle));
		break;

	case EVENT_ID_READ_PMU_CACHE:
	case EVENT_ID_DIFF_PMU_CACHE:
		if (read_task_event_size(task, &u.cache, sizeof(u.cache)) < 0)
			return -1;

		if (task->h->needs_byte_swap) {
			u.cache.refers = bswap_64(u.cache.refers);
			u.cache.misses = bswap_64(u.cache.misses);
		}

		save_task_event(task, &u.cache, sizeof(u.cache));
		break;

	case EVENT_ID_READ_PMU_BRANCH:
	case EVENT_ID_DIFF_PMU_BRANCH:
		if (read_task_event_size(task, &u.branch, sizeof(u.branch)) < 0)
			return -1;

		if (task->h->needs_byte_swap) {
			u.branch.branch = bswap_64(u.branch.branch);
			u.branch.misses = bswap_64(u.branch.misses);
		}

		save_task_event(task, &u.branch, sizeof(u.branch));
		break;

	case EVENT_ID_WATCH_CPU:
		if (read_task_event_size(task, &u.watch.cpu, sizeof(u.watch.cpu)) < 0)
			return -1;
		if (task->h->needs_byte_swap)
			u.watch.cpu = bswap_32(u.watch.cpu);

		save_task_event(task, &u.watch.cpu, sizeof(u.watch.cpu));
		break;

	case EVENT_ID_WATCH_VAR:
		if (read_task_watch_event(task, &u.watch, &len) < 0)
			return -1;
		save_task_event(task, &u.watch, len);
		break;

	default:
		pr_err_ns("unknown event has data: %u\n", rec->addr);
		break;
	}

	return 0;
}

/**
 * read_task_ustack - read user function record for @task
 * @handle: file handle
 * @task: tracee task
 *
 * This function reads current ftrace record and save it to @task->ustack.
 * Data file it accesses should be opened already.  When @task->valid is
 * set, it just returns @task->ustack already read, so if you want to force
 * read from file, the @task->valid should be reset before calling this
 * function.
 *
 * This function returns 0 if succeeded, -1 otherwise.
 */
int read_task_ustack(struct uftrace_data *handle, struct uftrace_task_reader *task)
{
	if (task->valid)
		return 0;

	if (task->done || task->fp == NULL)
		return -1;

	if (__read_task_ustack(task) < 0) {
		task->done = true;
		return -1;
	}

	if (task->ustack.more) {
		if (task->ustack.type == UFTRACE_ENTRY)
			read_task_args(task, &task->ustack, false);
		else if (task->ustack.type == UFTRACE_EXIT)
			read_task_args(task, &task->ustack, true);
		else if (task->ustack.type == UFTRACE_EVENT)
			read_task_event(task, &task->ustack);

		if (unlikely(task->args.args == NULL || task->args.len == 0)) {
			struct uftrace_symbol *sym;
			char *symname;

			/* there might be zero-length struct as a return value */
			if (task->args.args) {
				int actual_len = 0;
				struct uftrace_arg_spec *spec;

				list_for_each_entry(spec, task->args.args, list) {
					if ((task->ustack.type == UFTRACE_EXIT) !=
					    (spec->idx == RETVAL_IDX))
						continue;

					actual_len += spec->size;
				}

				if (actual_len == 0)
					goto out;
			}

			sym = task_find_sym(&handle->sessions, task, &task->ustack);
			symname = symbol_getname(sym, task->ustack.addr);
			pr_err_ns("record missing argument info for %s\n", symname);
			symbol_putname(sym, symname);
		}
	}

out:
	task->valid = true;
	return 0;
}

/**
 * get_task_ustack - read task's user function record
 * @handle: file handle
 * @idx: task index
 *
 * This function returns current ftrace record of @idx-th task from
 * data file in @handle.
 */
static struct uftrace_record *get_task_ustack(struct uftrace_data *handle, int idx)
{
	struct uftrace_task_reader *task;
	struct uftrace_record *curr;
	struct uftrace_rstack_list *rstack_list;
	struct uftrace_session_link *sessions = &handle->sessions;

	task = &handle->tasks[idx];
	rstack_list = &task->rstack_list;

	if (rstack_list->count)
		goto out;

	/*
	 * read task (user) stack until it found an entry that exceeds
	 * the given time filter (-t option).
	 */
	while (read_task_ustack(handle, task) == 0) {
		struct uftrace_session *sess;
		struct uftrace_trigger tr = {};
		uint64_t time_filter = handle->time_filter;
		unsigned size_filter = handle->size_filter;

		curr = &task->ustack;

		/* prevent ustack from invalid access */
		task->valid = false;

		if (!check_time_range(&handle->time_range, curr->time))
			continue;

		sess = find_task_session(sessions, task->t, curr->time);

		if (sess && (curr->type == UFTRACE_ENTRY || curr->type == UFTRACE_EXIT))
			uftrace_match_filter(curr->addr, &sess->filters, &tr);

		if (task->filter.stack) {
			time_filter = task->filter.stack->threshold;
			size_filter = task->filter.stack->size;
		}

		if (tr.flags & TRIGGER_FL_TIME_FILTER)
			time_filter = tr.time;
		if (tr.flags & TRIGGER_FL_SIZE_FILTER)
			size_filter = tr.size;

		if (curr->type == UFTRACE_ENTRY) {
			if (size_filter) {
				struct uftrace_symbol *sym;

				sym = find_symtabs(&sess->sym_info, curr->addr);
				if (sym && sym->size >= size_filter)
					add_to_rstack_list(rstack_list, curr, &task->args);
			}
			else {
				/* it needs to wait until matching exit found */
				add_to_rstack_list(rstack_list, curr, &task->args);
			}

			if (tr.flags & (TRIGGER_FL_TIME_FILTER | TRIGGER_FL_SIZE_FILTER)) {
				struct uftrace_task_filter_stack *tfs;

				tfs = xmalloc(sizeof(*tfs));
				tfs->next = task->filter.stack;
				tfs->depth = curr->depth;
				tfs->context = FSTACK_CTX_USER;
				tfs->threshold = time_filter;
				tfs->size = size_filter;

				task->filter.stack = tfs;
			}
		}
		else if (curr->type == UFTRACE_EXIT) {
			struct uftrace_rstack_list_node *last;
			uint64_t delta;
			int last_type;
			bool filtered = false;

			if (task->filter.stack) {
				struct uftrace_task_filter_stack *tfs;

				tfs = task->filter.stack;
				if (tfs->depth == curr->depth && tfs->context == FSTACK_CTX_USER) {
					/* discard stale filter */
					task->filter.stack = tfs->next;
					free(tfs);
				}
			}

			if (size_filter) {
				struct uftrace_symbol *sym;
				sym = find_symtabs(&sess->sym_info, curr->addr);

				if (sym && sym->size < size_filter)
					continue;
			}

			list_for_each_entry_reverse(last, &rstack_list->read, list) {
				if (last->rstack.type == UFTRACE_ENTRY)
					break;
			}
			if (list_no_entry(last, &rstack_list->read, list)) {
				/* it's already exceeded time filter, just return */
				add_to_rstack_list(rstack_list, curr, &task->args);
				break;
			}

			/* time filter is meaningful for functions */
			while (last->rstack.type != UFTRACE_ENTRY)
				last = list_prev_entry(last, list);

			delta = curr->time - last->rstack.time;
			if (delta < time_filter)
				filtered = true;

			if (handle->caller_filter)
				filtered |= !(tr.flags & TRIGGER_FL_CALLER);

			if (filtered) {
				/*
				 * it might set TRACE trigger, which shows
				 * function even if it's less than the time
				 * filter.
				 */
				if (tr.flags & TRIGGER_FL_TRACE) {
					add_to_rstack_list(rstack_list, curr, &task->args);
					break;
				}

				/* also delete matching entry (at the last) */
				do {
					last = list_last_entry(&rstack_list->read, typeof(*last),
							       list);

					last_type = last->rstack.type;
					delete_last_rstack_list(rstack_list);
				} while (last_type != UFTRACE_ENTRY);
			}
			else {
				/* found! process all existing rstacks in the list */
				add_to_rstack_list(rstack_list, curr, &task->args);
				break;
			}
		}
		else if (curr->type == UFTRACE_EVENT) {
			add_to_rstack_list(rstack_list, curr, &task->args);

			/* show user event regardless of time filter */
			if (curr->addr >= EVENT_ID_USER)
				break;
		}
		else {
			/* TODO: handle LOST properly */
			add_to_rstack_list(rstack_list, curr, &task->args);
			break;
		}
	}
	if (task->done && rstack_list->count == 0)
		return NULL;

out:
	task->valid = true;
	curr = get_first_rstack_list(rstack_list);
	memcpy(&task->ustack, curr, sizeof(*task->rstack));

	return &task->ustack;
}

static int read_user_stack(struct uftrace_data *handle, struct uftrace_task_reader **task)
{
	int i, next_i = -1;
	uint64_t next_time = 0;
	struct uftrace_record *tmp;

	for (i = 0; i < handle->info.nr_tid; i++) {
		tmp = get_task_ustack(handle, i);
		if (tmp == NULL)
			continue;

		if (next_i < 0 || tmp->time < next_time) {
			next_time = tmp->time;
			next_i = i;
		}
	}

	if (next_i < 0)
		return -1;

	*task = &handle->tasks[next_i];

	return next_i;
}

static int read_event_stack(struct uftrace_data *handle, struct uftrace_task_reader **task)
{
	int i, next_i = -1;
	uint64_t next_time = 0;
	struct uftrace_task_reader *t;
	struct uftrace_record *curr, *next;

	for (i = 0; i < handle->info.nr_tid; i++) {
		t = &handle->tasks[i];

		if (t->event_list.count == 0)
			continue;

		curr = get_first_rstack_list(&t->event_list);
		if (next_i < 0 || curr->time < next_time) {
			next_time = curr->time;
			next_i = i;
			next = curr;
		}
	}

	if (next_i < 0)
		return -1;

	*task = &handle->tasks[next_i];
	memcpy(&(*task)->estack, next, sizeof(*next));

	return next_i;
}

/* convert perf sched events to a virtual schedule function */
static bool convert_perf_event(struct uftrace_task_reader *task, struct uftrace_record *orig,
			       struct uftrace_record *dummy)
{
	switch (orig->addr) {
	case EVENT_ID_PERF_SCHED_IN:
	case EVENT_ID_PERF_SCHED_OUT:
	case EVENT_ID_PERF_SCHED_OUT_PREEMPT:
		if (orig->addr == EVENT_ID_PERF_SCHED_OUT ||
		    orig->addr == EVENT_ID_PERF_SCHED_OUT_PREEMPT) {
			dummy->type = UFTRACE_ENTRY;
			task->sched_out_seen = true;
			task->sched_cpu = task->h->last_perf_idx;
		}
		else {
			dummy->type = UFTRACE_EXIT;
			task->sched_out_seen = false;
		}

		dummy->time = orig->time;
		dummy->magic = RECORD_MAGIC;
		dummy->addr = orig->addr;
		dummy->depth = 0;
		dummy->more = 0;

		return true;

	default:
		return false;
	}
}

static void fstack_account_time(struct uftrace_task_reader *task)
{
	struct uftrace_fstack *fstack;
	struct uftrace_record *rstack = task->rstack;
	struct uftrace_record dummy_rec;
	bool is_kernel_func = is_kernel_record(task, rstack);
	int i;

	if (rstack->type == UFTRACE_EVENT) {
		if (!convert_perf_event(task, rstack, &dummy_rec))
			return;

		rstack = &dummy_rec;
	}

	if (!task->fstack_set) {
		/* inherit stack count after [v]fork() or recover from lost */
		task->stack_count = rstack->depth;
		if (rstack->type == UFTRACE_EXIT)
			task->stack_count++;

		task->fstack_set = true;

		if (!task->fork_handled) {
			struct uftrace_task_reader *parent = NULL;

			/* inherit display depth from parent (if possible) */
			if (task->t)
				parent = get_task_handle(task->h, task->t->ppid);

			if (parent && parent->fork_display_depth) {
				task->display_depth = parent->fork_display_depth;
				task->display_depth_set = true;

				/*
				 * cannot update user_stack_count due to the
				 * kernel_skip_out setting.  unfortunately,
				 * it'll show 'negative stack count' debug
				 * message when return to user.
				 */
				if (is_kernel_func)
					task->stack_count += task->display_depth;
			}

			task->fork_handled = true;
		}

		if (is_kernel_func)
			task->stack_count += task->user_stack_count;

		/* calculate duration from now on */
		for (i = 0; i < task->stack_count; i++) {
			fstack = fstack_get(task, i);

			if (fstack != NULL) {
				fstack->total_time = rstack->time; /* start time */
				fstack->child_time = 0;
				fstack->valid = true;
			}
		}

		task->filter.depth = task->h->depth;
	}

	if (task->lost_seen) {
		uint64_t timestamp_after_lost;

		if (rstack->type == UFTRACE_LOST)
			return;

		task->stack_count = rstack->depth;
		if (rstack->type == UFTRACE_EXIT)
			task->stack_count++;

		if (is_kernel_func)
			task->stack_count += task->user_stack_count;

		timestamp_after_lost = rstack->time - 1;
		task->lost_seen = false;

		/* XXX: currently LOST can occur in kernel */
		for (i = 0; i <= rstack->depth; i++) {
			fstack = fstack_get(task, i + task->user_stack_count);

			/* reset timestamp after seeing LOST */
			if (fstack != NULL) {
				fstack->total_time = timestamp_after_lost;
				fstack->child_time = 0;
			}
		}
	}

	if (task->ctx == FSTACK_CTX_KERNEL && !is_kernel_func) {
		/* protect from broken kernel records */
		if (rstack->type != UFTRACE_LOST && rstack != &dummy_rec) {
			task->stack_count = task->user_stack_count;
			task->filter.depth = task->h->depth - task->stack_count;
		}
	}

	/* if task filter was set, it doesn't have func_stack */
	if (task->func_stack == NULL)
		return;

	if (rstack->type == UFTRACE_ENTRY) {
		fstack = fstack_get(task, task->stack_count);
		if (fstack == NULL)
			return;

		fstack->addr = rstack->addr;
		fstack->total_time = rstack->time; /* start time */
		fstack->child_time = 0;
		fstack->valid = true;

		if (is_kernel_func) {
			struct uftrace_sym_info *sinfo;

			sinfo = &task->h->sessions.first->sym_info;
			fstack->addr = get_kernel_address(sinfo, rstack->addr);
		}
	}
	else if (rstack->type == UFTRACE_EXIT) {
		uint64_t delta;
		int idx = task->stack_count - 1;

		fstack = fstack_get(task, idx);
		if (fstack == NULL)
			return;

		delta = rstack->time - fstack->total_time;

		if (!fstack->valid)
			delta = 0UL;
		fstack->valid = false;

		fstack->total_time = delta;
		if (fstack->child_time > fstack->total_time)
			fstack->child_time = fstack->total_time;

		/* add current time to parent's child time */
		if (task->stack_count > 1)
			fstack[-1].child_time += delta;
	}
	else if (rstack->type == UFTRACE_LOST) {
		uint64_t delta;
		uint64_t lost_time = 0;

		task->lost_seen = true;
		task->display_depth_set = false;

		/* XXX: currently LOST can occur in kernel */
		for (i = task->stack_count; i >= task->user_stack_count; i--) {
			fstack = fstack_get(task, i);
			if (fstack == NULL)
				continue;

			if (lost_time == 0)
				lost_time = fstack->total_time + 1;

			/* account time of remaining functions at LOST */
			delta = lost_time - fstack->total_time;
			fstack->total_time = delta;
			if (fstack->child_time > fstack->total_time)
				fstack->child_time = fstack->total_time;

			if (i > 0)
				fstack[-1].child_time += delta;
		}
	}
}

static void fstack_update_stack_count(struct uftrace_task_reader *task)
{
	struct uftrace_record *rstack = task->rstack;
	struct uftrace_record dummy_rec;

	if (rstack->type == UFTRACE_EVENT) {
		if (!convert_perf_event(task, rstack, &dummy_rec))
			return;

		rstack = &dummy_rec;
	}

	if (is_user_record(task, rstack))
		task->ctx = FSTACK_CTX_USER;
	else if (is_kernel_record(task, rstack))
		task->ctx = FSTACK_CTX_KERNEL;
	else
		task->ctx = FSTACK_CTX_UNKNOWN;

	if (rstack->type == UFTRACE_ENTRY)
		task->stack_count++;
	else if (rstack->type == UFTRACE_EXIT && task->stack_count > 0)
		task->stack_count--;

	if (task->ctx == FSTACK_CTX_USER) {
		if (rstack->type == UFTRACE_ENTRY)
			task->user_stack_count++;
		else if (rstack->type == UFTRACE_EXIT && task->user_stack_count > 0)
			task->user_stack_count--;
	}
}

static int find_rstack_cpu(struct uftrace_kernel_reader *kernel, struct uftrace_record *rstack)
{
	int cpu = -1;

	if (rstack->type == UFTRACE_LOST) {
		for (cpu = 0; cpu < kernel->nr_cpus; cpu++) {
			if (rstack->addr == (unsigned)kparser_missed_events(&kernel->parser, cpu) &&
			    rstack->depth == kernel->rstacks[cpu].depth)
				break;
		}
		ASSERT(cpu < kernel->nr_cpus);
	}
	else {
		for (cpu = 0; cpu < kernel->nr_cpus; cpu++) {
			if (rstack->time == kernel->rstacks[cpu].time &&
			    rstack->addr == kernel->rstacks[cpu].addr)
				break;
		}
		ASSERT(cpu < kernel->nr_cpus);
	}

	return cpu;
}

static void __fstack_consume(struct uftrace_task_reader *task, struct uftrace_kernel_reader *kernel,
			     int cpu)
{
	struct uftrace_record *rstack = task->rstack;
	struct uftrace_data *handle = task->h;

	if (rstack->more) {
		struct uftrace_rstack_list_node *node;

		if (is_user_record(task, rstack))
			node = list_first_entry(&task->rstack_list.read, typeof(*node), list);
		else if (is_kernel_record(task, rstack))
			node = list_first_entry(&kernel->rstack_list[cpu].read, typeof(*node),
						list);
		else if (is_event_record(task, rstack))
			node = list_first_entry(&task->event_list.read, typeof(*node), list);
		else if (is_extern_record(task, rstack))
			goto consume_extern_data;
		else
			goto consume_perf_event;

		ASSERT(node->args.data);

		/* restore args/retval to task */
		free(task->args.data);
		task->args.args = node->args.args;
		task->args.data = node->args.data;
		task->args.len = node->args.len;
		node->args.data = NULL;
	}

	if (is_user_record(task, rstack)) {
		task->valid = false;
		if (task->rstack_list.count)
			consume_first_rstack_list(&task->rstack_list);
	}
	else if (is_kernel_record(task, rstack)) {
		kernel->rstack_valid[cpu] = false;
		if (kernel->rstack_list[cpu].count)
			consume_first_rstack_list(&kernel->rstack_list[cpu]);
	}
	else if (is_event_record(task, rstack)) {
		if (rstack->addr == EVENT_ID_PERF_COMM) {
			strncpy(task->t->comm, task->args.data, TASK_COMM_LAST);
			task->t->comm[TASK_COMM_LAST] = '\0';
		}

		if (task->event_list.count)
			consume_first_rstack_list(&task->event_list);
	}
	else if (rstack->type == UFTRACE_LOST) {
		kparser_clear_missed(&kernel->parser, cpu);
	}
	else if (is_extern_record(task, rstack)) {
		struct uftrace_extern_reader *extn;

consume_extern_data:
		extn = handle->extn;
		extn->valid = false;

		/* restore args/retval to task */
		free(task->args.data);
		task->args.data = xstrdup(extn->msg);
		task->args.len = strlen(extn->msg);
	}
	else { /* must be perf event */
		struct uftrace_perf_reader *perf;

consume_perf_event:
		ASSERT(handle->last_perf_idx >= 0);
		perf = &handle->perf[handle->last_perf_idx];

		if (rstack->addr == EVENT_ID_PERF_COMM) {
			memcpy(task->t->comm, perf->u.comm.comm, sizeof(task->t->comm));
		}

		perf->valid = false;
	}

	update_first_timestamp(handle, task, rstack);

	fstack_account_time(task);
	fstack_update_stack_count(task);
}

/**
 * fstack_consume - consume current rstack read
 * @handle: file handle
 * @task: task that holds current rstack
 *
 * This function consumes currently read stack by peek_rstack() so that
 * it can read next rstack in the data file.
 */
void fstack_consume(struct uftrace_data *handle, struct uftrace_task_reader *task)
{
	struct uftrace_record *rstack = task->rstack;
	struct uftrace_kernel_reader *kernel = handle->kernel;
	int cpu = 0;

	if (is_kernel_record(task, rstack))
		cpu = find_rstack_cpu(kernel, rstack);

	__fstack_consume(task, kernel, cpu);
}

static bool peek_perf_data(struct uftrace_task_reader *task)
{
	struct uftrace_data *handle = task->h;
	struct uftrace_perf_reader *perf = NULL;

	read_perf_data(handle);
	perf = &handle->perf[task->sched_cpu];

	if (perf->tid != task->tid)
		return false;

	if (perf->type != PERF_RECORD_SWITCH || perf->u.ctxsw.out)
		return false;

	return true;
}

static bool peek_event_rstack(struct uftrace_task_reader *task)
{
	struct uftrace_record *rec;

	rec = get_first_rstack_list(&task->event_list);

	if (rec->type != UFTRACE_EVENT)
		return false;

	if (rec->addr != EVENT_ID_PERF_SCHED_IN)
		return false;

	return true;
}

/* delay ustack after this schedule event */
static void adjust_rstack_after_schedule(struct uftrace_data *handle,
					 struct uftrace_task_reader *task)
{
	struct uftrace_record *next_rec;
	struct uftrace_fstack *prev_fstack;

	if (task->rstack_list.count == 0)
		return;

	next_rec = get_first_rstack_list(&task->rstack_list);
	if (next_rec->type == UFTRACE_ENTRY) {
		task->timestamp_next = 0;
		return;
	}

	/* get ENTRY record of the user function */
	if (task->rstack->addr == EVENT_ID_PERF_SCHED_IN && task->stack_count >= 2)
		prev_fstack = fstack_get(task, task->stack_count - 2);
	else
		prev_fstack = fstack_get(task, task->stack_count - 1);

	if (prev_fstack == NULL || prev_fstack->addr != next_rec->addr)
		return;

	if (task->rstack->addr == EVENT_ID_PERF_SCHED_OUT ||
	    task->rstack->addr == EVENT_ID_PERF_SCHED_OUT_PREEMPT) {
		if (task->timestamp_next == 0) {
			/*
			 * Get start time of next real (ENTRY) record as
			 * it's necessary to adjust return time after schedule.
			 * Note that estimated time of an EXIT record is a
			 * half between two ENTRY records.
			 *
			 * So we can next timestamp by adding diff between
			 * ENTRY and EXIT (i.e. half of delta) to EXIT.
			 *
			 *  EXIT + (EXIT - ENTRY) = 2*EXIT - ENTRY
			 */
			task->timestamp_next = next_rec->time * 2;
			task->timestamp_next -= prev_fstack->total_time;
		}

		pr_dbg3("task[%*d] delay next record after schedule\n", TASK_ID_LEN, task->tid);
		next_rec->time = ~0ULL;
		return;
	}

	/* if next record's time is later than schedule, it's fine */
	if (task->timestamp_estimate > task->rstack->time) {
		next_rec->time = task->timestamp_estimate;
		return;
	}

	/* calculate half between sched in and next */
	next_rec->time = (task->rstack->time + task->timestamp_next) / 2;
	/* save it in case it's overwritten by subsequent schedule */
	task->timestamp_estimate = next_rec->time;

	pr_dbg3("task[%*d] estimate next record after schedule\n", TASK_ID_LEN, task->tid);
}

static int __read_rstack(struct uftrace_data *handle, struct uftrace_task_reader **taskp,
			 bool consume)
{
	int u, k = -1, p, e, x;
	struct uftrace_task_reader *task = NULL;
	struct uftrace_task_reader *utask = NULL;
	struct uftrace_task_reader *ktask = NULL;
	struct uftrace_task_reader *etask = NULL;
	struct uftrace_kernel_reader *kernel = handle->kernel;
	struct uftrace_perf_reader *perf = NULL;
	struct uftrace_extern_reader *extn = handle->extn;
	uint64_t min_timestamp = ~0ULL;
	enum { NONE, USER, KERNEL, PERF, EVENT, EXTERN } source = NONE;
	/* keep last selected task for external data */
	static struct uftrace_task_reader *last_task = NULL;

	if (handle->time_filter)
		process_perf_event(handle);

	u = read_user_stack(handle, &utask);
	if (u >= 0) {
		min_timestamp = utask->ustack.time;
		source = USER;
	}

	if (has_kernel_data(kernel)) {
		k = read_kernel_stack(handle, &ktask);
		if (k < 0) {
			static bool warn = false;

			if (!warn && consume) {
				pr_dbg2("no more kernel data\n");
				warn = true;
			}
		}
		else if (ktask->kstack.time < min_timestamp) {
			min_timestamp = ktask->kstack.time;
			source = KERNEL;
		}
	}

	if (has_perf_data(handle) && !handle->time_filter) {
		p = read_perf_data(handle);
		perf = &handle->perf[p];

		if (p < 0) {
			static bool warn = false;

			if (!warn && consume) {
				pr_dbg2("no more perf data\n");
				warn = true;
			}
		}
		else if (perf->time < min_timestamp) {
			min_timestamp = perf->time;
			source = PERF;
		}
	}

	if (has_event_data(handle)) {
		e = read_event_stack(handle, &etask);

		if (e >= 0 && etask->estack.time < min_timestamp) {
			min_timestamp = etask->estack.time;
			source = EVENT;
		}
	}

	if (has_extern_data(handle)) {
		x = read_extern_data(handle, extn);

		if (x >= 0 && extn->time < min_timestamp) {
			min_timestamp = extn->time;
			source = EXTERN;
		}
	}

	switch (source) {
	case USER:
		utask->rstack = &utask->ustack;
		task = utask;

		/* subsequent EXIT records might have inverted timestamp */
		if (handle->hdr.feat_mask & ESTIMATE_RETURN && task->timestamp_estimate != 0) {
			if (task->rstack->type == UFTRACE_EXIT &&
			    task->rstack->time <= task->timestamp_estimate) {
				task->rstack->time = ++task->timestamp_estimate;
			}
			else {
				/*
				 * ENTRY records are always fine since
				 * they have real timestamps.
				 */
				task->timestamp_estimate = 0;
				task->timestamp_next = 0;
			}
		}
		break;
	case KERNEL:
		ktask->rstack = get_kernel_record(kernel, ktask, k);
		task = ktask;

		/*
		 * deep kernel trace includes 'schedule' function which
		 * mixed with perf sched event.  since depth of in/out event
		 * differs, consume sched in early with same depth.
		 */
		if (unlikely(task->sched_out_seen)) {
			if (has_perf_data(handle) && !handle->time_filter && peek_perf_data(task)) {
				perf = &handle->perf[task->sched_cpu];
				task->rstack = get_perf_record(handle, perf);
				task->rstack->time = min_timestamp - 1;
			}
			else if (has_event_data(handle) && handle->time_filter &&
				 peek_event_rstack(task)) {
				task->rstack = &task->estack;
				task->rstack->time = min_timestamp - 1;
			}
		}
		break;

	case PERF:
		task = get_task_handle(handle, perf->tid);
		if (unlikely(task == NULL))
			pr_err_ns("cannot find task %d\n", perf->tid);

		task->rstack = get_perf_record(handle, perf);

		if (task->rstack->addr == EVENT_ID_PERF_COMM) {
			task->rstack->more = 1;
			/* abuse task->args to save comm */
			free(task->args.data);
			task->args.data = xstrdup(perf->u.comm.comm);
			task->args.len = strlen(perf->u.comm.comm);
		}
		else if (task->rstack->addr == EVENT_ID_PERF_SCHED_IN ||
			 task->rstack->addr == EVENT_ID_PERF_SCHED_OUT ||
			 task->rstack->addr == EVENT_ID_PERF_SCHED_OUT_PREEMPT) {
			if (handle->hdr.feat_mask & ESTIMATE_RETURN && task->stack_count > 0)
				adjust_rstack_after_schedule(handle, task);
		}
		break;

	case EVENT:
		etask->rstack = &etask->estack;
		task = etask;
		break;

	case EXTERN:
		task = last_task;
		if (unlikely(task == NULL))
			task = &handle->tasks[0];

		task->rstack = get_extern_record(extn, &task->xstack);
		break;

	case NONE:
	default:
		return -1;
	}

	/* update stack count when the rstack is actually used */
	if (consume) {
		last_task = task;
		__fstack_consume(task, kernel, k);
	}

	*taskp = task;
	return 0;
}

/**
 * read_rstack - read and consume the oldest ftrace stack
 * @handle: file handle
 * @task: pointer to the oldest task
 *
 * This function reads all function trace records of each task,
 * compares the timestamp, and find the oldest one.  After this
 * function @task will point a task which has the oldest record, and
 * it can be accessed by @task->rstack.  The oldest record will be
 * consumed, that means it sets another (*@task)->rstack for next
 * call.
 *
 * This function returns 0 if it reads a rstack, -1 if it's done.
 */
int read_rstack(struct uftrace_data *handle, struct uftrace_task_reader **task)
{
	return __read_rstack(handle, task, true);
}

/**
 * peek_rstack - read the oldest ftrace stack
 * @handle: file handle
 * @task: pointer to the oldest task
 *
 * This function reads all function trace records of each task,
 * compares the timestamp, and find the oldest one.  After this
 * function @task will point a task which has the oldest record, and
 * it can be accessed by @task->rstack.  The oldest record will *NOT*
 * be consumed, that means another call to this or @read_rstack will
 * return same (*@task)->rstack.
 *
 * This function returns 0 if it reads a rstack, -1 if it's done.
 */
int peek_rstack(struct uftrace_data *handle, struct uftrace_task_reader **task)
{
	return __read_rstack(handle, task, false);
}

#ifdef UNIT_TEST

#include <sys/stat.h>

#define NUM_TASK 2
#define NUM_RECORD 4

static int test_tids[NUM_TASK] = { 1234, 5678 };
static struct uftrace_task test_tasks[NUM_TASK];
static struct uftrace_record test_record[NUM_TASK][NUM_RECORD] = {
	{
		{ 100, UFTRACE_ENTRY, false, RECORD_MAGIC, 0, 0x40000 },
		{ 200, UFTRACE_ENTRY, false, RECORD_MAGIC, 1, 0x41000 },
		{ 300, UFTRACE_EXIT, false, RECORD_MAGIC, 1, 0x41000 },
		{ 400, UFTRACE_EXIT, false, RECORD_MAGIC, 0, 0x40000 },
	},
	{
		{ 150, UFTRACE_ENTRY, false, RECORD_MAGIC, 0, 0x40000 },
		{ 250, UFTRACE_ENTRY, false, RECORD_MAGIC, 1, 0x41000 },
		{ 350, UFTRACE_EXIT, false, RECORD_MAGIC, 1, 0x41000 },
		{ 450, UFTRACE_EXIT, false, RECORD_MAGIC, 0, 0x40000 },
	}
};

static struct uftrace_record exec_record[] = {
	{ 000, UFTRACE_ENTRY, false, RECORD_MAGIC, 0, 0x40000 }, // main
	{ 100, UFTRACE_ENTRY, false, RECORD_MAGIC, 1, 0x43000 }, // execve
	{ 200, UFTRACE_ENTRY, false, RECORD_MAGIC, 0, 0x40000 }, // main
	{ 300, UFTRACE_ENTRY, false, RECORD_MAGIC, 1, 0x40100 }, // a
	{ 400, UFTRACE_ENTRY, false, RECORD_MAGIC, 2, 0x40200 }, // b
	{ 500, UFTRACE_ENTRY, false, RECORD_MAGIC, 3, 0x40300 }, // c
	{ 600, UFTRACE_EXIT, false, RECORD_MAGIC, 3, 0x40300 }, // c
	{ 700, UFTRACE_EXIT, false, RECORD_MAGIC, 2, 0x40200 }, // b
	{ 800, UFTRACE_EXIT, false, RECORD_MAGIC, 1, 0x40100 }, // a
	{ 900, UFTRACE_EXIT, false, RECORD_MAGIC, 0, 0x40000 }, // main
};

static struct uftrace_session test_sess;
static struct uftrace_data fstack_test_handle;
static void fstack_test_finish_file(void);

static int fstack_test_setup_file(struct uftrace_data *handle, int nr_tid, int *tids, int nr_record,
				  struct uftrace_record **records)
{
	int i;
	char *filename;

	handle->dirname = "tmp.dir";
	handle->info.tids = tids;
	handle->info.nr_tid = nr_tid;
	handle->hdr.max_stack = 16;
	handle->depth = 16;

	if (handle->sessions.first == NULL)
		handle->sessions.first = &test_sess;

	/* it doesn't have kernel functions */
	handle->sessions.first->sym_info.kernel_base = -1ULL;

	if (mkdir(handle->dirname, 0755) < 0) {
		if (errno != EEXIST) {
			pr_dbg("cannot create temp dir: %m\n");
			return -1;
		}
	}

	for (i = 0; i < handle->info.nr_tid; i++) {
		FILE *fp;

		if (asprintf(&filename, "%s/%d.dat", handle->dirname, handle->info.tids[i]) < 0) {
			pr_dbg("cannot alloc filename: %s/%d.dat", handle->dirname,
			       handle->info.tids[i]);
			return -1;
		}

		fp = fopen(filename, "w");
		if (fp == NULL) {
			pr_dbg("file open failed: %m\n");
			free(filename);
			return -1;
		}

		fwrite(records[i], sizeof(**records), nr_record, fp);

		free(filename);
		fclose(fp);

		test_tasks[i].tid = handle->info.tids[i];
	}
	fstack_setup_task(NULL, handle);

	/* for fstack_entry not to crash */
	for (i = 0; i < handle->info.nr_tid; i++) {
		if (handle->tasks[i].t == NULL)
			handle->tasks[i].t = &test_tasks[i];
	}

	setup_perf_data(handle);
	atexit(fstack_test_finish_file);
	return 0;
}

static int fstack_test_setup_normal(struct uftrace_data *handle)
{
	struct uftrace_record *normal_tests[] = {
		test_record[0],
		test_record[1],
	};

	return fstack_test_setup_file(handle, NUM_TASK, test_tids, NUM_RECORD, normal_tests);
}

static int fstack_test_setup_single(struct uftrace_data *handle)
{
	struct uftrace_record *single_tests[] = {
		test_record[0],
	};

	return fstack_test_setup_file(handle, 1, test_tids, NUM_RECORD, single_tests);
}

static int fstack_test_setup_exec(struct uftrace_data *handle)
{
	struct uftrace_record *exec_tests[] = {
		exec_record,
	};
	static struct uftrace_symbol exec_sym = {
		.addr = 0x3000,
		.size = 16,
		.name = "execve",
		.type = ST_PLT_FUNC,
	};
	static struct uftrace_module exec_mod = {
		.symtab = { .sym = &exec_sym, .nr_sym = 1, },
	};
	static struct uftrace_mmap map = {
		.mod = &exec_mod,
		.start = 0x40000,
		.end = 0x50000,
	};
	struct uftrace_msg_sess smsg = {
		.task = { .pid = test_tids[0], .tid = test_tids[0], },
		.sid = "uftrace-session", .namelen = 8,
		/* .name falls through (?) */
	};
	char name[] = "unittest";

	create_session(&handle->sessions, &smsg, "tests", "tests", name, true, false, false);
	create_task(&handle->sessions, &smsg.task, false);

	handle->sessions.first->sym_info.maps = &map;
	handle->sessions.first->sym_info.exec_map = &map;

	return fstack_test_setup_file(handle, 1, test_tids, ARRAY_SIZE(exec_record), exec_tests);
}

static void fstack_test_finish_file(void)
{
	int i;
	char *filename;
	struct uftrace_data *handle = &fstack_test_handle;

	if (handle->dirname == NULL)
		return;

	reset_task_handle(handle);

	for (i = 0; i < handle->info.nr_tid; i++) {
		if (asprintf(&filename, "%s/%d.dat", handle->dirname, handle->info.tids[i]) < 0)
			return;

		remove(filename);
		free(filename);
	}
	remove(handle->dirname);
	handle->dirname = NULL;
}

TEST_CASE(fstack_read)
{
	struct uftrace_data *handle = &fstack_test_handle;
	struct uftrace_task_reader *task;
	int i;

	TEST_EQ(fstack_test_setup_normal(handle), 0);

	for (i = 0; i < NUM_RECORD; i++) {
		pr_dbg("[%d] read rstack from task %d\n", i, test_tids[0]);
		TEST_EQ(read_rstack(handle, &task), 0);
		TEST_EQ(task->tid, test_tids[0]);
		TEST_EQ((uint64_t)task->rstack->type, (uint64_t)test_record[0][i].type);
		TEST_EQ((uint64_t)task->rstack->depth, (uint64_t)test_record[0][i].depth);
		TEST_EQ((uint64_t)task->rstack->addr, (uint64_t)test_record[0][i].addr);

		pr_dbg("[%d] peek rstack from task %d\n", i, test_tids[1]);
		TEST_EQ(peek_rstack(handle, &task), 0);
		TEST_EQ(task->tid, test_tids[1]);
		TEST_EQ((uint64_t)task->rstack->type, (uint64_t)test_record[1][i].type);
		TEST_EQ((uint64_t)task->rstack->depth, (uint64_t)test_record[1][i].depth);
		TEST_EQ((uint64_t)task->rstack->addr, (uint64_t)test_record[1][i].addr);

		pr_dbg("[%d] read rstack from task %d\n", i, test_tids[1]);
		TEST_EQ(read_rstack(handle, &task), 0);
		TEST_EQ(task->tid, test_tids[1]);
		TEST_EQ((uint64_t)task->rstack->type, (uint64_t)test_record[1][i].type);
		TEST_EQ((uint64_t)task->rstack->depth, (uint64_t)test_record[1][i].depth);
		TEST_EQ((uint64_t)task->rstack->addr, (uint64_t)test_record[1][i].addr);
	}

	return TEST_OK;
}

TEST_CASE(fstack_skip)
{
	struct uftrace_data *handle = &fstack_test_handle;
	struct uftrace_task_reader *task;
	struct uftrace_trigger tr = {
		0,
	};
	struct uftrace_opts opts = {
		.event_skip_out = true,
		.libcall = true,
	};

	TEST_EQ(fstack_test_setup_single(handle), 0);

	pr_dbg("set depth filter to skip depth 1 records\n");
	handle->depth = 1;

	pr_dbg("read first rstack for task %d\n", test_tids[0]);
	TEST_EQ(read_rstack(handle, &task), 0);

	TEST_EQ(fstack_entry(task, task->rstack, &tr), 0);
	TEST_EQ(task->tid, test_tids[0]);
	TEST_EQ((uint64_t)task->rstack->type, (uint64_t)test_record[0][0].type);
	TEST_EQ((uint64_t)task->rstack->depth, (uint64_t)test_record[0][0].depth);
	TEST_EQ((uint64_t)task->rstack->addr, (uint64_t)test_record[0][0].addr);

	/* skip filtered records (due to depth) */
	pr_dbg("fstack skip to rstack for task %d again\n", test_tids[0]);
	TEST_EQ(fstack_skip(handle, task, task->rstack->depth, &opts), task);
	TEST_EQ(task->tid, test_tids[0]);
	TEST_EQ((uint64_t)task->rstack->type, (uint64_t)test_record[0][3].type);
	TEST_EQ((uint64_t)task->rstack->depth, (uint64_t)test_record[0][3].depth);
	TEST_EQ((uint64_t)task->rstack->addr, (uint64_t)test_record[0][3].addr);

	return TEST_OK;
}

TEST_CASE(fstack_time)
{
	struct uftrace_data *handle = &fstack_test_handle;
	struct uftrace_task_reader *task;
	int i;

	TEST_EQ(fstack_test_setup_normal(handle), 0);

	pr_dbg("set time filter to skip depth 1 records\n");
	handle->time_filter = 200;

	for (i = 0; i < NUM_TASK; i++) {
		pr_dbg("[%d] read rstack from task %d\n", i, test_tids[0]);
		TEST_EQ(read_rstack(handle, &task), 0);
		TEST_EQ(task->tid, test_tids[0]);
		TEST_EQ((uint64_t)task->rstack->type, (uint64_t)test_record[0][i * 3].type);
		TEST_EQ((uint64_t)task->rstack->depth, (uint64_t)test_record[0][i * 3].depth);
		TEST_EQ((uint64_t)task->rstack->addr, (uint64_t)test_record[0][i * 3].addr);

		pr_dbg("[%d] read rstack from task %d\n", i, test_tids[1]);
		TEST_EQ(read_rstack(handle, &task), 0);
		TEST_EQ(task->tid, test_tids[1]);
		TEST_EQ((uint64_t)task->rstack->type, (uint64_t)test_record[1][i * 3].type);
		TEST_EQ((uint64_t)task->rstack->depth, (uint64_t)test_record[1][i * 3].depth);
		TEST_EQ((uint64_t)task->rstack->addr, (uint64_t)test_record[1][i * 3].addr);
	}

	return TEST_OK;
}

TEST_CASE(fstack_fixup)
{
	struct uftrace_data *handle = &fstack_test_handle;
	struct uftrace_task_reader *task;
	int i;

	TEST_EQ(fstack_test_setup_exec(handle), 0);
	pr_dbg("set fixup filter to detect special functions like exec\n");
	fstack_prepare_fixup(handle);

	for (i = 0; i < ARRAY_SIZE(exec_record); i++) {
		pr_dbg("[%d] read rstack from task %d\n", i, test_tids[0]);
		TEST_EQ(read_rstack(handle, &task), 0);
		TEST_EQ(fstack_check_filter(task), true);

		pr_dbg("check stack count of the task\n");
		TEST_EQ(task->tid, test_tids[0]);
		TEST_EQ((uint64_t)task->rstack->addr, (uint64_t)exec_record[i].addr);
		if (task->rstack->type == UFTRACE_ENTRY)
			TEST_EQ(task->stack_count - 1, (int)exec_record[i].depth);
		else
			TEST_EQ(task->stack_count, (int)exec_record[i].depth);

		pr_dbg("adjust stack count after filter check\n");
		fstack_check_filter_done(task);
	}

	return TEST_OK;
}
#endif /* UNIT_TEST */
