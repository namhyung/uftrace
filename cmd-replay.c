#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <inttypes.h>
#include <stdio_ext.h>
#include <assert.h>
#include <ctype.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/fstack.h"


static int column_index;
static int prev_tid = -1;

static int task_column_depth(struct ftrace_task_handle *task, struct opts *opts)
{
	if (!opts->column_view)
		return 0;

	if (task->column_index == -1)
		task->column_index = column_index++;

	return task->column_index * opts->column_offset;
}

static void print_backtrace(struct ftrace_task_handle *task)
{
	int i;
	struct ftrace_session *sess;
	struct fstack *fstack;
	struct sym *sym;
	char *name;

	for (i = 0; i < task->stack_count - 1; i++) {
		fstack = &task->func_stack[i];
		sess = find_task_session(task->tid, fstack->total_time);

		if (sess)
			sym = find_symtabs(&sess->symtabs, fstack->addr);
		else
			sym = NULL;

		name = symbol_getname(sym, fstack->addr);
		pr_out("  backtrace [%5d] |", task->tid);
		pr_gray(" /* [%2d] %s */\n", i, name);
		symbol_putname(sym, name);
	}
}

static int print_flat_rstack(struct ftrace_file_handle *handle,
			     struct ftrace_task_handle *task,
			     struct opts *opts)
{
	static int count;
	struct ftrace_ret_stack *rstack = task->rstack;
	struct ftrace_session *sess = find_task_session(task->tid, rstack->time);
	struct symtabs *symtabs;
	struct sym *sym;
	char *name;
	struct fstack *fstack;

	if (sess == NULL)
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtabs(symtabs, rstack->addr);
	name = symbol_getname(sym, rstack->addr);
	fstack = &task->func_stack[rstack->depth];

	if (rstack->type == FTRACE_ENTRY) {
		pr_out("[%d] ==> %d/%d: ip (%s), time (%"PRIu64")\n",
		       count++, task->tid, rstack->depth,
		       name, rstack->time);
	} else if (rstack->type == FTRACE_EXIT) {
		pr_out("[%d] <== %d/%d: ip (%s), time (%"PRIu64":%"PRIu64")\n",
		       count++, task->tid, rstack->depth,
		       name, rstack->time, fstack->total_time);
	} else if (rstack->type == FTRACE_LOST) {
		pr_out("[%d] XXX %d: lost %d records\n",
		       count++, task->tid, (int)rstack->addr);
	}

	symbol_putname(sym, name);
	return 0;
}

static void print_task_newline(int current_tid)
{
	if (prev_tid != -1 && current_tid != prev_tid)
		pr_out(" %7s %2s %7s |\n", "", "", "");

	prev_tid = current_tid;
}

void get_argspec_string(struct ftrace_task_handle *task,
		        char *args, size_t len,
		        enum argspec_string_bits str_mode)
{
	int i = 0, n = 0;
	char str[64];
	const int null_str = -1;
	void *data = task->args.data;
	struct list_head *arg_list = task->args.args;
	struct ftrace_arg_spec *spec;
	union {
		long i;
		float f;
		double d;
		long long ll;
		long double D;
		unsigned char v[16];
	} val;

	bool needs_paren      = !!(str_mode & NEEDS_PAREN);
	bool needs_semi_colon = !!(str_mode & NEEDS_SEMI_COLON);
	bool has_more         = !!(str_mode & HAS_MORE);
	bool is_retval        = !!(str_mode & IS_RETVAL);
	bool needs_assignment = !!(str_mode & NEEDS_ASSIGNMENT);
	bool needs_escape     = !!(str_mode & NEEDS_ESCAPE);

	if (!has_more) {
		if (needs_paren)
			strcpy(args, "()");
		else {
			if (is_retval && needs_semi_colon)
				args[n++] = ';';
			args[n] = '\0';
		}
		return;
	} else if (!needs_escape)
		needs_semi_colon = true;

	assert(arg_list && !list_empty(arg_list));

	if (!is_retval)
		args[n++] = '(';
	else if (needs_assignment) {
		args[n++] = ' ';
		args[n++] = '=';
		args[n++] = ' ';
	}
	list_for_each_entry(spec, arg_list, list) {
		char fmtstr[16];
		char *len_mod[] = { "hh", "h", "", "ll" };
		char fmt, *lm;
		unsigned idx;
		size_t size = spec->size;

		/* skip unwanted arguments or retval */
		if (is_retval != (spec->idx == RETVAL_IDX))
			continue;

		if (i > 0) {
			n += snprintf(args + n, len, ", ");
			len -= n;
		}

		memset(val.v, 0, sizeof(val));
		fmt = ARG_SPEC_CHARS[spec->fmt];

		switch (spec->fmt) {
		case ARG_FMT_AUTO:
			memcpy(val.v, data, spec->size);
			if (val.i > 100000L || val.i < -100000L) {
				fmt = 'x';
				/*
				 * Show small negative integers naturally
				 * on 64-bit systems.  The conversion is
				 * required to avoid compiler warnings
				 * on 32-bit systems.
				 */
				if (sizeof(long) == sizeof(uint64_t)) {
					uint64_t val64 = val.i;

					if (val64 >  0xffff0000 &&
					    val64 <= 0xffffffff) {
						fmt = 'd';
						idx = 2;
						break;
					}
				}
			}
			/* fall through */
		case ARG_FMT_SINT:
		case ARG_FMT_UINT:
		case ARG_FMT_HEX:
			idx = ffs(spec->size) - 1;
			break;
		default:
			idx = 2;
			break;
		}

		if (spec->fmt == ARG_FMT_STR) {
			unsigned short slen;
			memcpy(&slen, data, 2);

			memcpy(str, data + 2, slen);
			str[slen] = '\0';

			if (!memcmp(str, &null_str, sizeof(null_str)))
				n += snprintf(args + n, len, "NULL");
			else if (needs_escape)
				/* quotation mark has to be escaped by backslash
				   in chrome trace json format */
				n += snprintf(args + n, len, "\\\"%.*s\\\"",
					      slen, str);
			else
				n += snprintf(args + n, len, "\"%.*s\"",
					      slen, str);

			size = slen + 2;
		}
		else if (spec->fmt == ARG_FMT_CHAR) {
			char c;

			memcpy(&c, data, 1);
			if (isprint(c))
				n += snprintf(args + n, len, "'%c'", c);
			else
				n += snprintf(args + n, len, "'\\x%02hhx'", c);
			size = 1;
		}
		else if (spec->fmt == ARG_FMT_FLOAT) {
			if (spec->size == 10)
				lm = "L";
			else
				lm = len_mod[idx];

			memcpy(val.v, data, spec->size);
			snprintf(fmtstr, sizeof(fmtstr), "%%#%s%c", lm, fmt);

			switch (spec->size) {
			case 4:
				n += snprintf(args + n, len, fmtstr, val.f);
				break;
			case 8:
				n += snprintf(args + n, len, fmtstr, val.d);
				break;
			case 10:
				n += snprintf(args + n, len, fmtstr, val.D);
				break;
			default:
				pr_dbg("invalid floating-point type size %d\n",
				       spec->size);
				break;
			}
		}
		else {
			assert(idx < ARRAY_SIZE(len_mod));
			lm = len_mod[idx];

			if (spec->fmt != ARG_FMT_AUTO)
				memcpy(val.v, data, spec->size);

			snprintf(fmtstr, sizeof(fmtstr), "%%#%s%c", lm, fmt);

			if (spec->size > (int)sizeof(long))
				n += snprintf(args + n, len, fmtstr, val.ll);
			else
				n += snprintf(args + n, len, fmtstr, val.i);
		}

		i++;
		len -= n;
		data += ALIGN(size, 4);

		/* read only the first match for retval */
		if (is_retval)
			break;
	}
	if (!is_retval) {
		args[n] = ')';
		args[n+1] = '\0';
	} else {
		if (needs_semi_colon)
			args[n++] = ';';
		args[n] = '\0';
	}
}

static int print_graph_rstack(struct ftrace_file_handle *handle,
			      struct ftrace_task_handle *task,
			      struct opts *opts)
{
	struct ftrace_ret_stack *rstack = task->rstack;
	struct ftrace_session *sess;
	struct symtabs *symtabs;
	struct sym *sym = NULL;
	enum argspec_string_bits str_mode = 0;
	char *symname = NULL;

	if (task == NULL)
		return 0;

	if (rstack->type == FTRACE_LOST)
		goto lost;

	sess = find_task_session(task->tid, rstack->time);
	if (sess == NULL && !is_kernel_address(rstack->addr))
		return 0;

	symtabs = &sess->symtabs;
	sym = find_symtabs(symtabs, rstack->addr);
	symname = symbol_getname(sym, rstack->addr);

	if (rstack->type == FTRACE_ENTRY && symname[strlen(symname) - 1] != ')')
		str_mode |= NEEDS_PAREN;

	if (opts->kernel_skip_out) {
		/* skip kernel functions outside user functions */
		if (!task->user_stack_count && is_kernel_address(rstack->addr))
			goto out;
	}

	char args[1024];
	if (rstack->type == FTRACE_ENTRY) {
		struct ftrace_task_handle *next = NULL;
		struct fstack *fstack;
		int rstack_depth = rstack->depth;
		int depth = task->display_depth;
		struct ftrace_trigger tr = {
			.flags = 0,
		};
		int ret;

		ret = fstack_entry(task, rstack, &tr);
		if (ret < 0)
			goto out;

		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		if (tr.flags & TRIGGER_FL_BACKTRACE)
			print_backtrace(task);

		depth += task_column_depth(task, opts);

		if (rstack->more)
			str_mode |= HAS_MORE;
		get_argspec_string(task, args, sizeof(args), str_mode);

		fstack = &task->func_stack[task->stack_count - 1];

		if (!opts->no_merge)
			next = fstack_skip(handle, task, rstack_depth);

		if (task == next &&
		    next->rstack->depth == rstack_depth &&
		    next->rstack->type == FTRACE_EXIT) {
			char retval[1024];

			/* leaf function - also consume return record */
			fstack_consume(handle, next);

			str_mode = IS_RETVAL | NEEDS_SEMI_COLON;
			if (next->rstack->more) {
				str_mode |= HAS_MORE;
				str_mode |= NEEDS_ASSIGNMENT;
			}
			get_argspec_string(task, retval, sizeof(retval), str_mode);

			print_time_unit(fstack->total_time);

			pr_out(" [%5d] | %*s", task->tid, depth * 2, "");
			if (tr.flags & TRIGGER_FL_COLOR) {
				pr_color(tr.color, "%s", symname);
				pr_out("%s%s\n", args, retval);
			}
			else
				pr_out("%s%s%s\n", symname, args, retval);

			/* fstack_update() is not needed here */

			fstack_exit(task);
		}
		else {
			/* function entry */
			print_time_unit(0UL);
			pr_out(" [%5d] | %*s", task->tid, depth * 2, "");
			if (tr.flags & TRIGGER_FL_COLOR) {
				pr_color(tr.color, "%s", symname);
				pr_out("%s {\n", args);
			}
			else
				pr_out("%s%s {\n", symname, args);

			fstack_update(FTRACE_ENTRY, task, fstack);
		}
	}
	else if (rstack->type == FTRACE_EXIT) {
		struct fstack *fstack;

		/* function exit */
		fstack = &task->func_stack[task->stack_count];

		if (!(fstack->flags & FSTACK_FL_NORECORD) && fstack_enabled) {
			int depth = fstack_update(FTRACE_EXIT, task, fstack);
			char *retval = args;

			depth += task_column_depth(task, opts);

			str_mode = IS_RETVAL;
			if (rstack->more) {
				str_mode |= HAS_MORE;
				str_mode |= NEEDS_ASSIGNMENT;
			}
			get_argspec_string(task, retval, sizeof(args), str_mode);

			/* give a new line when tid is changed */
			if (opts->task_newline)
				print_task_newline(task->tid);

			print_time_unit(fstack->total_time);
			pr_out(" [%5d] | %*s}%s", task->tid, depth * 2, "", retval);
			if (opts->comment)
				pr_gray(" /* %s */\n", symname);
			else
				pr_gray("\n");
		}

		fstack_exit(task);
	}
	else if (rstack->type == FTRACE_LOST) {
		int depth, losts;
lost:
		depth = task->display_depth + 1;
		losts = (int)rstack->addr;

		/* skip kernel lost messages outside of user functions */
		if (opts->kernel_skip_out && task->user_stack_count == 0)
			return 0;

		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		print_time_unit(0UL);
		pr_out(" [%5d] |", task->tid);

		if (losts > 0)
			pr_red(" %*s/* LOST %d records!! */\n",
			       depth * 2, "", losts);
		else /* kernel sometimes have unknown count */
			pr_red(" %*s/* LOST some records!! */\n",
			       depth * 2, "");
	}
out:
	symbol_putname(sym, symname);
	return 0;
}

static void print_warning(struct ftrace_task_handle *task)
{
	print_time_unit(0UL);
	pr_out(" %7s |", "");
	pr_red(" %*s/* inverted time: broken data? */\n",
	       (task->display_depth + 1) * 2, "");
}

static bool skip_sys_exit(struct opts *opts, struct ftrace_task_handle *task)
{
	unsigned long ip;

	if (task->func_stack == NULL)
		return true;

	/* skip 'sys_exit[_group] at last for kernel tracing */
	if (!opts->kernel || task->user_stack_count != 0)
		return false;

	ip = task->func_stack[0].addr;
	if (is_kernel_address(ip)) {
		struct sym *sym = find_symtabs(NULL, ip);

		if (!strncmp(sym->name, "sys_exit", 8))
			return true;
	}
	return false;
}

static void print_remaining_stack(struct opts *opts,
				  struct ftrace_file_handle *handle)
{
	int i;
	int total = 0;

	for (i = 0; i < handle->nr_tasks; i++) {
		if (skip_sys_exit(opts, &handle->tasks[i]))
			continue;

		total += handle->tasks[i].stack_count;
	}

	if (total == 0)
		return;

	pr_out("\nuftrace stopped tracing with remaining functions");
	pr_out("\n===============================================\n");

	for (i = 0; i < handle->nr_tasks; i++) {
		struct ftrace_task_handle *task = &handle->tasks[i];

		if (task->stack_count == 0)
			continue;

		if (skip_sys_exit(opts, task))
			continue;

		pr_out("task: %d\n", task->tid);

		while (task->stack_count-- > 0) {
			struct fstack *fstack = &task->func_stack[task->stack_count];
			uint64_t time = fstack->total_time;
			struct ftrace_session *sess = find_task_session(task->tid, time);
			unsigned long ip = fstack->addr;
			struct symtabs *symtabs;
			struct sym *sym;
			char *symname;

			if (sess || is_kernel_address(ip)) {
				symtabs = &sess->symtabs;
				sym = find_symtabs(symtabs, ip);
			} else
				sym = NULL;

			symname = symbol_getname(sym, ip);

			pr_out("[%d] %s\n", task->stack_count, symname);

			symbol_putname(sym, symname);
		}
		pr_out("\n");
	}
}

int command_replay(int argc, char *argv[], struct opts *opts)
{
	int ret;
	uint64_t prev_time = 0;
	struct ftrace_file_handle handle;
	struct ftrace_task_handle *task;
	struct ftrace_kernel kern;

	__fsetlocking(outfp, FSETLOCKING_BYCALLER);
	__fsetlocking(logfp, FSETLOCKING_BYCALLER);

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

	if (!opts->flat)
		pr_out("# DURATION    TID     FUNCTION\n");

	while (read_rstack(&handle, &task) == 0 && !ftrace_done) {
		struct ftrace_ret_stack *rstack = task->rstack;
		uint64_t curr_time = rstack->time;

		/* skip user functions if --kernel-only is set */
		if (opts->kernel_only && !is_kernel_address(rstack->addr))
			continue;

		/*
		 * data sanity check: timestamp should be ordered.
		 * But print_graph_rstack() may change task->rstack
		 * during fstack_skip().  So check the timestamp here.
		 */
		if (curr_time) {
			if (prev_time > curr_time)
				print_warning(task);
			prev_time = rstack->time;
		}

		if (opts->flat)
			ret = print_flat_rstack(&handle, task, opts);
		else
			ret = print_graph_rstack(&handle, task, opts);

		if (ret)
			break;
	}

	print_remaining_stack(opts, &handle);

	if (handle.kern)
		finish_kernel_data(handle.kern);

	close_data_file(opts, &handle);

	return ret;
}
