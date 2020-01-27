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
#include "utils/list.h"
#include "utils/kernel.h"
#include "utils/field.h"

#include "libtraceevent/event-parse.h"

static bool flat_mode = false;

static int column_index;
static int prev_tid = -1;

static LIST_HEAD(output_fields);

#define NO_TIME  (void *)1  /* to suppress duration */

static void print_duration(struct field_data *fd)
{
	struct fstack *fstack = fd->fstack;
	void *arg = fd->arg;
	uint64_t d = 0;

	/* any non-NULL argument suppresses the output */
	if (fstack && arg == NULL)
		d = fstack->total_time;

	print_time_unit(d);
}

static void print_tid(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;
	pr_out("[%6d]", task->tid);
}

static void print_addr(struct field_data *fd)
{
	struct fstack *fstack = fd->fstack;

	/* uftrace records (truncated) 48-bit addresses */
	int width = sizeof(long) == 4 ? 8 : 12;

	if (fstack == NULL)  /* LOST */
		pr_out("%*s", width, "");
	else
		pr_out("%*"PRIx64, width, effective_addr(fstack->addr));
}

static void print_timestamp(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;

	uint64_t  sec = task->timestamp / NSEC_PER_SEC;
	uint64_t nsec = task->timestamp % NSEC_PER_SEC;

	pr_out("%8"PRIu64".%09"PRIu64, sec, nsec);
}

static void print_timedelta(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;
	uint64_t delta = 0;

	if (task->timestamp_last)
		delta = task->timestamp - task->timestamp_last;

	print_time_unit(delta);
}

static void print_elapsed(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;
	uint64_t elapsed = task->timestamp - task->h->time_range.first;

	print_time_unit(elapsed);
}

static void print_task(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;

	pr_out("%*s", 15, task->t->comm);
}

static void print_module(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;
	struct fstack *fstack = fd->fstack;
	uint64_t timestamp = task->timestamp;
	struct uftrace_session *s;
	struct uftrace_mmap *map;
	char *modname = "[unknown]";

	/* for EVENT or LOST record */
	if (fstack == NULL) {
		pr_out("%*s", 16, "");
		return;
	}

	s = find_task_session(&task->h->sessions, task->t, timestamp);
	if (s) {
		map = find_map(&s->symtabs, fstack->addr);
		if (map == MAP_KERNEL)
			modname = "[kernel]";
		else if (map)
			modname = basename(map->libname);
	}

	pr_out("%*.*s", 16, 16, modname);
}

static struct display_field field_duration = {
	.id      = REPLAY_F_DURATION,
	.name    = "duration",
	.header  = " DURATION ",
	.length  = 10,
	.print   = print_duration,
	.list    = LIST_HEAD_INIT(field_duration.list),
};

static struct display_field field_tid = {
	.id      = REPLAY_F_TID,
	.name    = "tid",
	.header  = "   TID  ",
	.length  = 8,
	.print   = print_tid,
	.list    = LIST_HEAD_INIT(field_tid.list),
};

static struct display_field field_addr = {
	.id      = REPLAY_F_ADDR,
	.name    = "addr",
#if __SIZEOF_LONG__ == 4
	.header  = " ADDRESS",
	.length  = 8,
#else
	.header  = "   ADDRESS  ",
	.length  = 12,
#endif
	.print   = print_addr,
	.list    = LIST_HEAD_INIT(field_addr.list),
};

static struct display_field field_time = {
	.id      = REPLAY_F_TIMESTAMP,
	.name    = "time",
	.header  = "     TIMESTAMP    ",
	.length  = 18,
	.print   = print_timestamp,
	.list    = LIST_HEAD_INIT(field_time.list),
};

static struct display_field field_delta = {
	.id      = REPLAY_F_TIMEDELTA,
	.name    = "delta",
	.header  = " TIMEDELTA",
	.length  = 10,
	.print   = print_timedelta,
	.list    = LIST_HEAD_INIT(field_delta.list),
};

static struct display_field field_elapsed = {
	.id      = REPLAY_F_ELAPSED,
	.name    = "elapsed",
	.header  = "  ELAPSED ",
	.length  = 10,
	.print   = print_elapsed,
	.list    = LIST_HEAD_INIT(field_elapsed.list),
};

static struct display_field field_task = {
	.id      = REPLAY_F_TASK,
	.name    = "task",
	.header  = "      TASK NAME",
	.length  = 15,
	.print   = print_task,
	.list    = LIST_HEAD_INIT(field_task.list),
};

static struct display_field field_module = {
	.id      = REPLAY_F_MODULE,
	.name    = "module",
	.header  = "     MODULE NAME",
	.length  = 16,
	.print   = print_module,
	.list    = LIST_HEAD_INIT(field_module.list),
};

/* index of this table should be matched to display_field_id */
static struct display_field *field_table[] = {
	&field_duration,
	&field_tid,
	&field_addr,
	&field_time,
	&field_delta,
	&field_elapsed,
	&field_task,
	&field_module,
};

static void print_field(struct uftrace_task_reader *task,
			struct fstack *fstack, void *arg)
{
	struct field_data fd = {
		.task = task,
		.fstack = fstack,
		.arg = arg,
	};

	if (print_field_data(&output_fields, &fd, 1))
		pr_out(" | ");
}

static void setup_default_field(struct list_head *fields, struct opts *opts)
{
	if (opts->range.start > 0 || opts->range.stop > 0) {
		if (opts->range.start_elapsed || opts->range.stop_elapsed)
			add_field(fields, field_table[REPLAY_F_ELAPSED]);
		else
			add_field(fields, field_table[REPLAY_F_TIMESTAMP]);
	}
	if (flat_mode)
		add_field(fields, field_table[REPLAY_F_ELAPSED]);
	else
		add_field(fields, field_table[REPLAY_F_DURATION]);
	add_field(fields, field_table[REPLAY_F_TID]);
}

static int task_column_depth(struct uftrace_task_reader *task, struct opts *opts)
{
	if (!opts->column_view)
		return 0;

	if (task->column_index == -1)
		task->column_index = column_index++;

	return task->column_index * opts->column_offset;
}

static void print_backtrace(struct uftrace_task_reader *task)
{
	struct uftrace_session_link *sessions = &task->h->sessions;
	int i;

	for (i = 0; i < task->stack_count - 1; i++) {
		struct display_field *field;
		struct sym *sym;
		char *name;
		struct fstack *fstack = &task->func_stack[i];
		struct field_data fd = {
			.task = task,
			.fstack = fstack,
		};

		sym = task_find_sym_addr(sessions, task,
					 fstack->total_time, fstack->addr);

		pr_out(" ");
		list_for_each_entry(field, &output_fields, list) {
			if (field->id == REPLAY_F_DURATION)
				pr_out("%*s", field->length, "backtrace");
			else
				field->print(&fd);
			pr_out(" ");
		}
		if (!list_empty(&output_fields))
			pr_out("| ");

		name = symbol_getname(sym, fstack->addr);
		pr_gray("/* [%2d] %s */\n", i, name);
		symbol_putname(sym, name);
	}
}

static void print_event(struct uftrace_task_reader *task,
			struct uftrace_record *urec,
			int color)
{
	unsigned evt_id = urec->addr;
	char *evt_name = get_event_name(task->h, evt_id);

	if (evt_id == EVENT_ID_EXTERN_DATA) {
		pr_color(color, "%s: %s", evt_name, (char *)task->args.data);
	}
	else if (evt_id >= EVENT_ID_USER) {
		/* TODO: some events might have arguments */
		pr_color(color, "%s", evt_name);
	}
	else if (evt_id >= EVENT_ID_PERF) {
		pr_color(color, "%s", evt_name);

		if (evt_id == EVENT_ID_PERF_COMM)
			pr_color(color, " (name=%s)", (char *)task->args.data);
	}
	else if (evt_id >= EVENT_ID_BUILTIN) {
		union {
			struct uftrace_proc_statm *statm;
			struct uftrace_page_fault *page_fault;
			struct uftrace_pmu_cycle  *cycle;
			struct uftrace_pmu_cache  *cache;
			struct uftrace_pmu_branch *branch;
			int                       *cpu;
		} u;

		switch (evt_id) {
		case EVENT_ID_READ_PROC_STATM:
			u.statm = task->args.data;
			pr_color(color, "%s (size=%"PRIu64"KB, rss=%"PRIu64"KB, shared=%"PRIu64"KB)",
				 evt_name, u.statm->vmsize, u.statm->vmrss, u.statm->shared);
			break;
		case EVENT_ID_READ_PAGE_FAULT:
			u.page_fault = task->args.data;
			pr_color(color, "%s (major=%"PRIu64", minor=%"PRIu64")",
				 evt_name, u.page_fault->major, u.page_fault->minor);
			break;
		case EVENT_ID_READ_PMU_CYCLE:
			u.cycle = task->args.data;
			pr_color(color, "%s (cycle=%"PRIu64", instructions=%"PRIu64")",
				 evt_name, u.cycle->cycles, u.cycle->instrs);
			break;
		case EVENT_ID_READ_PMU_CACHE:
			u.cache = task->args.data;
			pr_color(color, "%s (refers=%"PRIu64", misses=%"PRIu64")",
				 evt_name, u.cache->refers, u.cache->misses);
			break;
		case EVENT_ID_READ_PMU_BRANCH:
			u.branch = task->args.data;
			pr_color(color, "%s (branch=%"PRIu64", misses=%"PRIu64")",
				 evt_name, u.branch->branch, u.branch->misses);
			break;
		case EVENT_ID_DIFF_PROC_STATM:
			u.statm = task->args.data;
			pr_color(color, "%s (size=%+"PRId64"KB, rss=%+"PRId64"KB, shared=%+"PRId64"KB)",
				 evt_name, u.statm->vmsize, u.statm->vmrss, u.statm->shared);
			break;
		case EVENT_ID_DIFF_PAGE_FAULT:
			u.page_fault = task->args.data;
			pr_color(color, "%s (major=%+"PRId64", minor=%+"PRId64")",
				 evt_name, u.page_fault->major, u.page_fault->minor);
			break;
		case EVENT_ID_DIFF_PMU_CYCLE:
			u.cycle = task->args.data;
			pr_color(color, "%s (cycle=%+"PRId64", instructions=%+"PRId64", IPC=%.2f)",
				 evt_name, u.cycle->cycles, u.cycle->instrs,
				 (float)u.cycle->instrs / u.cycle->cycles);
			break;
		case EVENT_ID_DIFF_PMU_CACHE:
			u.cache = task->args.data;
			pr_color(color, "%s (refers=%+"PRId64", misses=%+"PRId64", hit=%"PRId64"%%)",
				 evt_name, u.cache->refers, u.cache->misses,
				 (u.cache->refers - u.cache->misses) * 100 / u.cache->refers);
			break;
		case EVENT_ID_DIFF_PMU_BRANCH:
			u.branch = task->args.data;
			pr_color(color, "%s (branch=%+"PRId64", misses=%+"PRId64", predict=%"PRId64"%%)",
				 evt_name, u.branch->branch, u.branch->misses,
				 (u.branch->branch - u.branch->misses) * 100 / u.branch->branch);
			break;
		case EVENT_ID_WATCH_CPU:
			u.cpu = task->args.data;
			pr_color(color, "%s (cpu=%d)", evt_name, *u.cpu);
			break;
		default:
			pr_color(color, "%s", evt_name);
		}
	}
	else {
		/* kernel events */
		pr_color(color, "%s (%.*s)", evt_name,
			 task->args.len, task->args.data);
	}
	free(evt_name);
}

static void print_task_newline(int current_tid)
{
	if (prev_tid != -1 && current_tid != prev_tid) {
		if (print_empty_field(&output_fields, 1))
			pr_out(" | ");
		pr_out("\n");
	}

	prev_tid = current_tid;
}

static int print_flat_rstack(struct uftrace_data *handle,
			     struct uftrace_task_reader *task,
			     struct opts *opts)
{
	struct uftrace_record *rstack;
	struct uftrace_session_link *sessions = &handle->sessions;
	struct sym *sym = NULL;
	char *symname = NULL;

	if (task == NULL)
		return 0;

	rstack = task->rstack;
	if (rstack->type == UFTRACE_LOST)
		goto lost;

	sym = task_find_sym(sessions, task, rstack);
	symname = symbol_getname(sym, rstack->addr);

	/* skip it if --no-libcall is given */
	if (!opts->libcall && sym && sym->type == ST_PLT_FUNC)
		goto out;

	task->timestamp_last = task->timestamp;
	task->timestamp = rstack->time;

	if (rstack->type == UFTRACE_ENTRY) {
		enum argspec_string_bits str_mode = NEEDS_PAREN;
		struct fstack *fstack;
		char args[1024];

		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		if (rstack->more)
			str_mode |= HAS_MORE;
		get_argspec_string(task, args, sizeof(args), str_mode);

		fstack = &task->func_stack[task->stack_count - 1];

		/* function entry */
		print_field(task, fstack, NO_TIME);
		pr_out("%s%s\n", symname, args);

		fstack_update(UFTRACE_ENTRY, task, fstack);
	}
	else if (rstack->type == UFTRACE_LOST) {
		int losts;
lost:
		losts = (int)rstack->addr;

		/* skip kernel lost messages outside of user functions */
		if (opts->kernel_skip_out && task->user_stack_count == 0)
			return 0;

		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		print_field(task, NULL, NO_TIME);

		if (losts > 0)
			pr_red("/* LOST %d records!! */\n", losts);
		else /* kernel sometimes have unknown count */
			pr_red("/* LOST some records!! */\n");
		return 0;
	}
out:
	symbol_putname(sym, symname);
	return 0;
}

#define print_char(c)                                                   \
({ args[n] = c; n++; len--; })

#define print_args(fmt, ...)						\
({ int _x = snprintf(args + n, len, fmt, ##__VA_ARGS__); n += _x; len -= _x; })

#define print_json_escaped_char(c)					\
	do {								\
		if (c == '\n')						\
			print_args("\\\\n");				\
		else if (c == '\t')					\
			print_args("\\\\t");				\
		else if (c == '\\')					\
			print_args("\\\\");				\
		else if (c == '"')					\
			print_args("\\\"");				\
		else if (isprint(c))					\
			print_char(c);                                  \
		else							\
			print_args("\\\\x%02hhx", c);			\
	} while (0)

#define print_escaped_char(c)						\
	do {								\
		if (c == '\0')						\
			print_args("\\0");				\
		else if (c == '\b')					\
			print_args("\\b");				\
		else if (c == '\n')                                     \
			print_args("\\n");				\
		else							\
			print_char(c);                                  \
	} while (0)

void get_argspec_string(struct uftrace_task_reader *task,
			char *args, size_t len,
			enum argspec_string_bits str_mode)
{
	int i = 0, n = 0;
	char *str = NULL;

	const int null_str = -1;
	void *data = task->args.data;
	struct list_head *arg_list = task->args.args;
	struct uftrace_arg_spec *spec;
	union {
		long i;
		void *p;
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
	bool needs_json       = !!(str_mode & NEEDS_JSON);

	if (!has_more) {
		if (needs_paren)
			strcpy(args, "()");
		else {
			if (is_retval && needs_semi_colon)
				args[n++] = ';';
			args[n] = '\0';
		}
		return;
	}

	assert(arg_list && !list_empty(arg_list));

	if (needs_paren)
		print_args("%s(%s", color_bold, color_reset);
	else if (needs_assignment)
		print_args("%s = %s", color_bold, color_reset);

	list_for_each_entry(spec, arg_list, list) {
		char fmtstr[16];
		char *len_mod[] = { "hh", "h", "", "ll" };
		char fmt, *lm;
		unsigned idx;
		size_t size = spec->size;

		/* skip unwanted arguments or retval */
		if (is_retval != (spec->idx == RETVAL_IDX))
			continue;

		if (i > 0)
			print_args("%s, %s", color_bold, color_reset);

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
		case ARG_FMT_HEX:
			idx = ffs(spec->size) - 1;
			break;
		case ARG_FMT_UINT:
			memcpy(val.v, data, spec->size);
			if ((unsigned long)val.i > 100000UL)
				fmt = 'x';
			idx = ffs(spec->size) - 1;
			break;
		default:
			idx = 2;
			break;
		}

		if (spec->fmt == ARG_FMT_STR ||
		    spec->fmt == ARG_FMT_STD_STRING) {
			unsigned short slen;

			memcpy(&slen, data, 2);

			str = xmalloc(slen + 1);
			memcpy(str, data + 2, slen);
			str[slen] = '\0';

			if (slen == 4 && !memcmp(str, &null_str, sizeof(null_str)))
				print_args("NULL");
			else if (needs_json) {
				char *p = str;
				print_args("\\\"");
				while (*p) {
					char c = *p++;
					print_json_escaped_char(c);
				}
				print_args("\\\"");
			}
			else {
				print_args("%s", color_string);
				print_args("\"");

				char *p = str;
				while (*p) {
					char c = *p++;
					if (c & 0x80) {
						break;
					}
				}
				/*
				* if value of character is over than 128(0x80),
				* then it will be UTF-8 string
				*/
				if (*p) {
					print_args("%.*s", slen, str);
				}
				else {
					p = str;
					while (*p) {
						char c = *p++;
						print_escaped_char(c);
					}
				}

				print_args("\"");
				print_args("%s", color_reset);
			}

			/* std::string can be represented as "TEXT"s from C++14 */
			if (spec->fmt == ARG_FMT_STD_STRING)
				print_args("s");

			free(str);
			size = slen + 2;
		}
		else if (spec->fmt == ARG_FMT_CHAR) {
			char c;

			memcpy(&c, data, 1);
			if (needs_json) {
				print_args("'");
				print_json_escaped_char(c);
				print_args("'");
			}
			else {
				print_args("%s", color_string);
				print_args("'");
				print_escaped_char(c);
				print_args("'");
				print_args("%s", color_reset);
			}
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
				print_args(fmtstr, val.f);
				break;
			case 8:
				print_args(fmtstr, val.d);
				break;
			case 10:
				print_args(fmtstr, val.D);
				break;
			default:
				pr_dbg("invalid floating-point type size %d\n",
				       spec->size);
				break;
			}
		}
		else if (spec->fmt == ARG_FMT_PTR) {
			struct uftrace_session_link *sessions = &task->h->sessions;
			struct sym *sym;

			memcpy(val.v, data, spec->size);
			sym = task_find_sym_addr(sessions, task,
						 task->rstack->time,
						 (uint64_t)val.i);

			if (sym) {
				print_args("%s", color_symbol);
				print_args("&%s", sym->name);
				print_args("%s", color_reset);
			}
			else if (val.p)
				print_args("%p", val.p);
			else
				print_args("0");
		}
		else if (spec->fmt == ARG_FMT_ENUM) {
			struct uftrace_session_link *sessions = &task->h->sessions;
			struct uftrace_session *s;
			struct uftrace_mmap *map;
			struct debug_info *dinfo;
			char *estr;

			memcpy(val.v, data, spec->size);
			s = find_task_session(sessions, task->t,
					      task->rstack->time);

			map = find_map(&s->symtabs, task->rstack->addr);
			if (map == NULL || map->mod == NULL) {
				print_args("<ENUM?> %lx", val.i);
				goto next;
			}

			dinfo = &map->mod->dinfo;
			estr = get_enum_string(&dinfo->enums, spec->enum_str, val.i);
			if (strstr(estr, "|") && strcmp("|", color_enum_or)) {
				struct strv enum_vals = STRV_INIT;

				strv_split(&enum_vals, estr, "|");
				free(estr);
				estr = strv_join(&enum_vals, color_enum_or);
				strv_free(&enum_vals);
			}

			print_args("%s", color_enum);
			if (strlen(estr) >= len)
				print_args("<ENUM>");
			else
				print_args("%s", estr);
			print_args("%s", color_reset);
			free(estr);
		}
		else {
			if (spec->fmt != ARG_FMT_AUTO)
				memcpy(val.v, data, spec->size);

			assert(idx < ARRAY_SIZE(len_mod));
			lm = len_mod[idx];

			snprintf(fmtstr, sizeof(fmtstr), "%%#%s%c", lm, fmt);
			if (spec->size == 8)
				print_args(fmtstr, val.ll);
			else
				print_args(fmtstr, val.i);
		}

next:
		i++;
		data += ALIGN(size, 4);

		if (len <= 2)
			break;

		/* read only the first match for retval */
		if (is_retval)
			break;
	}

	if (needs_paren) {
		print_args("%s)%s", color_bold, color_reset);
	} else {
		if (needs_semi_colon)
			args[n++] = ';';
		args[n] = '\0';
	}
}

static int print_graph_rstack(struct uftrace_data *handle,
			      struct uftrace_task_reader *task,
			      struct opts *opts)
{
	struct uftrace_record *rstack;
	struct uftrace_session_link *sessions = &handle->sessions;
	struct sym *sym = NULL;
	enum argspec_string_bits str_mode = 0;
	char *symname = NULL;
	char args[1024];
	char *libname = "";
	struct uftrace_mmap *map = NULL;

	if (task == NULL)
		return 0;

	rstack = task->rstack;
	if (rstack->type == UFTRACE_LOST)
		goto lost;

	sym = task_find_sym(sessions, task, rstack);
	symname = symbol_getname(sym, rstack->addr);

	/* skip it if --no-libcall is given */
	if (!opts->libcall && sym && sym->type == ST_PLT_FUNC)
		goto out;

	if (rstack->type == UFTRACE_ENTRY) {
		if (symname[strlen(symname) - 1] != ')' || rstack->more)
			str_mode |= NEEDS_PAREN;
	}

	task->timestamp_last = task->timestamp;
	task->timestamp = rstack->time;

	if (opts->libname && sym && sym->type == ST_PLT_FUNC) {
		struct uftrace_session *s;

		s = find_task_session(sessions, task->t, rstack->time);
		if (s != NULL) {
			map = find_symbol_map(&s->symtabs, symname);
			if (map != NULL)
				libname = basename(map->libname);
		}
	}

	if (rstack->type == UFTRACE_ENTRY) {
		struct uftrace_task_reader *next = NULL;
		struct fstack *fstack;
		int rstack_depth = rstack->depth;
		int depth;
		struct uftrace_trigger tr = {
			.flags = 0,
		};
		int ret;

		ret = fstack_entry(task, rstack, &tr);
		if (ret < 0)
			goto out;

		/* display depth is set in fstack_entry() */
		depth = task->display_depth;

		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		if (tr.flags & TRIGGER_FL_BACKTRACE)
			print_backtrace(task);

		if (tr.flags & TRIGGER_FL_COLOR)
			task->event_color = tr.color;
		else
			task->event_color = DEFAULT_EVENT_COLOR;

		depth += task_column_depth(task, opts);

		if (rstack->more)
			str_mode |= HAS_MORE;
		get_argspec_string(task, args, sizeof(args), str_mode);

		fstack = &task->func_stack[task->stack_count - 1];

		if (!opts->no_merge)
			next = fstack_skip(handle, task, rstack_depth, opts);

		if (task == next &&
		    next->rstack->depth == rstack_depth &&
		    next->rstack->type == UFTRACE_EXIT) {
			char retval[1024];

			/* leaf function - also consume return record */
			fstack_consume(handle, next);

			str_mode = IS_RETVAL | NEEDS_SEMI_COLON;
			if (next->rstack->more) {
				str_mode |= HAS_MORE;
				str_mode |= NEEDS_ASSIGNMENT;
			}
			get_argspec_string(task, retval, sizeof(retval), str_mode);

			print_field(task, fstack, NULL);
			pr_out("%*s", depth * 2, "");
			if (tr.flags & TRIGGER_FL_COLOR) {
				pr_color(tr.color, "%s", symname);
				if (*libname)
					pr_color(tr.color, "@%s", libname);
				pr_out("%s%s\n", args, retval);
			}
			else {
				pr_out("%s%s%s%s%s\n", symname,
				       *libname ? "@" : "",
				       libname, args, retval);
			}

			/* fstack_update() is not needed here */

			fstack_exit(task);
		}
		else {
			/* function entry */
			print_field(task, fstack, NO_TIME);
			pr_out("%*s", depth * 2, "");
			if (tr.flags & TRIGGER_FL_COLOR) {
				pr_color(tr.color, "%s", symname);
				if (*libname)
					pr_color(tr.color, "@%s", libname);
				pr_out("%s {\n", args);
			}
			else {
				pr_out("%s%s%s%s {\n", symname,
				       *libname ? "@" : "", libname, args);
			}

			fstack_update(UFTRACE_ENTRY, task, fstack);
		}
	}
	else if (rstack->type == UFTRACE_EXIT) {
		struct fstack *fstack;

		/* function exit */
		fstack = &task->func_stack[task->stack_count];

		if (!(fstack->flags & FSTACK_FL_NORECORD) && fstack_enabled) {
			int depth = fstack_update(UFTRACE_EXIT, task, fstack);
			char *retval = args;

			depth += task_column_depth(task, opts);

			str_mode = IS_RETVAL;
			if (rstack->more) {
				str_mode |= HAS_MORE;
				str_mode |= NEEDS_ASSIGNMENT;
				str_mode |= NEEDS_SEMI_COLON;
			}
			get_argspec_string(task, retval, sizeof(args), str_mode);

			/* give a new line when tid is changed */
			if (opts->task_newline)
				print_task_newline(task->tid);

			print_field(task, fstack, NULL);
			pr_out("%*s}%s", depth * 2, "", retval);
			if (opts->comment)
				pr_gray(" /* %s%s%s */\n", symname,
					*libname ? "@" : "", libname);
			else
				pr_gray("\n");
		}

		fstack_exit(task);
	}
	else if (rstack->type == UFTRACE_LOST) {
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

		print_field(task, NULL, NO_TIME);

		if (losts > 0)
			pr_red("%*s/* LOST %d records!! */\n",
			       depth * 2, "", losts);
		else /* kernel sometimes have unknown count */
			pr_red("%*s/* LOST some records!! */\n",
			       depth * 2, "");
		return 0;
	}
	else if (rstack->type == UFTRACE_EVENT) {
		int depth;
		struct fstack *fstack;
		struct uftrace_task_reader *next = NULL;
		struct uftrace_record rec = *rstack;
		uint64_t evt_id = rstack->addr;

		depth = task->display_depth;

		if (!fstack_check_filter(task))
			goto out;

		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		depth += task_column_depth(task, opts);

		/*
		 * try to merge a subsequent sched-in event:
		 * it might overwrite rstack - use (saved) rec for printing.
		 */
		if (evt_id == EVENT_ID_PERF_SCHED_OUT && !opts->no_merge)
			next = fstack_skip(handle, task, 0, opts);

		if (task == next &&
		    next->rstack->addr == EVENT_ID_PERF_SCHED_IN) {
			/* consume the matching sched-in record */
			fstack_consume(handle, next);

			rec.addr = sched_sym.addr;
			evt_id = EVENT_ID_PERF_SCHED_IN;
		}

		/* show external data regardless of display depth */
		if (evt_id == EVENT_ID_EXTERN_DATA)
			depth = 0;

		/* for sched-in to show schedule duration */
		fstack = &task->func_stack[task->stack_count];

		if (!(fstack->flags & FSTACK_FL_NORECORD) && fstack_enabled) {
			if (evt_id == EVENT_ID_PERF_SCHED_IN &&
			    fstack->total_time)
				print_field(task, fstack, NULL);
			else
				print_field(task, NULL, NO_TIME);

			pr_color(task->event_color, "%*s/* ", depth * 2, "");
			print_event(task, &rec, task->event_color);
			pr_color(task->event_color, " */\n");
		}

	}
out:
	symbol_putname(sym, symname);
	return 0;
}

static void print_warning(struct uftrace_task_reader *task)
{
	if (print_empty_field(&output_fields, 1))
		pr_out(" | ");
	pr_red(" %*s/* inverted time: broken data? */\n",
	       (task->display_depth + 1) * 2, "");
}

static bool skip_sys_exit(struct opts *opts, struct uftrace_task_reader *task)
{
	uint64_t ip;
	struct sym *sym;

	if (task->func_stack == NULL)
		return true;

	/* skip 'sys_exit[_group] at last for kernel tracing */
	if (!has_kernel_data(task->h->kernel) || task->user_stack_count != 0)
		return false;

	ip = task->func_stack[0].addr;
	sym = find_symtabs(&task->h->sessions.first->symtabs, ip);
	if (sym == NULL)
		return false;

	/* Linux 4.17 added __x64_sys_exit, __ia32_sys_exit and so on */
	if (strstr(sym->name, "sys_exit"))
		return true;
	if (!strcmp(sym->name, "do_syscall_64"))
		return true;

	return false;
}

static void print_remaining_stack(struct opts *opts,
				  struct uftrace_data *handle)
{
	int i, k;
	int total = 0;
	struct uftrace_session_link *sessions = &handle->sessions;

	for (i = 0; i < handle->nr_tasks; i++) {
		struct uftrace_task_reader *task = &handle->tasks[i];
		int zero_count = 0;

		if (skip_sys_exit(opts, task))
			continue;

		for (k = 0; k < task->stack_count; k++) {
			if (task->func_stack[k].addr)
				break;
			zero_count++;
		}

		total += task->stack_count - zero_count;
	}

	if (total == 0)
		return;

	pr_out("\nuftrace stopped tracing with remaining functions");
	pr_out("\n================================================\n");

	for (i = 0; i < handle->nr_tasks; i++) {
		struct uftrace_task_reader *task = &handle->tasks[i];
		int zero_count = 0;

		if (task->stack_count == 0)
			continue;

		for (k = 0; k < task->stack_count; k++) {
			if (task->func_stack[k].addr)
				break;
			zero_count++;
		}

		if (zero_count == task->stack_count)
			continue;

		if (skip_sys_exit(opts, task))
			continue;

		pr_out("task: %d\n", task->tid);

		while (task->stack_count-- > 0) {
			struct fstack *fstack = &task->func_stack[task->stack_count];
			uint64_t time = fstack->total_time;
			uint64_t ip = fstack->addr;
			struct sym *sym;
			char *symname;

			sym = task_find_sym_addr(sessions, task, time, ip);
			symname = symbol_getname(sym, ip);

			pr_out("[%d] %s\n", task->stack_count - zero_count, symname);

			symbol_putname(sym, symname);

			if (task->stack_count == zero_count)
				break;
		}
		pr_out("\n");
	}
}

int command_replay(int argc, char *argv[], struct opts *opts)
{
	int ret;
	uint64_t prev_time = 0;
	struct uftrace_data handle;
	struct uftrace_task_reader *task;

	__fsetlocking(outfp, FSETLOCKING_BYCALLER);
	__fsetlocking(logfp, FSETLOCKING_BYCALLER);

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
		return -1;
	}

	if (handle.hdr.feat_mask & FLAT)
		flat_mode = true;

	fstack_setup_filters(opts, &handle);
	setup_field(&output_fields, opts, &setup_default_field,
		    field_table, ARRAY_SIZE(field_table));

	if (peek_rstack(&handle, &task) == 0)
		print_header(&output_fields, "#", "FUNCTION", 1);

	while (read_rstack(&handle, &task) == 0 && !uftrace_done) {
		struct uftrace_record *rstack = task->rstack;
		uint64_t curr_time = rstack->time;

		if (!fstack_check_opts(task, opts))
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

		if (flat_mode)
			ret = print_flat_rstack(&handle, task, opts);
		else
			ret = print_graph_rstack(&handle, task, opts);

		if (ret)
			break;
	}

	if (!flat_mode)
		print_remaining_stack(opts, &handle);

	close_data_file(opts, &handle);

	return ret;
}
