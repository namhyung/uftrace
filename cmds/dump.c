#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

#include "uftrace.h"
#include "utils/event.h"
#include "utils/filter.h"
#include "utils/fstack.h"
#include "utils/graph.h"
#include "utils/kernel-parser.h"
#include "utils/kernel.h"
#include "utils/list.h"
#include "utils/utils.h"
#include "version.h"

/* target sampling frequency for flame graph */
#define FLAME_GRAPH_SAMPLE_FREQ 1000000

/* this is to skip arguments and return value output */
static bool show_args;

struct uftrace_dump_ops {
	/* this is called at the beginning */
	void (*header)(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
		       struct uftrace_opts *opts);
	/* this is called when a task starts */
	void (*task_start)(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task);
	/* this is called when a record's time is before the previous */
	void (*inverted_time)(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task);
	/* this is called for each user-level function entry/exit */
	void (*task_rstack)(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task,
			    char *name);
	/* this is called for each user-level event */
	void (*task_event)(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task);
	/* this is called when kernel data starts */
	void (*kernel_start)(struct uftrace_dump_ops *ops, struct uftrace_kernel_reader *kernel);
	/* this is called when a cpu data start */
	void (*cpu_start)(struct uftrace_dump_ops *ops, struct uftrace_kernel_reader *kernel,
			  int cpu);
	/* this is called for each kernel-level function entry/exit */
	void (*kernel_func)(struct uftrace_dump_ops *ops, struct uftrace_kernel_reader *kernel,
			    int cpu, struct uftrace_record *frs, char *name);
	/* this is called for each kernel event (tracepoint) */
	void (*kernel_event)(struct uftrace_dump_ops *ops, struct uftrace_kernel_reader *kernel,
			     int cpu, struct uftrace_record *frs);
	/* this is called when there's a lost record (usually in kernel) */
	void (*lost)(struct uftrace_dump_ops *ops, uint64_t time, int tid, int losts);
	/* this is called when a perf data (for each cpu) starts */
	void (*perf_start)(struct uftrace_dump_ops *ops, struct uftrace_perf_reader *perf, int cpu);
	/* this is called for each perf event (except for schedule) */
	void (*perf_event)(struct uftrace_dump_ops *ops, struct uftrace_perf_reader *perf,
			   struct uftrace_record *frs);
	/* this is called at the end */
	void (*footer)(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
		       struct uftrace_opts *opts);
};

struct uftrace_raw_dump {
	struct uftrace_dump_ops ops;
	uint64_t file_offset;
	uint64_t kbuf_offset;
};

struct uftrace_chrome_dump {
	struct uftrace_dump_ops ops;
	unsigned lost_event_cnt;
	bool last_comma;
	struct uftrace_opts *opts;
};

struct uftrace_flame_dump {
	struct uftrace_dump_ops ops;
	struct rb_root tasks;
	struct fg_node *node;
	uint64_t sample_time;
};

struct uftrace_graphviz_dump {
	struct uftrace_dump_ops ops;
};

struct uftrace_mermaid_dump {
	struct uftrace_dump_ops ops;
};

static const char *rstack_type(struct uftrace_record *frs)
{
	return frs->type == UFTRACE_EXIT  ? "exit " :
	       frs->type == UFTRACE_ENTRY ? "entry" :
	       frs->type == UFTRACE_EVENT ? "event" :
					    "lost ";
}

static void pr_time(uint64_t timestamp)
{
	unsigned sec = timestamp / NSEC_PER_SEC;
	unsigned nsec = timestamp % NSEC_PER_SEC;

	pr_out("%u.%09u  ", sec, nsec);
}

static int pr_task(struct uftrace_opts *opts)
{
	FILE *fp;
	char buf[PATH_MAX];
	struct uftrace_msg msg;
	struct uftrace_msg_task tmsg;
	struct uftrace_msg_sess smsg;
	char *exename = NULL;

	snprintf(buf, sizeof(buf), "%s/task", opts->dirname);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return -1;

	while (fread(&msg, sizeof(msg), 1, fp) == 1) {
		if (msg.magic != UFTRACE_MSG_MAGIC) {
			pr_red("invalid message magic: %hx\n", msg.magic);
			goto out;
		}

		switch (msg.type) {
		case UFTRACE_MSG_TASK_START:
			if (fread(&tmsg, sizeof(tmsg), 1, fp) != 1) {
				pr_red("cannot read task message: %m\n");
				goto out;
			}

			pr_time(tmsg.time);
			pr_out("task tid %d (pid %d)\n", tmsg.tid, tmsg.pid);
			break;
		case UFTRACE_MSG_FORK_END:
			if (fread(&tmsg, sizeof(tmsg), 1, fp) != 1) {
				pr_red("cannot read task message: %m\n");
				goto out;
			}

			pr_time(tmsg.time);
			pr_out("fork pid %d (ppid %d)\n", tmsg.tid, tmsg.pid);
			break;
		case UFTRACE_MSG_SESSION:
			if (fread(&smsg, sizeof(smsg), 1, fp) != 1) {
				pr_red("cannot read session message: %m\n");
				goto out;
			}

			free(exename);
			exename = xmalloc(ALIGN(smsg.namelen, 8));
			if (fread(exename, ALIGN(smsg.namelen, 8), 1, fp) != 1) {
				pr_red("cannot read executable name: %m\n");
				goto out;
			}

			pr_time(smsg.task.time);
			pr_out("session of task %d: %.*s (%s)\n", smsg.task.tid, SESSION_ID_LEN,
			       smsg.sid, exename);
			break;
		default:
			pr_out("unknown message type: %u\n", msg.type);
			break;
		}
	}

out:
	free(exename);
	fclose(fp);
	return 0;
}

static int pr_task_txt(struct uftrace_opts *opts)
{
	FILE *fp;
	char buf[PATH_MAX];
	char *ptr, *end;
	char *timestamp;
	int pid, tid;
	char sid[20];

	snprintf(buf, sizeof(buf), "%s/task.txt", opts->dirname);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), fp)) {
		if (!strncmp(buf, "TASK", 4)) {
			ptr = strstr(buf, "timestamp=");
			if (ptr == NULL) {
				pr_red("invalid task timestamp\n");
				goto out;
			}
			timestamp = ptr + 10;

			end = strchr(ptr, ' ');
			if (end == NULL) {
				pr_red("invalid task timestamp\n");
				goto out;
			}
			*end++ = '\0';

			sscanf(end, "tid=%d pid=%d", &tid, &pid);

			pr_out("%s  task tid %d (pid %d)\n", timestamp, tid, pid);
		}
		else if (!strncmp(buf, "FORK", 4)) {
			ptr = strstr(buf, "timestamp=");
			if (ptr == NULL) {
				pr_red("invalid task timestamp\n");
				goto out;
			}
			timestamp = ptr + 10;

			end = strchr(ptr, ' ');
			if (end == NULL) {
				pr_red("invalid task timestamp\n");
				goto out;
			}
			*end++ = '\0';

			sscanf(end, "pid=%d ppid=%d", &tid, &pid);

			pr_out("%s  fork pid %d (ppid %d)\n", timestamp, tid, pid);
		}
		else if (!strncmp(buf, "SESS", 4)) {
			char *exename;

			ptr = strstr(buf, "timestamp=");
			if (ptr == NULL) {
				pr_red("invalid session timestamp\n");
				goto out;
			}
			timestamp = ptr + 10;

			end = strchr(ptr, ' ');
			if (end == NULL) {
				pr_red("invalid session timestamp\n");
				goto out;
			}
			*end++ = '\0';

			if (sscanf(end, "pid=%d sid=%s", &tid, sid) != 2)
				sscanf(end, "tid=%d sid=%s", &tid, sid);

			ptr = strstr(end, "exename=");
			if (ptr == NULL) {
				pr_red("invalid session exename\n");
				goto out;
			}
			exename = ptr + 8 + 1; // skip double-quote

			end = strrchr(ptr, '\"');
			if (end == NULL) {
				pr_red("invalid session exename\n");
				goto out;
			}
			*end++ = '\0';

			pr_out("%s  session of task %d: %.*s (%s)\n", timestamp, tid, 16, sid,
			       exename);
		}
	}

out:
	fclose(fp);
	return 0;
}

static void pr_hex(uint64_t *offset, void *data, size_t len)
{
	size_t i;
	unsigned char *h = data;
	uint64_t ofs = *offset;

	if (!debug)
		return;

	while (len >= 16) {
		pr_green(" <%016" PRIx64 ">:", ofs);
		pr_green(" %02x %02x %02x %02x %02x %02x %02x %02x "
			 " %02x %02x %02x %02x %02x %02x %02x %02x\n",
			 h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11],
			 h[12], h[13], h[14], h[15]);

		ofs += 16;
		len -= 16;
		h += 16;
	}

	if (len) {
		pr_green(" <%016" PRIx64 ">:", ofs);
		if (len > 8) {
			pr_green(" %02x %02x %02x %02x %02x %02x %02x %02x ", h[0], h[1], h[2],
				 h[3], h[4], h[5], h[6], h[7]);

			ofs += 8;
			len -= 8;
			h += 8;
		}

		for (i = 0; i < len; i++)
			pr_green(" %02x", *h++);
		pr_green("\n");

		ofs += len;
	}

	*offset = ofs;
}

static void pr_args(struct uftrace_fstack_args *args)
{
	struct uftrace_arg_spec *spec;
	struct uftrace_task_reader *task;
	struct uftrace_session_link *sessions;
	void *ptr = args->data;
	size_t size;
	int i = 0;

	task = container_of(args, typeof(*task), args);
	sessions = &task->h->sessions;

	list_for_each_entry(spec, args->args, list) {
		/* skip return value info */
		if (spec->idx == RETVAL_IDX)
			continue;

		if (spec->fmt == ARG_FMT_STR || spec->fmt == ARG_FMT_STD_STRING) {
			char *buf;
			const int null_str = -1;

			size = *(unsigned short *)ptr;
			buf = xmalloc(size + 1);
			strncpy(buf, ptr + 2, size);
			buf[size] = '\0';

			if (!memcmp(buf, &null_str, 4))
				strcpy(buf, "NULL");

			if (spec->fmt == ARG_FMT_STD_STRING)
				pr_out("  args[%d] std::string: %s\n", i, buf);
			else
				pr_out("  args[%d] str: %s\n", i, buf);

			free(buf);
			size += 2;
		}
		else if (spec->fmt == ARG_FMT_PTR) {
			struct uftrace_symbol *sym;
			unsigned long val = 0;

			memcpy(&val, ptr, spec->size);
			size = spec->size;

			sym = task_find_sym_addr(sessions, task, task->rstack->time, (uint64_t)val);

			if (sym)
				pr_out("  args[%d] p: %lx (&%s)\n", i, val, sym->name);
			else if (val)
				pr_out("  args[%d] p: %p\n", i, (void *)val);
			else
				pr_out("  args[%d] p: 0\n", i);
		}
		else if (spec->fmt == ARG_FMT_ENUM) {
			long long val = 0;
			struct uftrace_mmap *map;
			struct uftrace_session *s;
			struct uftrace_dbg_info *dinfo;
			char *enum_def;

			s = find_task_session(sessions, task->t, task->rstack->time);

			map = find_map(&s->sym_info, task->rstack->addr);
			if (!map || !map->mod)
				goto print_raw;

			dinfo = &map->mod->dinfo;
			memcpy(&val, ptr, spec->size);
			enum_def = get_enum_string(&dinfo->enums, spec->type_name, val);

			pr_out("  args[%d] enum %s: %s (%lld)\n", i, spec->type_name, enum_def,
			       val);

			free(enum_def);
			size = spec->size;
		}
		else if (spec->fmt == ARG_FMT_STRUCT) {
			int c;
			unsigned char *p = ptr;

			pr_out("  args[%d] struct %s:", i, spec->type_name ?: "");
			for (c = 0; c < spec->size; c++) {
				if ((c % 16) == 0)
					pr_out("\n\t");
				pr_out("%02x ", p[c]);
				if ((c % 8) == 7)
					pr_out(" ");
			}
			pr_out("\n");
			size = spec->size;
		}
		else {
			long long val = 0;
print_raw:
			memcpy(&val, ptr, spec->size);

			pr_out("  args[%d] %c%d: 0x%0*llx\n", i, ARG_SPEC_CHARS[spec->fmt],
			       spec->size * 8, spec->size * 2, val);

			size = spec->size;
		}

		ptr += ALIGN(size, 4);
		i++;
	}
}

static void pr_retval(struct uftrace_fstack_args *args)
{
	struct uftrace_arg_spec *spec;
	struct uftrace_task_reader *task;
	struct uftrace_session_link *sessions;
	void *ptr = args->data;
	size_t size;

	task = container_of(args, typeof(*task), args);
	sessions = &task->h->sessions;

	list_for_each_entry(spec, args->args, list) {
		/* skip argument info */
		if (spec->idx != RETVAL_IDX)
			continue;

		if (spec->fmt == ARG_FMT_STR || spec->fmt == ARG_FMT_STD_STRING) {
			char *buf;
			const int null_str = -1;

			size = *(unsigned short *)ptr;
			buf = xmalloc(size + 1);
			strncpy(buf, ptr + 2, size);
			buf[size] = '\0';

			if (!memcmp(buf, &null_str, 4))
				strcpy(buf, "NULL");

			if (spec->fmt == ARG_FMT_STD_STRING)
				pr_out("  retval std::string: %s\n", buf);
			else
				pr_out("  retval str: %s\n", buf);

			free(buf);
			size += 2;
		}
		else if (spec->fmt == ARG_FMT_PTR) {
			struct uftrace_symbol *sym;
			unsigned long val = 0;

			memcpy(&val, ptr, spec->size);
			size = spec->size;

			sym = task_find_sym_addr(sessions, task, task->rstack->time, (uint64_t)val);

			if (sym)
				pr_out("  retval p: %lx (&%s)\n", val, sym->name);
			else
				pr_out("  retval p: %p\n", (void *)val);
		}
		else if (spec->fmt == ARG_FMT_STRUCT) {
			int c;
			unsigned char *p = ptr;

			pr_out("  retval struct %s:", spec->type_name ?: "");
			for (c = 0; c < spec->size; c++) {
				if ((c % 16) == 0)
					pr_out("\n\t");
				pr_out("%02x ", p[c]);
				if ((c % 8) == 7)
					pr_out(" ");
			}
			pr_out("\n");
			size = spec->size;
		}
		else {
			long long val = 0;

			memcpy(&val, ptr, spec->size);
			pr_out("  retval %c%d: 0x%0*llx\n", ARG_SPEC_CHARS[spec->fmt],
			       spec->size * 8, spec->size * 2, val);

			size = spec->size;
		}

		ptr += ALIGN(size, 4);
	}
}

static void pr_event(struct uftrace_task_reader *task, unsigned evt_id)
{
	char *evt_name = event_get_name(task->h, evt_id);
	struct uftrace_symbol *sym = NULL;
	char *evt_data;

	if (evt_id == EVENT_ID_WATCH_VAR) {
		unsigned long long addr = 0;

		if (data_is_lp64(task->h))
			memcpy(&addr, task->args.data, 8);
		else
			memcpy(&addr, task->args.data, 4);

		sym = task_find_sym_addr(&task->h->sessions, task, task->ustack.time, addr);
	}
	evt_data = event_get_data_str(task->h, evt_id, task->args.data, task->args.len, sym, false);

	pr_out("  %s", evt_name);
	if (evt_data)
		pr_out(": %s", evt_data);
	pr_out("\n");

	free(evt_name);
	free(evt_data);
}

static void get_header_string(char *buf, size_t sz, uint64_t hdr_mask, const char **hdr_str,
			      int hdr_max)
{
	int i;
	size_t len;
	bool first = true;

	for (i = 0; i < hdr_max; i++) {
		if (!((1U << i) & hdr_mask))
			continue;

		len = snprintf(buf, sz, "%s%s", first ? "" : " | ", hdr_str[i]);
		buf += len;
		sz -= len;

		first = false;
	}
}

static void dump_raw_header(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
			    struct uftrace_opts *opts)
{
	int i;
	char buf[1024];
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);
	const char *feat_str[] = { "PLTHOOK",	 "TASK_SESSION", "KERNEL",     "ARGUMENT",
				   "RETVAL",	 "SYM_REL_ADDR", "MAX_STACK",  "EVENT",
				   "PERF_EVENT", "AUTO_ARGS",	 "DEBUG_INFO", "ESTIMATE_RETURN",
				   "SYM_SIZE" };
	const char *info_str[] = { "EXE_NAME",	   "EXE_BUILD_ID", "EXIT_STATUS", "CMDLINE",
				   "CPUINFO",	   "MEMINFO",	   "OSINFO",	  "TASKINFO",
				   "USAGEINFO",	   "LOADINFO",	   "ARG_SPEC",	  "RECORD_DATE",
				   "PATTERN_TYPE", "VERSION",	   "UTC_OFFSET" };

	pr_out("uftrace file header: magic         = ");
	for (i = 0; i < UFTRACE_MAGIC_LEN; i++)
		pr_out("%02x", handle->hdr.magic[i]);
	pr_out("\n");
	pr_out("uftrace file header: version       = %u\n", handle->hdr.version);
	pr_out("uftrace file header: header size   = %u\n", handle->hdr.header_size);
	pr_out("uftrace file header: endian        = %u (%s)\n", handle->hdr.endian,
	       handle->hdr.endian == 1 ? "little" : "big");
	pr_out("uftrace file header: class         = %u (%s bit)\n", handle->hdr.elf_class,
	       handle->hdr.elf_class == 2 ? "64" : "32");
	get_header_string(buf, sizeof(buf), handle->hdr.feat_mask, feat_str, FEAT_BIT_MAX);
	pr_out("uftrace file header: features      = %#" PRIx64 " (%s)\n", handle->hdr.feat_mask,
	       buf);
	get_header_string(buf, sizeof(buf), handle->hdr.info_mask, info_str, INFO_BIT_MAX);
	pr_out("uftrace file header: info          = %#" PRIx64 " (%s)\n", handle->hdr.info_mask,
	       buf);
	pr_hex(&raw->file_offset, &handle->hdr, handle->hdr.header_size);
	pr_out("\n");

	if (debug) {
		pr_out("%d tasks found\n", handle->info.nr_tid);

		/* try to read task.txt first */
		if (pr_task_txt(opts) < 0 && pr_task(opts) < 0)
			pr_red("cannot open task file\n");

		pr_out("\n");
	}
}

static void dump_raw_task_start(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	pr_out("reading %d.dat\n", task->tid);
	raw->file_offset = 0;

	setup_rstack_list(&task->rstack_list);
}

static void dump_raw_inverted_time(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task)
{
	pr_red("\n");
	pr_red("*************************************\n");
	pr_red("* inverted time - data seems broken *\n");
	pr_red("*************************************\n");
	pr_red("\n");
}

static void dump_raw_task_rstack(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task,
				 char *name)
{
	struct uftrace_record *frs = task->rstack;
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	if (frs->type == UFTRACE_EVENT)
		name = event_get_name(task->h, frs->addr);

	pr_time(frs->time);
	pr_out("%*d: [%s] %s(%" PRIx64 ") depth: %u\n", TASK_ID_LEN, task->tid, rstack_type(frs),
	       name, frs->addr, frs->depth);
	pr_hex(&raw->file_offset, frs, sizeof(*frs));

	if (frs->type == UFTRACE_EVENT)
		free(name);

	if (frs->more && show_args) {
		if (frs->type == UFTRACE_ENTRY) {
			pr_time(frs->time);
			pr_out("%*d: [%s] length = %d\n", TASK_ID_LEN, task->tid, "args ",
			       task->args.len);
			pr_args(&task->args);
			pr_hex(&raw->file_offset, task->args.data, ALIGN(task->args.len, 8));
		}
		else if (frs->type == UFTRACE_EXIT) {
			pr_time(frs->time);
			pr_out("%*d: [%s] length = %d\n", TASK_ID_LEN, task->tid, "retval",
			       task->args.len);
			pr_retval(&task->args);
			pr_hex(&raw->file_offset, task->args.data, ALIGN(task->args.len, 8));
		}
		else
			abort();
	}
}

static void dump_raw_task_event(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task)
{
	struct uftrace_record *frs = task->rstack;
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);
	char *name = event_get_name(task->h, frs->addr);

	pr_time(frs->time);
	pr_out("%*d: [%s] %s(%" PRIx64 ") depth: %u\n", TASK_ID_LEN, task->tid, rstack_type(frs),
	       name, frs->addr, frs->depth);
	pr_hex(&raw->file_offset, frs, sizeof(*frs));

	if (frs->more && show_args) {
		pr_time(frs->time);
		pr_out("%*d: [%s] length = %d\n", TASK_ID_LEN, task->tid, "data ", task->args.len);
		pr_event(task, frs->addr);
		pr_hex(&raw->file_offset, task->args.data, ALIGN(task->args.len, 8));
	}
	free(name);
}

static void dump_raw_kernel_start(struct uftrace_dump_ops *ops,
				  struct uftrace_kernel_reader *kernel)
{
	pr_out("\n");
}

static void dump_raw_cpu_start(struct uftrace_dump_ops *ops, struct uftrace_kernel_reader *kernel,
			       int cpu)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	pr_out("reading kernel-cpu%d.dat\n", cpu);

	raw->file_offset = 0;
	raw->kbuf_offset = __kparser_curr_offset(&kernel->parser, cpu);
}

/* internal kernel tracing ring buffer format for extended timestamp */
#define KERNEL_TRACING_TIME_EXTEND 30

static void dump_raw_kernel_rstack(struct uftrace_dump_ops *ops,
				   struct uftrace_kernel_reader *kernel, int cpu,
				   struct uftrace_record *frs, char *name)
{
	int tid = kernel->tids[cpu];
	struct uftrace_kernel_parser *kp = &kernel->parser;
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	/* check dummy 'time extend' record at the beginning */
	if (raw->kbuf_offset == 0x18) {
		uint64_t offset = 0x10;
		uint64_t timestamp = 0;
		void *data = __kparser_read_offset(kp, cpu, offset);
		unsigned char *tmp = data - 12; /* data still returns next record */

		if ((*tmp & 0x1f) == KERNEL_TRACING_TIME_EXTEND) {
			uint32_t upper, lower;
			int size;

			size = __kparser_event_size(kp, cpu);

			memcpy(&lower, tmp, 4);
			memcpy(&upper, tmp + 4, 4);
			timestamp = ((uint64_t)upper << 27) + (lower >> 5);

			pr_time(frs->time - timestamp);
			pr_out("%*d: [%s] %s (+%" PRIu64 " nsec)\n", TASK_ID_LEN, tid, "time ",
			       "extend", timestamp);

			if (debug)
				pr_hex(&offset, tmp, 8);
			else if (__kparser_next_event(kp, cpu))
				raw->kbuf_offset += size + 4; // 4 = event header size
			else
				raw->kbuf_offset = 0;
		}
	}

	pr_time(frs->time);
	pr_out("%*d: [%s] %s(%" PRIx64 ") depth: %u\n", TASK_ID_LEN, tid, rstack_type(frs), name,
	       frs->addr, frs->depth);

	if (debug) {
		/* this is only needed for hex dump */
		void *data = __kparser_read_offset(kp, cpu, raw->kbuf_offset);
		int size;

		size = __kparser_event_size(kp, cpu);
		raw->file_offset = __kparser_curr_offset(kp, cpu);
		pr_hex(&raw->file_offset, data - 4, size + 4);

		if (__kparser_next_event(kp, cpu))
			raw->kbuf_offset += size + 4; // 4 = event header size
		else
			raw->kbuf_offset = 0;
	}
}

static void dump_raw_kernel_event(struct uftrace_dump_ops *ops,
				  struct uftrace_kernel_reader *kernel, int cpu,
				  struct uftrace_record *frs)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);
	struct uftrace_kernel_parser *kp = &kernel->parser;
	int tid = kernel->tids[cpu];
	void *event;
	char *event_data;
	char buf[512];
	int size = 0;

	event = kparser_find_event(kp, frs->addr);
	if (!event)
		return;

	kparser_event_name(kp, event, buf, sizeof(buf));
	event_data = read_kernel_event(kernel, cpu, &size);

	pr_time(frs->time);
	pr_out("%*d: [%s] %s(%ld) %.*s\n", TASK_ID_LEN, tid, rstack_type(frs), buf, frs->addr, size,
	       event_data);

	if (debug) {
		/* this is only needed for hex dump */
		void *data = __kparser_read_offset(kp, cpu, raw->kbuf_offset);
		int size;

		size = __kparser_event_size(kp, cpu);
		raw->file_offset = __kparser_curr_offset(kp, cpu);
		pr_hex(&raw->file_offset, data - 4, size + 4);

		if (__kparser_next_event(kp, cpu))
			raw->kbuf_offset += size + 4; // 4 = event header size
		else
			raw->kbuf_offset = 0;
	}
}

static void dump_raw_kernel_lost(struct uftrace_dump_ops *ops, uint64_t time, int tid, int losts)
{
	pr_time(time);
	pr_red("%*d: [%s ]: %d events\n", TASK_ID_LEN, tid, "lost", losts);
}

static void dump_raw_perf_start(struct uftrace_dump_ops *ops, struct uftrace_perf_reader *perf,
				int cpu)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	if (cpu == 0)
		pr_out("\n");

	pr_out("reading perf-cpu%d.dat\n", cpu);

	raw->file_offset = 0;
}

static void dump_raw_perf_event(struct uftrace_dump_ops *ops, struct uftrace_perf_reader *perf,
				struct uftrace_record *frs)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);
	char *evt_name = event_get_name(NULL, frs->addr);

	pr_time(frs->time);
	pr_out("%*d: [%s] %s(%" PRIu64 ")\n", TASK_ID_LEN, perf->tid, rstack_type(frs), evt_name,
	       frs->addr);

	if (debug) {
		/* XXX: this is different from file contents */
		switch (frs->addr) {
		case EVENT_ID_PERF_SCHED_IN:
		case EVENT_ID_PERF_SCHED_OUT:
			pr_hex(&raw->file_offset, &perf->u.ctxsw, sizeof(perf->u.ctxsw));
			break;
		case EVENT_ID_PERF_TASK:
		case EVENT_ID_PERF_EXIT:
			pr_hex(&raw->file_offset, &perf->u.task, sizeof(perf->u.task));
			break;
		case EVENT_ID_PERF_COMM:
			pr_hex(&raw->file_offset, &perf->u.comm, sizeof(perf->u.comm));
			break;
		default:
			break;
		}
	}

	free(evt_name);
}

/* chrome support */
static void dump_chrome_header(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
			       struct uftrace_opts *opts)
{
	struct uftrace_chrome_dump *chrome = container_of(ops, typeof(*chrome), ops);
	struct uftrace_info *info = &handle->info;
	struct uftrace_task *task;
	int tid;
	int i;

	if (handle->hdr.feat_mask & PERF_EVENT)
		update_perf_task_comm(handle);

	pr_out("{\"traceEvents\":[\n");
	for (i = 0; i < info->nr_tid; i++) {
		tid = info->tids[i];
		task = find_task(&handle->sessions, tid);

		pr_out("{\"ts\":0,\"ph\":\"M\",\"pid\":%d,"
		       "\"name\":\"process_name\","
		       "\"args\":{\"name\":\"[%d] %s\"}},\n",
		       tid, tid, task->comm);
		pr_out("{\"ts\":0,\"ph\":\"M\",\"pid\":%d,"
		       "\"name\":\"thread_name\","
		       "\"args\":{\"name\":\"[%d] %s\"}},\n",
		       tid, tid, task->comm);
	}

	chrome->last_comma = false;
}

void print_json_escaped_char(char **args, size_t *len, const char c);

static void dump_chrome_task_rstack(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task,
				    char *name)
{
	char ph;
	char spec_buf[2048];
	char name_buf[2048];
	struct uftrace_record *frs = task->rstack;
	enum uftrace_argspec_string_bits str_mode = NEEDS_JSON;
	struct uftrace_chrome_dump *chrome = container_of(ops, typeof(*chrome), ops);
	bool is_process = task->t->pid == task->tid;
	int rec_type = frs->type;
	size_t namelen = strlen(name);
	char *p = name_buf;
	size_t len = sizeof(name_buf) - 1;
	size_t i;
	struct uftrace_dbg_loc *loc = NULL;

	if (chrome->opts && chrome->opts->srcline) {
		loc = task_find_loc_addr(&task->h->sessions, task, frs->time, frs->addr);
	}

	if (rec_type == UFTRACE_EVENT) {
		switch (frs->addr) {
		case EVENT_ID_PERF_SCHED_IN:
			/*
			 * new thread starts with a sched-in event
			 * which should be ignored
			 */
			if (task->timestamp_last == 0)
				return;
			rec_type = UFTRACE_EXIT;
			break;
		case EVENT_ID_PERF_SCHED_OUT:
			rec_type = UFTRACE_ENTRY;
			break;
		default:
			return;
		}
	}

	/* escape the function name */
	for (i = 0; i < namelen; i++)
		print_json_escaped_char(&p, &len, name[i]);
	*p = '\0';

	if (chrome->last_comma)
		pr_out(",\n");
	chrome->last_comma = true;

	if (rec_type == UFTRACE_ENTRY) {
		ph = 'B';
		if (is_process) {
			/* no need to add "tid" field */
			pr_out("{\"ts\":%" PRIu64 ".%03d,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
			       frs->time / 1000, (int)(frs->time % 1000), ph, task->tid, name_buf);
		}
		else {
			pr_out("{\"ts\":%" PRIu64
			       ".%03d,\"ph\":\"%c\",\"pid\":%d,\"tid\":%d,\"name\":\"%s\"",
			       frs->time / 1000, (int)(frs->time % 1000), ph, task->t->pid,
			       task->tid, name_buf);
		}

		if ((loc != NULL) || (frs->more && show_args)) {
			pr_out(",\"args\":{");

			if ((loc != NULL)) {
				pr_out("\"srcline\":\"%s:%d\"", loc->file->name, loc->line);
				if ((frs->more && show_args))
					pr_out(",");
			}

			if ((frs->more && show_args)) {
				str_mode |= NEEDS_PAREN | HAS_MORE;
				get_argspec_string(task, spec_buf, sizeof(spec_buf), str_mode);
				pr_out("\"arguments\":\"%s\"", spec_buf);
			}

			pr_out("}}");
		}
		else {
			pr_out("}");
		}
	}
	else if (rec_type == UFTRACE_EXIT) {
		ph = 'E';
		if (is_process) {
			/* no need to add "tid" field */
			pr_out("{\"ts\":%" PRIu64 ".%03d,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
			       frs->time / 1000, (int)(frs->time % 1000), ph, task->tid, name_buf);
		}
		else {
			pr_out("{\"ts\":%" PRIu64
			       ".%03d,\"ph\":\"%c\",\"pid\":%d,\"tid\":%d,\"name\":\"%s\"",
			       frs->time / 1000, (int)(frs->time % 1000), ph, task->t->pid,
			       task->tid, name_buf);
		}

		if ((loc != NULL) || (frs->more && show_args)) {
			pr_out(",\"args\":{");

			if ((loc != NULL)) {
				pr_out("\"srcline\":\"%s:%d\"", loc->file->name, loc->line);
				if ((frs->more && show_args))
					pr_out(",");
			}

			if ((frs->more && show_args)) {
				str_mode |= IS_RETVAL | HAS_MORE;
				get_argspec_string(task, spec_buf, sizeof(spec_buf), str_mode);
				pr_out("\"retval\":\"%s\"", spec_buf);
			}

			pr_out("}}");
		}
		else {
			pr_out("}");
		}
	}
	else if (rec_type == UFTRACE_LOST)
		chrome->lost_event_cnt++;
}

static void dump_chrome_kernel_rstack(struct uftrace_dump_ops *ops,
				      struct uftrace_kernel_reader *kernel, int cpu,
				      struct uftrace_record *rec, char *name)
{
	int tid;
	struct uftrace_task_reader *task;

	tid = kernel->tids[cpu];
	task = get_task_handle(kernel->handle, tid);
	if (task == NULL)
		return;

	dump_chrome_task_rstack(ops, task, name);
}

static void dump_chrome_perf_event(struct uftrace_dump_ops *ops, struct uftrace_perf_reader *perf,
				   struct uftrace_record *frs)
{
	uint64_t evt_id = frs->addr;
	bool is_process = perf->u.comm.pid == perf->tid;

	switch (evt_id) {
	case EVENT_ID_PERF_COMM:
		if (is_process) {
			pr_out(",\n{\"ts\":0,\"ph\":\"M\",\"pid\":%d,"
			       "\"name\":\"process_name\","
			       "\"args\":{\"name\":\"%s\"}}",
			       perf->tid, perf->u.comm.comm);
			pr_out(",\n{\"ts\":0,\"ph\":\"M\",\"pid\":%d,"
			       "\"name\":\"thread_name\","
			       "\"args\":{\"name\":\"%s\"}}",
			       perf->tid, perf->u.comm.comm);
		}
		else {
			pr_out(",\n{\"ts\":0,\"ph\":\"M\",\"pid\":%d,\"tid\":%d,"
			       "\"name\":\"thread_name\","
			       "\"args\":{\"name\":\"[%d] %s\"}}",
			       perf->u.comm.pid, perf->tid, perf->tid, perf->u.comm.comm);
		}
		break;
	default:
		break;
	};
}

static void dump_chrome_footer(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
			       struct uftrace_opts *opts)
{
	char buf[PATH_MAX];
	struct stat statbuf;
	struct uftrace_chrome_dump *chrome = container_of(ops, typeof(*chrome), ops);

	/* read recorded date and time */
	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);
	if (stat(buf, &statbuf) < 0)
		return;

	ctime_r(&statbuf.st_mtime, buf);
	buf[strlen(buf) - 1] = '\0';

	pr_out("\n], \"displayTimeUnit\": \"ns\", \"metadata\": {\n");
	pr_out("\"version\":\"uftrace %s\",\n", UFTRACE_VERSION);
	pr_out("\"recorded_time\":\"%s\",\n", buf);
	if (handle->hdr.info_mask & CMDLINE)
		pr_out("\"command_line\":\"%s\"\n", handle->info.cmdline);
	pr_out("} }\n");

	/*
	 * Chrome trace format requires to have both entry and exit records so
	 * that it can identify the range of function call and return.
	 * However, if there are some lost records, it cannot match the entry
	 * and exit of some functions.  It may show some of functions do not
	 * return until the program is finished or vice versa.
	 *
	 * Since it's very difficult to generate fake records for lost data to
	 * match entry and exit of some lost functions, we just inform the fact
	 * to users as of now.
	 */
	if (chrome->lost_event_cnt) {
		pr_warn("Some of function trace records are lost. "
			"(%d times shown)\n",
			chrome->lost_event_cnt);
		pr_warn("The output json format may not show the correct view "
			"in chrome browser.\n");
	}
}

/* flamegraph support */
static struct uftrace_graph flame_graph = {
	.root.head = LIST_HEAD_INIT(flame_graph.root.head),
	.special_nodes = LIST_HEAD_INIT(flame_graph.special_nodes),
};

static void adjust_fg_time(struct uftrace_task_graph *tg, void *arg)
{
	struct uftrace_dump_ops *ops = arg;
	struct uftrace_flame_dump *flame = container_of(ops, typeof(*flame), ops);
	struct uftrace_graph_node *node = tg->node;
	struct uftrace_fstack *fstack;
	uint64_t curr_time;
	uint64_t sample_time;
	uint64_t accounted_time;

	if (flame->sample_time == 0)
		return;

	if (tg->node->parent == NULL)
		return;

	fstack = fstack_get(tg->task, tg->task->stack_count);
	if (fstack == NULL)
		return;

	curr_time = fstack->total_time;
	sample_time = flame->sample_time;

	/*
	 * it needs to track the child time separately
	 * since child time not accounted due to sample time
	 * should be accounted to parent.
	 *
	 * For example, with 1us sample time:
	 *
	 * # DURATION    TID     FUNCTION
	 *             [12345] | main() {
	 *    4.789 us [12345] |   foo();
	 *    4.987 us [12345] |   bar();
	 *   10.567 us [12345] | } // main
	 *
	 * In this case, main's total time is more than 10us
	 * so 10 samples should be shown, but after accounting
	 * foo and bar (4 samples each), its time would be
	 * 10.567 - 4.789 - 4.987 = 0.791 so no samples for main.
	 * But it actually needs to get 2 samples.
	 *
	 * So add the accounted child time only, not real time.
	 */
	accounted_time = (curr_time / sample_time) * sample_time;

	node->parent->child_time -= curr_time;
	node->parent->child_time += accounted_time;
}

static void print_flame_graph(struct uftrace_dump_ops *ops, struct uftrace_graph_node *node,
			      struct uftrace_opts *opts)
{
	struct uftrace_graph_node *child;
	struct uftrace_flame_dump *flame = container_of(ops, typeof(*flame), ops);
	unsigned long sample = node->nr_calls;

	if (sample && flame->sample_time)
		sample = (node->time - node->child_time) / flame->sample_time;

	if (sample) {
		struct uftrace_graph_node *parent = node;
		char *names[opts->max_stack];
		char *buf, *ptr;
		int i = 0;
		size_t len = 0;

		while (parent != NULL && parent->name != NULL) {
			names[i++] = parent->name;
			len += strlen(parent->name) + 1;
			parent = parent->parent;
		}

		buf = ptr = xmalloc(len + 32);
		while (--i >= 0)
			ptr += snprintf(ptr, len, "%s;", names[i]);
		ptr[-1] = ' ';
		snprintf(ptr, len, "%lu", sample);

		pr_out("%s\n", buf);
		free(buf);
	}

	list_for_each_entry(child, &node->head, list)
		print_flame_graph(ops, child, opts);
}

static void dump_flame_header(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
			      struct uftrace_opts *opts)
{
	graph_init_callbacks(NULL, adjust_fg_time, NULL, ops);
}

static void dump_flame_task_rstack(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task,
				   char *name)
{
	struct uftrace_record *frs = task->rstack;
	struct uftrace_task_graph *graph;

	graph = graph_get_task(task, sizeof(*graph));

	graph->graph = &flame_graph;
	flame_graph.sess = find_task_session(&task->h->sessions, task->t, frs->time);

	if (graph->node == NULL)
		graph->node = &flame_graph.root;

	graph_add_node(graph, frs->type, name, sizeof(struct uftrace_graph_node), NULL);
}

static void dump_flame_kernel_rstack(struct uftrace_dump_ops *ops,
				     struct uftrace_kernel_reader *kernel, int cpu,
				     struct uftrace_record *rec, char *name)
{
	int tid;
	struct uftrace_task_reader *task;
	struct uftrace_task_graph *graph;

	tid = kernel->tids[cpu];
	task = get_task_handle(kernel->handle, tid);
	if (task == NULL)
		return;

	graph = graph_get_task(task, sizeof(*graph));

	graph->graph = &flame_graph;
	flame_graph.sess = kernel->handle->sessions.first;

	if (graph->node == NULL)
		graph->node = &flame_graph.root;

	graph_add_node(graph, rec->type, name, sizeof(struct uftrace_graph_node), NULL);
}

static void dump_flame_footer(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
			      struct uftrace_opts *opts)
{
	print_flame_graph(ops, &flame_graph.root, opts);

	graph_destroy(&flame_graph);
	graph_remove_task();
}

/* graphviz support */
static struct uftrace_graph graphviz_graph = {
	.root.head = LIST_HEAD_INIT(graphviz_graph.root.head),
	.special_nodes = LIST_HEAD_INIT(graphviz_graph.special_nodes),
};

static void dump_graphviz_header(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
				 struct uftrace_opts *opts)
{
	char *exename = (char *)uftrace_basename(handle->info.exename);

	graphviz_graph.root.name = exename;
	pr_out("# version\":\"uftrace %s\"\n", UFTRACE_VERSION);

	if (handle->hdr.info_mask & CMDLINE)
		pr_out("# command_line \"%s\"\n", handle->info.cmdline);

	pr_out("\ndigraph ");
	pr_out("\"%s\"", exename);
	pr_out(" { \n");

	graph_init_callbacks(NULL, NULL, NULL, ops);
}

static void dump_graphviz_task_rstack(struct uftrace_dump_ops *ops,
				      struct uftrace_task_reader *task, char *name)
{
	struct uftrace_record *frs = task->rstack;
	struct uftrace_task_graph *graph;

	graph = graph_get_task(task, sizeof(*graph));

	graph->graph = &graphviz_graph;
	graphviz_graph.sess = find_task_session(&task->h->sessions, task->t, frs->time);
	if (graph->node == NULL)
		graph->node = &graphviz_graph.root;

	graph_add_node(graph, frs->type, name, sizeof(struct uftrace_graph_node), NULL);
}

static void dump_graphviz_kernel_rstack(struct uftrace_dump_ops *ops,
					struct uftrace_kernel_reader *kernel, int cpu,
					struct uftrace_record *rec, char *name)
{
	int tid;
	struct uftrace_task_reader *task;
	struct uftrace_task_graph *graph;

	tid = kernel->tids[cpu];
	task = get_task_handle(kernel->handle, tid);
	if (task == NULL)
		return;

	graph = graph_get_task(task, sizeof(*graph));

	graph->graph = &graphviz_graph;
	graphviz_graph.sess = kernel->handle->sessions.first;

	if (graph->node == NULL)
		graph->node = &graphviz_graph.root;

	graph_add_node(graph, rec->type, name, sizeof(struct uftrace_graph_node), NULL);
}

static void print_graph_to_graphviz(struct uftrace_graph_node *node, struct uftrace_opts *opts)
{
	struct uftrace_graph_node *child;
	unsigned long n_calls = node->nr_calls;

	if (n_calls) {
		struct uftrace_graph_node *parent = node->parent;

		pr_out("    ");
		if (parent != NULL && parent->name != NULL) {
			pr_out("\"%s\" -> ", parent->name);
		}
		pr_out("\"%s\"", node->name);

		// Edge Attributes
		pr_out(" [xlabel = \"%lu\"]\n", n_calls);
	}

	list_for_each_entry(child, &node->head, list)
		print_graph_to_graphviz(child, opts);
}

static void dump_graphviz_footer(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
				 struct uftrace_opts *opts)
{
	print_graph_to_graphviz(&graphviz_graph.root, opts);
	pr_out("}\n");

	graph_destroy(&graphviz_graph);
	graph_remove_task();
}

/* mermaid support */
static struct uftrace_graph mermaid_graph = {
	.root.head = LIST_HEAD_INIT(mermaid_graph.root.head),
	.special_nodes = LIST_HEAD_INIT(mermaid_graph.special_nodes),
};

static void dump_mermaid_task_rstack(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task,
				     char *name)
{
	struct uftrace_record *frs = task->rstack;
	struct uftrace_task_graph *graph;

	graph = graph_get_task(task, sizeof(*graph));

	graph->graph = &mermaid_graph;
	mermaid_graph.sess = find_task_session(&task->h->sessions, task->t, frs->time);
	if (graph->node == NULL)
		graph->node = &mermaid_graph.root;

	graph_add_node(graph, frs->type, name, sizeof(struct uftrace_graph_node), NULL);
}

static void dump_mermaid_kernel_rstack(struct uftrace_dump_ops *ops,
				       struct uftrace_kernel_reader *kernel, int cpu,
				       struct uftrace_record *rec, char *name)
{
	int tid;
	struct uftrace_task_reader *task;
	struct uftrace_task_graph *graph;

	tid = kernel->tids[cpu];
	task = get_task_handle(kernel->handle, tid);
	if (task == NULL)
		return;

	graph = graph_get_task(task, sizeof(*graph));

	graph->graph = &mermaid_graph;
	mermaid_graph.sess = kernel->handle->sessions.first;

	if (graph->node == NULL)
		graph->node = &mermaid_graph.root;

	graph_add_node(graph, rec->type, name, sizeof(struct uftrace_graph_node), NULL);
}

static void dump_mermaid_header(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
				struct uftrace_opts *opts)
{
	graph_init_callbacks(NULL, NULL, NULL, ops);
	mermaid_graph.root.name = (char *)uftrace_basename(handle->info.exename);

	pr_out("<html>\n");
	pr_out("<body>\n");
}

static void print_graph_node_mermaid(struct uftrace_graph *graph, struct uftrace_graph_node *node)
{
	char *symname = node->name;
	struct uftrace_graph_node *child;
	static int depth = -1;
	depth++;
	list_for_each_entry(child, &node->head, list) {
		pr_out("  %d_%d[\"%s\"] -->|%d| %d_%d[\"%s\"];\n", depth, node->id, symname,
		       child->nr_calls, depth + 1, child->id, child->name);
		print_graph_node_mermaid(graph, child);
	}
	if (list_no_entry(child, &node->head, list)) {
		depth--;
	}
}

static void dump_mermaid_footer(struct uftrace_dump_ops *ops, struct uftrace_data *handle,
				struct uftrace_opts *opts)
{
	const char *interactive_option_html;
	const char *interactive_option_js;

	/* skip empty graph */
	if (mermaid_graph.root.time == 0 && mermaid_graph.root.nr_edges == 0)
		return;

	pr_out("<h2>Function Call Graph for <span style=\"color:blue\" id=\"baseName\">%s</span>",
	       mermaid_graph.root.name);
	pr_out("</h2>\n");

	interactive_option_html =
#include "utils/mermaid.html.cstr" /* This file is converted from mermaid.html at build-time */
		;

	pr_out("%s", interactive_option_html);

	pr_out("<div class=\"mermaid\" id=\"meraid_graph\">\n");
	pr_out("flowchart TB\n");
	print_graph_node_mermaid(&mermaid_graph, &mermaid_graph.root);
	pr_out("</div>\n");
	pr_out("<script src=\"https://cdn.jsdelivr.net/npm/mermaid@9/dist/mermaid.min.js\"></script>\n");
	pr_out("<script>\n");
	pr_out("var config = {\n");
	pr_out("	startOnLoad: true,\n");
	pr_out("	maxTextSize: 99999999,\n");
	pr_out("	flowchart: { useMaxWidth: false, curve : \'basis\', htmlLabels: \'false\'},\n");
	pr_out("	securityLevel:\'loose\'\n");
	pr_out("};\n");
	pr_out("mermaid.initialize(config);\n");

	interactive_option_js =
#include "utils/mermaid.js.cstr" /* This file is converted from mermaid.js at build-time */
		;

	pr_out("%s", interactive_option_js);

	pr_out("</script>\n");
	pr_out("</body>\n");
	pr_out("</html>\n");
}

static void do_dump_file(struct uftrace_dump_ops *ops, struct uftrace_opts *opts,
			 struct uftrace_data *handle)
{
	int i;
	uint64_t prev_time;
	struct uftrace_task_reader *task;
	struct uftrace_session_link *sessions = &handle->sessions;

	call_if_nonull(ops->header, ops, handle, opts);

	for (i = 0; i < handle->info.nr_tid; i++) {
		if (opts->kernel && opts->kernel_only)
			continue;

		task = &handle->tasks[i];
		task->rstack = &task->ustack;

		prev_time = 0;

		call_if_nonull(ops->task_start, ops, task);

		while (!read_task_ustack(handle, task) && !uftrace_done) {
			struct uftrace_record *frs = &task->ustack;
			struct uftrace_symbol *sym;
			char *name;

			if (frs->more) {
				add_to_rstack_list(&task->rstack_list, frs, &task->args);
			}

			/* consume the rstack as it didn't call read_rstack() */
			fstack_consume(handle, task);

			if (!check_time_range(&handle->time_range, frs->time))
				continue;

			if (prev_time > frs->time)
				call_if_nonull(ops->inverted_time, ops, task);
			prev_time = frs->time;

			if (!fstack_check_filter(task))
				continue;

			if (frs->type == UFTRACE_EVENT) {
				if (!opts->no_event)
					call_if_nonull(ops->task_event, ops, task);
				continue;
			}

			sym = task_find_sym(sessions, task, frs);

			/* skip it if --no-libcall is given */
			if (!opts->libcall && sym && sym->type == ST_PLT_FUNC) {
				fstack_check_filter_done(task);
				continue;
			}

			name = symbol_getname(sym, frs->addr);
			call_if_nonull(ops->task_rstack, ops, task, name);
			symbol_putname(sym, name);

			fstack_check_filter_done(task);
		}
	}

	if (!has_kernel_data(handle->kernel) || uftrace_done)
		goto perf;

	call_if_nonull(ops->kernel_start, ops, handle->kernel);

	for (i = 0; i < handle->kernel->nr_cpus; i++) {
		struct uftrace_kernel_reader *kernel = handle->kernel;
		struct uftrace_record *frs = &kernel->rstacks[i];
		struct uftrace_session *fsess = handle->sessions.first;

		if (kparser_data_size(&kernel->parser, i) == 0)
			continue;

		call_if_nonull(ops->cpu_start, ops, kernel, i);

		while (!read_kernel_cpu_data(kernel, i) && !uftrace_done) {
			int tid = kernel->tids[i];
			int losts = kparser_missed_events(&kernel->parser, i);
			struct uftrace_symbol *sym = NULL;
			char *name;
			uint64_t addr;

			if (losts) {
				call_if_nonull(ops->lost, ops, frs->time, tid, losts);
				kparser_clear_missed(&kernel->parser, i);
			}

			if (!check_time_range(&handle->time_range, frs->time))
				continue;

			if (frs->type == UFTRACE_EVENT) {
				if (!opts->no_event)
					call_if_nonull(ops->kernel_event, ops, kernel, i, frs);
				continue;
			}

			addr = get_kernel_address(&fsess->sym_info, frs->addr);
			sym = find_symtabs(&fsess->sym_info, addr);
			name = symbol_getname(sym, addr);

			call_if_nonull(ops->kernel_func, ops, kernel, i, frs, name);

			symbol_putname(sym, name);
		}
	}

perf:
	if (opts->no_event || !has_perf_data(handle) || uftrace_done)
		goto footer;

	for (i = 0; i < handle->nr_perf; i++) {
		struct uftrace_perf_reader *perf = &handle->perf[i];
		struct stat statbuf;

		if (fstat(fileno(perf->fp), &statbuf) < 0)
			continue;
		if (statbuf.st_size == 0)
			continue;

		call_if_nonull(ops->perf_start, ops, perf, i);

		while (!uftrace_done) {
			struct uftrace_record *rec;

			/* for re-read perf data from file */
			perf->valid = false;

			rec = get_perf_record(handle, perf);
			if (rec == NULL)
				break;

			if (opts->no_sched && is_sched_event(rec->addr))
				continue;

			call_if_nonull(ops->perf_event, ops, perf, rec);
		}
	}

footer:
	call_if_nonull(ops->footer, ops, handle, opts);
}

static bool check_task_rstack(struct uftrace_task_reader *task, struct uftrace_opts *opts)
{
	struct uftrace_record *frs = task->rstack;

	if (!fstack_check_opts(task, opts))
		return false;

	if (!check_time_range(&task->h->time_range, frs->time))
		return false;

	if (!fstack_check_filter(task))
		return false;

	return true;
}

static void dump_replay_func(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task,
			     struct uftrace_opts *opts)
{
	struct uftrace_record *rec = task->rstack;
	struct uftrace_session_link *sessions = &task->h->sessions;
	struct uftrace_symbol *sym;
	char *name;

	sym = task_find_sym(sessions, task, rec);

	/* skip it if --no-libcall is given */
	if (!opts->libcall && sym && sym->type == ST_PLT_FUNC)
		return;

	name = symbol_getname(sym, rec->addr);
	if (is_kernel_record(task, rec)) {
		struct uftrace_kernel_reader *kernel = task->h->kernel;

		call_if_nonull(ops->kernel_func, ops, kernel, kernel->last_read_cpu, rec, name);
	}
	else {
		call_if_nonull(ops->task_rstack, ops, task, name);
	}
	symbol_putname(sym, name);
}

static void dump_replay_event(struct uftrace_dump_ops *ops, struct uftrace_task_reader *task)
{
	struct uftrace_record *rec = task->rstack;

	/* handle schedule events as if functions */
	if (rec->addr == EVENT_ID_PERF_SCHED_IN || rec->addr == EVENT_ID_PERF_SCHED_OUT) {
		call_if_nonull(ops->task_rstack, ops, task, "linux:schedule");
		return;
	}

	if (is_user_record(task, rec)) {
		call_if_nonull(ops->task_event, ops, task);
	}
	else if (is_kernel_record(task, rec)) {
		struct uftrace_kernel_reader *kernel = task->h->kernel;

		call_if_nonull(ops->kernel_event, ops, kernel, kernel->last_read_cpu, rec);
	}
	else if (is_event_record(task, rec)) {
		struct uftrace_perf_reader perf = {
			.tid = task->tid,
			.time = rec->time,
		};

		if (rec->addr == EVENT_ID_PERF_COMM) {
			strncpy(perf.u.comm.comm, task->args.data, TASK_COMM_LAST);
			perf.u.comm.comm[TASK_COMM_LAST] = '\0';
			perf.u.comm.pid = task->t->pid;
		}

		call_if_nonull(ops->perf_event, ops, &perf, rec);
	}
	else if (is_extern_record(task, rec)) {
		call_if_nonull(ops->task_event, ops, task);
	}
	else {
		struct uftrace_perf_reader *perf;

		ASSERT(task->h->last_perf_idx >= 0);
		perf = &task->h->perf[task->h->last_perf_idx];

		call_if_nonull(ops->perf_event, ops, perf, rec);
	}
}

static void do_dump_replay(struct uftrace_dump_ops *ops, struct uftrace_opts *opts,
			   struct uftrace_data *handle)
{
	uint64_t prev_time = 0;
	struct uftrace_task_reader *task;
	int i;

	ops->header(ops, handle, opts);

	while (!read_rstack(handle, &task) && !uftrace_done) {
		struct uftrace_record *frs = task->rstack;

		task->timestamp_last = frs->time;

		if (!check_task_rstack(task, opts))
			continue;

		if (prev_time > frs->time)
			call_if_nonull(ops->inverted_time, ops, task);
		prev_time = frs->time;

		if (task->rstack->type == UFTRACE_EVENT)
			dump_replay_event(ops, task);
		else
			dump_replay_func(ops, task, opts);

		fstack_check_filter_done(task);
	}

	/* add duration of remaining functions */
	for (i = 0; i < handle->nr_tasks; i++) {
		uint64_t last_time;

		task = &handle->tasks[i];

		if (task->stack_count == 0)
			continue;

		last_time = task->timestamp_last;

		if (handle->time_range.stop && handle->time_range.stop < last_time)
			last_time = handle->time_range.stop;

		while (--task->stack_count >= 0) {
			struct uftrace_fstack *fstack;
			struct uftrace_session *fsess = handle->sessions.first;

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

			/* make sure is_kernel_record() working correctly */
			if (is_kernel_address(&fsess->sym_info, fstack->addr))
				task->rstack = &task->kstack;
			else
				task->rstack = &task->ustack;

			task->rstack->time = last_time;
			task->rstack->type = UFTRACE_EXIT;
			task->rstack->addr = fstack->addr;
			task->rstack->more = 0;

			if (!check_task_rstack(task, opts))
				continue;

			if (task->rstack->type == UFTRACE_EVENT)
				dump_replay_event(ops, task);
			else
				dump_replay_func(ops, task, opts);

			fstack_check_filter_done(task);
		}
	}

	ops->footer(ops, handle, opts);
}

int command_dump(int argc, char *argv[], struct uftrace_opts *opts)
{
	int ret;
	struct uftrace_data handle;

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
		return -1;
	}

	fstack_setup_filters(opts, &handle);

	if (opts->show_args)
		show_args = true;

	if (opts->chrome_trace) {
		struct uftrace_chrome_dump dump = {
			.ops = {
				.header         = dump_chrome_header,
				.task_rstack    = dump_chrome_task_rstack,
				.kernel_func    = dump_chrome_kernel_rstack,
				.perf_event     = dump_chrome_perf_event,
				.footer         = dump_chrome_footer,
			},
			.opts = opts,
		};

		do_dump_replay(&dump.ops, opts, &handle);
	}
	else if (opts->flame_graph) {
		struct uftrace_flame_dump dump = {
			.ops = {
				.header         = dump_flame_header,
				.task_rstack    = dump_flame_task_rstack,
				.kernel_func    = dump_flame_kernel_rstack,
				.footer         = dump_flame_footer,
			},
			.tasks = RB_ROOT,
			.sample_time = opts->sample_time,
		};

		if (!opts->sample_time && handle.hdr.info_mask & RECORD_DATE) {
			uint64_t total_time, sample_time;

			/* elapsed time is saved in second */
			total_time = strtod(handle.info.elapsed_time, NULL) * 1e9;

			/* start from 1 usec and increase it for the target freq */
			for (sample_time = 1000; sample_time * FLAME_GRAPH_SAMPLE_FREQ < total_time;
			     sample_time *= 10) {
				/* max sample time is 1 sec */
				if (sample_time == 1000000000)
					break;
			}

			dump.sample_time = sample_time;
		}
		do_dump_replay(&dump.ops, opts, &handle);
	}
	else if (opts->graphviz) {
		struct uftrace_graphviz_dump dump = {
			.ops = {
				.header         = dump_graphviz_header,
				.task_rstack    = dump_graphviz_task_rstack,
				.kernel_func    = dump_graphviz_kernel_rstack,
				.footer         = dump_graphviz_footer,
			},
		};

		do_dump_replay(&dump.ops, opts, &handle);
	}
	else if (opts->mermaid) {
		struct uftrace_mermaid_dump dump = {
			.ops = {
				.header         = dump_mermaid_header,
				.task_rstack    = dump_mermaid_task_rstack,
				.kernel_func    = dump_mermaid_kernel_rstack,
				.footer         = dump_mermaid_footer,
			},
		};

		do_dump_replay(&dump.ops, opts, &handle);
	}
	else {
		struct uftrace_raw_dump dump = {
			.ops = {
				.header         = dump_raw_header,
				.task_start     = dump_raw_task_start,
				.inverted_time  = dump_raw_inverted_time,
				.task_rstack    = dump_raw_task_rstack,
				.task_event     = dump_raw_task_event,
				.kernel_start   = dump_raw_kernel_start,
				.cpu_start      = dump_raw_cpu_start,
				.kernel_func    = dump_raw_kernel_rstack,
				.kernel_event   = dump_raw_kernel_event,
				.lost           = dump_raw_kernel_lost,
				.perf_start     = dump_raw_perf_start,
				.perf_event     = dump_raw_perf_event,
			},
		};

		do_dump_file(&dump.ops, opts, &handle);
	}

	close_data_file(opts, &handle);

	return ret;
}

#ifdef UNIT_TEST
TEST_CASE(dump_command1)
{
	struct uftrace_opts opts = {
		.dirname = "dump-file-test",
		.exename = read_exename(),
		.max_stack = 10,
		.depth = OPT_DEPTH_DEFAULT,
	};
	struct uftrace_data handle;
	struct uftrace_raw_dump dump = {
		.ops = {
			.header         = dump_raw_header,
			.task_start     = dump_raw_task_start,
			.inverted_time  = dump_raw_inverted_time,
			.task_rstack    = dump_raw_task_rstack,
			.task_event     = dump_raw_task_event,
			.kernel_start   = dump_raw_kernel_start,
			.cpu_start      = dump_raw_cpu_start,
			.kernel_func    = dump_raw_kernel_rstack,
			.kernel_event   = dump_raw_kernel_event,
			.lost           = dump_raw_kernel_lost,
			.perf_start     = dump_raw_perf_start,
			.perf_event     = dump_raw_perf_event,
		},
	};

	TEST_EQ(prepare_test_data(&opts, &handle), 0);

	pr_dbg("dump each file contents\n");
	do_dump_file(&dump.ops, &opts, &handle);

	release_test_data(&opts, &handle);
	return TEST_OK;
}

TEST_CASE(dump_command2)
{
	struct uftrace_opts opts = {
		.dirname = "dump-replay-test",
		.exename = read_exename(),
		.max_stack = 10,
		.depth = OPT_DEPTH_DEFAULT,
	};
	struct uftrace_data handle;
	struct uftrace_raw_dump dump = {
		.ops = {
			.header         = dump_chrome_header,
			.task_rstack    = dump_chrome_task_rstack,
			.kernel_func    = dump_chrome_kernel_rstack,
			.perf_event     = dump_chrome_perf_event,
			.footer         = dump_chrome_footer,
		},
	};

	TEST_EQ(prepare_test_data(&opts, &handle), 0);

	pr_dbg("dump contents in time order\n");
	do_dump_replay(&dump.ops, &opts, &handle);

	release_test_data(&opts, &handle);
	return TEST_OK;
}
#endif /* UNIT_TEST */
