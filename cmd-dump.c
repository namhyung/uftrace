#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <sys/stat.h>

#include "uftrace.h"
#include "utils/list.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "utils/filter.h"
#include "utils/kernel.h"
#include "libtraceevent/kbuffer.h"
#include "libtraceevent/event-parse.h"


struct uftrace_dump_ops {
	/* this is called at the beginning */
	void (*header)(struct uftrace_dump_ops *ops,
		       struct ftrace_file_handle *handle, struct opts *opts);
	/* this is called when a task starts */
	void (*task_start)(struct uftrace_dump_ops *ops,
			   struct ftrace_task_handle *task);
	/* this is called when a record's time is before the previous */
	void (*inverted_time)(struct uftrace_dump_ops *ops,
			      struct ftrace_task_handle *task);
	/* this is called for each user-level function entry/exit */
	void (*task_rstack)(struct uftrace_dump_ops *ops,
			    struct ftrace_task_handle *task, char *name);
	/* this is called when kernel data starts */
	void (*kernel_start)(struct uftrace_dump_ops *ops,
			     struct uftrace_kernel_reader *kernel);
	/* this is called when a cpu data start */
	void (*cpu_start)(struct uftrace_dump_ops *ops,
			  struct uftrace_kernel_reader *kernel, int cpu);
	/* this is called for each kernel-level function entry/exit */
	void (*kernel_func)(struct uftrace_dump_ops *ops,
			    struct uftrace_kernel_reader *kernel, int cpu,
			    struct uftrace_record *frs, char *name);
	/* this is called for each kernel event (tracepoint) */
	void (*kernel_event)(struct uftrace_dump_ops *ops,
			     struct uftrace_kernel_reader *kernel, int cpu,
			     struct uftrace_record *frs);
	/* thius is called when there's a lost record (usually in kernel) */
	void (*lost)(struct uftrace_dump_ops *ops,
		     uint64_t time, int tid, int losts);
	/* this is called when a perf data (for each cpu) starts */
	void (*perf_start)(struct uftrace_dump_ops *ops,
			   struct uftrace_perf_reader *perf, int cpu);
	/* this is called for each perf event (e.g. schedule) */
	void (*perf_event)(struct uftrace_dump_ops *ops,
			   struct uftrace_perf_reader *perf,
			   struct uftrace_record *frs);
	/* this is called at the end */
	void (*footer)(struct uftrace_dump_ops *ops,
		       struct ftrace_file_handle *handle, struct opts *opts);
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
};

struct uftrace_flame_dump {
	struct uftrace_dump_ops ops;
	struct rb_root tasks;
	struct fg_node *node;
	uint64_t sample_time;
};

static const char * rstack_type(struct uftrace_record *frs)
{
	return frs->type == UFTRACE_EXIT ? "exit " :
		frs->type == UFTRACE_ENTRY ? "entry" :
		frs->type == UFTRACE_EVENT ? "event" : "lost ";
}

static void pr_time(uint64_t timestamp)
{
	unsigned sec   = timestamp / NSEC_PER_SEC;
	unsigned nsec  = timestamp % NSEC_PER_SEC;

	pr_out("%u.%09u  ", sec, nsec);
}

static int pr_task(struct opts *opts)
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
			if (fread(exename, ALIGN(smsg.namelen, 8), 1,fp) != 1 ) {
				pr_red("cannot read executable name: %m\n");
				goto out;
			}

			pr_time(smsg.task.time);
			pr_out("session of task %d: %.*s (%s)\n",
			       smsg.task.tid, sizeof(smsg.sid), smsg.sid, exename);
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

static int pr_task_txt(struct opts *opts)
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
			exename = ptr + 8 + 1;  // skip double-quote

			end = strrchr(ptr, '\"');
			if (end == NULL) {
				pr_red("invalid session exename\n");
				goto out;
			}
			*end++ = '\0';

			pr_out("%s  session of task %d: %.*s (%s)\n",
			       timestamp, tid, 16, sid, exename);
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
		pr_green(" <%016"PRIx64">:", ofs);
		pr_green(" %02x %02x %02x %02x %02x %02x %02x %02x "
			 " %02x %02x %02x %02x %02x %02x %02x %02x\n",
			 h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
			 h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);

		ofs += 16;
		len -= 16;
		h += 16;
	}

	if (len) {
		pr_green(" <%016"PRIx64">:", ofs);
		if (len > 8) {
			pr_green(" %02x %02x %02x %02x %02x %02x %02x %02x ",
				 h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

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

static void pr_args(struct fstack_arguments *args)
{
	struct uftrace_arg_spec *spec;
	void *ptr = args->data;
	size_t size;
	int i = 0;

	list_for_each_entry(spec, args->args, list) {
		/* skip return value info */
		if (spec->idx == RETVAL_IDX)
			continue;

		if (spec->fmt == ARG_FMT_STR ||
		    spec->fmt == ARG_FMT_STD_STRING) {
			char *buf;
			const int null_str = -1;

			size = *(unsigned short *)ptr;
			buf = xmalloc(size + 1);
			strncpy(buf, ptr + 2, size);

			if (!memcmp(buf, &null_str, 4))
				strcpy(buf, "NULL");

			if (spec->fmt == ARG_FMT_STD_STRING)
				pr_out("  args[%d] std::string: %s\n", i , buf);
			else
				pr_out("  args[%d] str: %s\n", i , buf);

			free(buf);
			size += 2;
		}
		else {
			long long val = 0;

			memcpy(&val, ptr, spec->size);
			pr_out("  args[%d] %c%d: 0x%0*llx\n", i,
			       ARG_SPEC_CHARS[spec->fmt], spec->size * 8,
			       spec->size * 2, val);
			size = spec->size;
		}

		ptr += ALIGN(size, 4);
		i++;
	}
}

static void pr_retval(struct fstack_arguments *args)
{
	struct uftrace_arg_spec *spec;
	void *ptr = args->data;
	size_t size;
	int i = 0;

	list_for_each_entry(spec, args->args, list) {
		/* skip argument info */
		if (spec->idx != RETVAL_IDX)
			continue;

		if (spec->fmt == ARG_FMT_STR ||
		    spec->fmt == ARG_FMT_STD_STRING) {
			char buf[64] = {0};
			const int null_str = -1;

			size = *(unsigned short *)ptr;
			strncpy(buf, ptr + 2, size);

			if (!memcmp(buf, &null_str, 4))
				strcpy(buf, "NULL");

			if (spec->fmt == ARG_FMT_STD_STRING)
				pr_out("  retval[%d] std::string: %s\n", i , buf);
			else
				pr_out("  retval[%d] str: %s\n", i , buf);
			size += 2;
		}
		else {
			long long val = 0;

			memcpy(&val, ptr, spec->size);
			pr_out("  retval[%d] %c%d: 0x%0*llx\n", i,
			       ARG_SPEC_CHARS[spec->fmt], spec->size * 8,
			       spec->size * 2, val);
			size = spec->size;
		}

		ptr += ALIGN(size, 4);
		i++;
	}
}

static void pr_event(int eid, void *ptr, int len)
{
	union {
		struct uftrace_proc_statm *statm;
		struct uftrace_page_fault *pgfault;
	} d;

	/* built-in events */
	switch (eid) {
	case EVENT_ID_PROC_STATM:
		d.statm = ptr;
		pr_out("  proc/statm: vmsize=%"PRIu64"K vmrss=%"PRIu64"K shared=%"PRIu64"K\n",
		       d.statm->vmsize, d.statm->vmrss, d.statm->shared);
		break;
	case EVENT_ID_PAGE_FAULT:
		d.pgfault = ptr;
		pr_out("  page-fault: major=%"PRIu64" minor=%"PRIu64"\n",
		       d.pgfault->major, d.pgfault->minor);
		break;
	default:
		break;
	}

	/* user events */
}

static void get_feature_string(char *buf, size_t sz, uint64_t feature_mask)
{
	int i;
	size_t len;
	bool first = true;
	const char *feat_str[] = { "PLTHOOK", "TASK_SESSION", "KERNEL",
				   "ARGUMENT", "RETVAL", "SYM_REL_ADDR",
				   "MAX_STACK", "EVENT", "PERF_EVENT" };

	/* feat_str should match to enum uftrace_feat_bits */
	for (i = 0; i < FEAT_BIT_MAX; i++) {
		if (!((1U << i) & feature_mask))
			continue;

		len = snprintf(buf, sz, "%s%s", first ? "" : " | ", feat_str[i]);
		buf += len;
		sz  -= len;

		first = false;
	}
}

static void print_raw_header(struct uftrace_dump_ops *ops,
			     struct ftrace_file_handle *handle,
			     struct opts *opts)
{
	int i;
	char buf[1024];
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	pr_out("uftrace file header: magic         = ");
	for (i = 0; i < UFTRACE_MAGIC_LEN; i++)
		pr_out("%02x", handle->hdr.magic[i]);
	pr_out("\n");
	pr_out("uftrace file header: version       = %u\n", handle->hdr.version);
	pr_out("uftrace file header: header size   = %u\n", handle->hdr.header_size);
	pr_out("uftrace file header: endian        = %u (%s)\n",
	       handle->hdr.endian, handle->hdr.endian == 1 ? "little" : "big");
	pr_out("uftrace file header: class         = %u (%s bit)\n",
	       handle->hdr.class, handle->hdr.class == 2 ? "64" : "32");
	get_feature_string(buf, sizeof(buf), handle->hdr.feat_mask);
	pr_out("uftrace file header: features      = %#"PRIx64" (%s)\n",
	       handle->hdr.feat_mask, buf);
	pr_out("uftrace file header: info          = %#"PRIx64"\n", handle->hdr.info_mask);
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

static void print_raw_task_start(struct uftrace_dump_ops *ops,
				 struct ftrace_task_handle *task)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	pr_out("reading %d.dat\n", task->tid);
	raw->file_offset = 0;

	setup_rstack_list(&task->rstack_list);
}

static void print_raw_inverted_time(struct uftrace_dump_ops *ops,
				    struct ftrace_task_handle *task)
{
	pr_red("\n");
	pr_red("*************************************\n");
	pr_red("* inverted time - data seems broken *\n");
	pr_red("*************************************\n");
	pr_red("\n");
}

static void print_raw_task_rstack(struct uftrace_dump_ops *ops,
				  struct ftrace_task_handle *task, char *name)
{
	struct uftrace_record *frs = task->rstack;
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	if (frs->type == UFTRACE_EVENT)
		name = get_event_name(task->h, frs->addr);

	pr_time(frs->time);
	pr_out("%5d: [%s] %s(%"PRIx64") depth: %u\n",
	       task->tid, rstack_type(frs),
	       name, frs->addr, frs->depth);
	pr_hex(&raw->file_offset, frs, sizeof(*frs));

	if (frs->type == UFTRACE_EVENT)
		free(name);

	if (frs->more) {
		if (frs->type == UFTRACE_ENTRY) {
			pr_time(frs->time);
			pr_out("%5d: [%s] length = %d\n", task->tid, "args ",
			       task->args.len);
			pr_args(&task->args);
			pr_hex(&raw->file_offset, task->args.data,
			       ALIGN(task->args.len, 8));
		}
		else if (frs->type == UFTRACE_EXIT) {
			pr_time(frs->time);
			pr_out("%5d: [%s] length = %d\n", task->tid, "retval",
			       task->args.len);
			pr_retval(&task->args);
			pr_hex(&raw->file_offset, task->args.data,
			       ALIGN(task->args.len, 8));
		}
		else if (frs->type == UFTRACE_EVENT) {
			pr_time(frs->time);
			pr_out("%5d: [%s] length = %d\n", task->tid, "data ",
			       task->args.len);
			pr_event(frs->addr, task->args.data, task->args.len);
			pr_hex(&raw->file_offset, task->args.data,
			       ALIGN(task->args.len, 8));
		}
		else
			abort();
	}
}

static void print_raw_kernel_start(struct uftrace_dump_ops *ops,
				   struct uftrace_kernel_reader *kernel)
{
	pr_out("\n");
}

static void print_raw_cpu_start(struct uftrace_dump_ops *ops,
				struct uftrace_kernel_reader *kernel, int cpu)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);
	struct kbuffer *kbuf = kernel->kbufs[cpu];

	pr_out("reading kernel-cpu%d.dat\n", cpu);

	raw->file_offset = 0;
	raw->kbuf_offset = kbuffer_curr_offset(kbuf);
}

static void print_raw_kernel_rstack(struct uftrace_dump_ops *ops,
				    struct uftrace_kernel_reader *kernel, int cpu,
				    struct uftrace_record *frs, char *name)
{
	int tid = kernel->tids[cpu];
	struct kbuffer *kbuf = kernel->kbufs[cpu];
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	/* check dummy 'time extend' record at the beginning */
	if (raw->kbuf_offset == 0x18) {
		uint64_t offset = 0x10;
		unsigned long long timestamp = 0;
		void *data = kbuffer_read_at_offset(kbuf, offset, NULL);
		unsigned char *tmp = data - 12;  /* data still returns next record */

		if ((*tmp & 0x1f) == KBUFFER_TYPE_TIME_EXTEND) {
			uint32_t upper, lower;
			int size;

			size = kbuffer_event_size(kbuf);

			memcpy(&lower, tmp, 4);
			memcpy(&upper, tmp + 4, 4);
			timestamp = ((uint64_t)upper << 27) + (lower >> 5);

			pr_time(frs->time - timestamp);
			pr_out("%5d: [%s] %s (+%"PRIu64" nsec)\n",
			       tid, "time ", "extend", timestamp);

			if (debug)
				pr_hex(&offset, tmp, 8);
			else if (kbuffer_next_event(kbuf, NULL))
				raw->kbuf_offset += size + 4;  // 4 = event header size
			else
				raw->kbuf_offset = 0;
		}
	}

	pr_time(frs->time);
	pr_out("%5d: [%s] %s(%"PRIx64") depth: %u\n",
	       tid, rstack_type(frs),
	       name, frs->addr, frs->depth);

	if (debug) {
		/* this is only needed for hex dump */
		void *data = kbuffer_read_at_offset(kbuf, raw->kbuf_offset, NULL);
		int size;

		size = kbuffer_event_size(kbuf);
		raw->file_offset = kernel->offsets[cpu] + kbuffer_curr_offset(kbuf);
		pr_hex(&raw->file_offset, data - 4, size + 4);

		if (kbuffer_next_event(kbuf, NULL))
			raw->kbuf_offset += size + 4;  // 4 = event header size
		else
			raw->kbuf_offset = 0;
	}
}


static void print_raw_kernel_event(struct uftrace_dump_ops *ops,
				   struct uftrace_kernel_reader *kernel, int cpu,
				   struct uftrace_record *frs)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);
	struct event_format *event;
	int tid = kernel->tids[cpu];
	char *event_data;
	int size = 0;

	event = pevent_find_event(kernel->pevent, frs->addr);
	event_data = read_kernel_event(kernel, cpu, &size);

	pr_time(frs->time);
	pr_out("%5d: [%s] %s:%s(%d) %.*s\n",
	       tid, rstack_type(frs), event->system, event->name,
	       frs->addr, size, event_data);

	if (debug) {
		/* this is only needed for hex dump */
		struct kbuffer *kbuf = kernel->kbufs[cpu];
		void *data = kbuffer_read_at_offset(kbuf, raw->kbuf_offset, NULL);
		int size;

		size = kbuffer_event_size(kbuf);
		raw->file_offset = kernel->offsets[cpu] + kbuffer_curr_offset(kbuf);
		pr_hex(&raw->file_offset, data - 4, size + 4);

		if (kbuffer_next_event(kbuf, NULL))
			raw->kbuf_offset += size + 4;  // 4 = event header size
		else
			raw->kbuf_offset = 0;
	}
}

static void print_raw_kernel_lost(struct uftrace_dump_ops *ops,
				  uint64_t time, int tid, int losts)
{
	pr_time(time);
	pr_red("%5d: [%s ]: %d events\n", tid, "lost", losts);
}

static void print_raw_perf_start(struct uftrace_dump_ops *ops,
				 struct uftrace_perf_reader *perf, int cpu)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	if (cpu == 0)
		pr_out("\n");

	pr_out("reading perf-cpu%d.dat\n", cpu);

	raw->file_offset = 0;
}

static void print_raw_perf_event(struct uftrace_dump_ops *ops,
				 struct uftrace_perf_reader *perf,
				 struct uftrace_record *frs)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);
	char *evt_name = get_event_name(NULL, frs->addr);

	pr_time(frs->time);
	pr_out("%5d: [%s] %s(%d)\n",
	       perf->ctxsw.tid, rstack_type(frs), evt_name, frs->addr);

	if (debug)
		pr_hex(&raw->file_offset, &perf->ctxsw, sizeof(perf->ctxsw));

	free(evt_name);
}

static void print_raw_footer(struct uftrace_dump_ops *ops,
			     struct ftrace_file_handle *handle,
			     struct opts *opts)
{
}

static void print_chrome_header(struct uftrace_dump_ops *ops,
				struct ftrace_file_handle *handle,
				struct opts *opts)
{
	struct uftrace_chrome_dump *chrome = container_of(ops, typeof(*chrome), ops);

	pr_out("{\"traceEvents\":[\n");

	chrome->last_comma = false;
}

static void print_chrome_task_start(struct uftrace_dump_ops *ops,
				    struct ftrace_task_handle *task)
{
}

static void print_chrome_inverted_time(struct uftrace_dump_ops *ops,
				       struct ftrace_task_handle *task)
{
}

static void print_chrome_task_rstack(struct uftrace_dump_ops *ops,
				     struct ftrace_task_handle *task, char *name)
{
	char ph;
	char spec_buf[1024];
	struct uftrace_record *frs = task->rstack;
	enum argspec_string_bits str_mode = NEEDS_ESCAPE | NEEDS_PAREN;
	struct uftrace_chrome_dump *chrome = container_of(ops, typeof(*chrome), ops);

	if (frs->type == UFTRACE_EVENT) {
		if (frs->addr != EVENT_ID_PERF_SCHED_IN &&
		    frs->addr != EVENT_ID_PERF_SCHED_OUT)
			return;

		/* new thread starts with sched-in event which should be ignored */
		if (frs->addr == EVENT_ID_PERF_SCHED_IN && task->timestamp_last == 0)
			return;
	}

	if (chrome->last_comma)
		pr_out(",\n");
	chrome->last_comma = true;

	if ((frs->type == UFTRACE_ENTRY) ||
	    (frs->type == UFTRACE_EVENT && frs->addr == EVENT_ID_PERF_SCHED_OUT)) {
		ph = 'B';
		pr_out("{\"ts\":%"PRIu64".%03d,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
		       frs->time / 1000, (int)(frs->time % 1000), ph, task->tid, name);
		if (frs->more) {
			str_mode |= HAS_MORE;
			get_argspec_string(task, spec_buf, sizeof(spec_buf), str_mode);
			pr_out(",\"args\":{\"arguments\":\"%s\"}}",
				spec_buf);
		}
		else
			pr_out("}");
	}
	else if ((frs->type == UFTRACE_EXIT) ||
		 (frs->type == UFTRACE_EVENT && frs->addr == EVENT_ID_PERF_SCHED_IN)) {
		ph = 'E';
		pr_out("{\"ts\":%"PRIu64".%03d,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
		       frs->time / 1000, (int)(frs->time % 1000), ph, task->tid, name);
		if (frs->more) {
			str_mode |= IS_RETVAL | HAS_MORE;
			get_argspec_string(task, spec_buf, sizeof(spec_buf), str_mode);
			pr_out(",\"args\":{\"retval\":\"%s\"}}",
				spec_buf);
		}
		else
			pr_out("}");
	}
	else if (frs->type == UFTRACE_LOST)
		chrome->lost_event_cnt++;
}

static void print_chrome_kernel_start(struct uftrace_dump_ops *ops,
				      struct uftrace_kernel_reader *kernel)
{
}

static void print_chrome_cpu_start(struct uftrace_dump_ops *ops,
				   struct uftrace_kernel_reader *kernel, int cpu)
{
}

static void print_chrome_kernel_rstack(struct uftrace_dump_ops *ops,
				       struct uftrace_kernel_reader *kernel, int cpu,
				       struct uftrace_record *frs, char *name)
{
}

static void print_chrome_kernel_event(struct uftrace_dump_ops *ops,
				      struct uftrace_kernel_reader *kernel, int cpu,
				      struct uftrace_record *frs)
{
}

static void print_chrome_kernel_lost(struct uftrace_dump_ops *ops,
				     uint64_t time, int tid, int losts)
{
}

static void print_chrome_perf_start(struct uftrace_dump_ops *ops,
				    struct uftrace_perf_reader *perf, int cpu)
{
}

static void print_chrome_perf_event(struct uftrace_dump_ops *ops,
				    struct uftrace_perf_reader *perf,
				    struct uftrace_record *frs)
{
}

static void print_chrome_footer(struct uftrace_dump_ops *ops,
				struct ftrace_file_handle *handle,
				struct opts *opts)
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
	if (handle->hdr.info_mask & (1UL << CMDLINE))
		pr_out("\"command_line\":\"%s\",\n", handle->info.cmdline);
	pr_out("\"recorded_time\":\"%s\"\n", buf);
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
			"(%d times shown)\n", chrome->lost_event_cnt);
		pr_warn("The output json format may not show the correct view "
			"in chrome browser.\n");
	}
}

/* flamegraph support */
struct fg_node {
	int calls;
	char *name;
	uint64_t total_time;
	uint64_t child_time;
	struct fg_node *parent;
	struct list_head siblings;
	struct list_head children;
};

static struct fg_node fg_root = {
	.siblings = LIST_HEAD_INIT(fg_root.siblings),
	.children = LIST_HEAD_INIT(fg_root.children),
};

struct fg_task {
	int tid;
	struct fg_node *node;
	struct rb_node link;
};

static struct fg_task * find_fg_task(struct rb_root *root, int tid)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct fg_task *iter, *new;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct fg_task, link);

		if (iter->tid == tid)
			return iter;

		if (iter->tid > tid)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	new = xmalloc(sizeof(*new));
	new->tid = tid;
	new->node = &fg_root;

	rb_link_node(&new->link, parent, p);
	rb_insert_color(&new->link, root);

	return new;
}

static struct fg_node * add_fg_node(struct fg_node *parent, char *name)
{
	struct fg_node *child;

	list_for_each_entry(child, &parent->children, siblings) {
		if (!strcmp(name, child->name))
			break;
	}

	if (list_no_entry(child, &parent->children, siblings)) {
		child = xmalloc(sizeof(*child));

		child->name = xstrdup(name);
		child->calls = 0;
		child->parent = parent;
		child->total_time = 0;
		child->child_time = 0;

		INIT_LIST_HEAD(&child->children);
		list_add(&child->siblings, &parent->children);
	}

	child->calls++;
	return child;
}

static struct fg_node * add_fg_time(struct fg_node *node,
				    struct ftrace_task_handle *task,
				    uint64_t sample_time)
{
	struct fstack *fstack = &task->func_stack[task->stack_count];

	if (sample_time) {
		uint64_t curr_time = fstack->total_time;

		node->total_time += curr_time;

		if (node->parent != &fg_root) {
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
			 * But it acctually needs to get 2 samples.
			 *
			 * So add the accounted child time only, not real time.
			 */
			uint64_t accounted_time;

			accounted_time = (curr_time / sample_time) * sample_time;
			node->parent->child_time += accounted_time;
		}
	}

	return node->parent;
}

static void print_flame_graph(struct fg_node *node, struct opts *opts)
{
	struct fg_node *child;
	unsigned long sample = node->calls;

	if (opts->sample_time)
		sample = (node->total_time - node->child_time) / opts->sample_time;

	if (sample) {
		struct fg_node *parent = node;
		char *names[opts->max_stack];
		char *buf, *ptr;
		int i = 0;
		size_t len = 0;

		while (parent != &fg_root) {
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

	list_for_each_entry(child, &node->children, siblings)
		print_flame_graph(child, opts);

	free(node->name);
	if (node != &fg_root)
		free(node);
}

static void print_flame_header(struct uftrace_dump_ops *ops,
			       struct ftrace_file_handle *handle,
			       struct opts *opts)
{
}

static void print_flame_task_start(struct uftrace_dump_ops *ops,
				   struct ftrace_task_handle *task)
{
}

static void print_flame_inverted_time(struct uftrace_dump_ops *ops,
				      struct ftrace_task_handle *task)
{
}

static void print_flame_task_rstack(struct uftrace_dump_ops *ops,
				    struct ftrace_task_handle *task, char *name)
{
	struct uftrace_record *frs = task->rstack;
	struct uftrace_flame_dump *flame = container_of(ops, typeof(*flame), ops);
	struct fg_task *t = find_fg_task(&flame->tasks, task->tid);
	struct fg_node *node = t->node;

	if (frs->type == UFTRACE_ENTRY)
		node = add_fg_node(node, name);
	else if (frs->type == UFTRACE_EXIT)
		node = add_fg_time(node, task, flame->sample_time);
	else if (frs->type == UFTRACE_EVENT) {
		if (frs->addr == EVENT_ID_PERF_SCHED_OUT)
			node = add_fg_node(node, name);
		else if (frs->addr == EVENT_ID_PERF_SCHED_IN &&
			 task->timestamp_last) /* ignore first sched-in for thread */
			node = add_fg_time(node, task, flame->sample_time);
		else
			node = t->node;  /* skip other event records */
	}
	else
		node = &fg_root;

	if (unlikely(node == NULL))
		node = &fg_root;

	t->node = node;
}

static void print_flame_kernel_start(struct uftrace_dump_ops *ops,
				     struct uftrace_kernel_reader *kernel)
{
}

static void print_flame_cpu_start(struct uftrace_dump_ops *ops,
				  struct uftrace_kernel_reader *kernel, int cpu)
{
}

static void print_flame_kernel_rstack(struct uftrace_dump_ops *ops,
				      struct uftrace_kernel_reader *kernel, int cpu,
				      struct uftrace_record *frs, char *name)
{
}

static void print_flame_kernel_event(struct uftrace_dump_ops *ops,
				     struct uftrace_kernel_reader *kernel, int cpu,
				     struct uftrace_record *frs)
{
}

static void print_flame_kernel_lost(struct uftrace_dump_ops *ops,
				    uint64_t time, int tid, int losts)
{
}

static void print_flame_perf_start(struct uftrace_dump_ops *ops,
				   struct uftrace_perf_reader *perf, int cpu)
{
}

static void print_flame_perf_event(struct uftrace_dump_ops *ops,
				   struct uftrace_perf_reader *perf,
				   struct uftrace_record *frs)
{
}

static void print_flame_footer(struct uftrace_dump_ops *ops,
			       struct ftrace_file_handle *handle,
			       struct opts *opts)
{
	print_flame_graph(&fg_root, opts);
}

static void do_dump_file(struct uftrace_dump_ops *ops, struct opts *opts,
			 struct ftrace_file_handle *handle)
{
	int i;
	uint64_t prev_time;
	struct ftrace_task_handle *task;
	struct uftrace_session_link *sessions = &handle->sessions;

	ops->header(ops, handle, opts);

	for (i = 0; i < handle->info.nr_tid; i++) {
		if (opts->kernel && opts->kernel_only)
			continue;

		task = &handle->tasks[i];
		task->rstack = &task->ustack;

		prev_time = 0;

		ops->task_start(ops, task);

		while (!read_task_ustack(handle, task) && !uftrace_done) {
			struct uftrace_record *frs = &task->ustack;
			struct sym *sym;
			char *name;

			if (frs->more) {
				add_to_rstack_list(&task->rstack_list,
						   frs, &task->args);
			}

			/* consume the rstack as it didn't call read_rstack() */
			fstack_consume(handle, task);

			if (!check_time_range(&handle->time_range, frs->time))
				continue;

			if (prev_time > frs->time)
				ops->inverted_time(ops, task);
			prev_time = frs->time;

			if (!fstack_check_filter(task))
				continue;

			sym = task_find_sym(sessions, task, frs);

			name = symbol_getname(sym, frs->addr);
			ops->task_rstack(ops, task, name);
			symbol_putname(sym, name);
		}
	}

	if (!has_kernel_data(handle->kernel) || uftrace_done)
		goto perf;

	ops->kernel_start(ops, handle->kernel);

	for (i = 0; i < handle->kernel->nr_cpus; i++) {
		struct uftrace_kernel_reader *kernel = handle->kernel;
		struct uftrace_record *frs = &kernel->rstacks[i];
		struct uftrace_session *fsess = handle->sessions.first;

		ops->cpu_start(ops, kernel, i);

		while (!read_kernel_cpu_data(kernel, i) && !uftrace_done) {
			int tid = kernel->tids[i];
			int losts = kernel->missed_events[i];
			struct sym *sym = NULL;
			char *name;

			if (losts) {
				ops->lost(ops, frs->time, tid, losts);
				kernel->missed_events[i] = 0;
			}

			if (!check_time_range(&handle->time_range, frs->time))
				continue;

			if (frs->type == UFTRACE_EVENT) {
				ops->kernel_event(ops, kernel, i, frs);
				continue;
			}

			sym = find_symtabs(&fsess->symtabs, frs->addr);
			name = symbol_getname(sym, frs->addr);

			ops->kernel_func(ops, kernel, i, frs, name);

			symbol_putname(sym, name);
		}
	}

perf:
	if (!has_perf_data(handle) || uftrace_done)
		goto footer;

	/* force get_perf_record() to read from file */
	handle->last_perf_idx = -1;

	for (i = 0; i < handle->nr_perf; i++) {
		struct uftrace_perf_reader *perf = &handle->perf[i];

		ops->perf_start(ops, perf, i);

		while (!uftrace_done) {
			struct uftrace_record *rec;

			rec = get_perf_record(handle, perf);
			if (rec == NULL)
				break;

			ops->perf_event(ops, perf, rec);
		}
	}

footer:
	ops->footer(ops, handle, opts);
}

static bool check_task_rstack(struct ftrace_task_handle *task,
			      struct opts *opts)
{
	struct uftrace_record *frs = task->rstack;

	if (has_kernel_data(task->h->kernel)) {
		if (opts->kernel_skip_out) {
			if (!task->user_stack_count &&
			    is_kernel_record(task, frs))
				return false;
		}

		if (opts->kernel_only &&
		    !is_kernel_record(task, frs))
			return false;
	}

	if (frs->type == UFTRACE_EVENT) {
		if (!task->user_stack_count && opts->event_skip_out)
			return false;
	}

	if (!fstack_check_filter(task))
		return false;

	if (!check_time_range(&task->h->time_range, frs->time))
		return false;

	return true;
}

static void dump_replay_task(struct uftrace_dump_ops *ops,
			     struct ftrace_task_handle *task)
{
	struct uftrace_record *frs = task->rstack;
	struct uftrace_session_link *sessions = &task->h->sessions;
	struct sym *sym = NULL;
	char *name;
	struct sym sched_sym = {
		.name = "linux:schedule",
	};

	if (frs->type != UFTRACE_EVENT)
		sym = task_find_sym(sessions, task, frs);
	else if (frs->addr == EVENT_ID_PERF_SCHED_IN ||
		 frs->addr == EVENT_ID_PERF_SCHED_OUT)
		sym = &sched_sym;

	name = symbol_getname(sym, frs->addr);
	ops->task_rstack(ops, task, name);
	symbol_putname(sym, name);
}

static void do_dump_replay(struct uftrace_dump_ops *ops, struct opts *opts,
			   struct ftrace_file_handle *handle)
{
	uint64_t prev_time = 0;
	struct ftrace_task_handle *task;
	int i;

	ops->header(ops, handle, opts);

	while (!read_rstack(handle, &task) && !uftrace_done) {
		struct uftrace_record *frs = task->rstack;

		if (!check_task_rstack(task, opts))
			continue;

		if (prev_time > frs->time)
			ops->inverted_time(ops, task);
		prev_time = frs->time;

		dump_replay_task(ops, task);

		task->timestamp_last = frs->time;
	}

	/* add duration of remaining functions */
	for (i = 0; i < handle->nr_tasks; i++) {
		uint64_t last_time;

		task = &handle->tasks[i];

		if (task->stack_count == 0)
			continue;

		last_time = task->rstack->time;

		if (handle->time_range.stop && handle->time_range.stop < last_time)
			last_time = handle->time_range.stop;

		while (--task->stack_count >= 0) {
			struct fstack *fstack;
			struct uftrace_session *fsess = handle->sessions.first;

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

			/* make sure is_kernel_record() working correctly */
			if (is_kernel_address(&fsess->symtabs, fstack->addr))
				task->rstack = &task->kstack;
			else
				task->rstack = &task->ustack;

			task->rstack->time = last_time;
			task->rstack->type = UFTRACE_EXIT;
			task->rstack->addr = fstack->addr;

			if (check_task_rstack(task, opts))
				dump_replay_task(ops, task);
		}
	}

	ops->footer(ops, handle, opts);
}

int command_dump(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
		return -1;
	}

	fstack_setup_filters(opts, &handle);

	if (opts->chrome_trace) {
		struct uftrace_chrome_dump dump = {
			.ops = {
				.header         = print_chrome_header,
				.task_start     = print_chrome_task_start,
				.inverted_time  = print_chrome_inverted_time,
				.task_rstack    = print_chrome_task_rstack,
				.kernel_start   = print_chrome_kernel_start,
				.cpu_start      = print_chrome_cpu_start,
				.kernel_func    = print_chrome_kernel_rstack,
				.kernel_event   = print_chrome_kernel_event,
				.lost           = print_chrome_kernel_lost,
				.perf_start     = print_chrome_perf_start,
				.perf_event     = print_chrome_perf_event,
				.footer         = print_chrome_footer,
			},
		};

		do_dump_replay(&dump.ops, opts, &handle);
	}
	else if (opts->flame_graph) {
		struct uftrace_flame_dump dump = {
			.ops = {
				.header         = print_flame_header,
				.task_start     = print_flame_task_start,
				.inverted_time  = print_flame_inverted_time,
				.task_rstack    = print_flame_task_rstack,
				.kernel_start   = print_flame_kernel_start,
				.cpu_start      = print_flame_cpu_start,
				.kernel_func    = print_flame_kernel_rstack,
				.kernel_event   = print_flame_kernel_event,
				.lost           = print_flame_kernel_lost,
				.perf_start     = print_flame_perf_start,
				.perf_event     = print_flame_perf_event,
				.footer         = print_flame_footer,
			},
			.tasks = RB_ROOT,
			.sample_time = opts->sample_time,
		};

		do_dump_replay(&dump.ops, opts, &handle);
	}
	else {
		struct uftrace_raw_dump dump = {
			.ops = {
				.header         = print_raw_header,
				.task_start     = print_raw_task_start,
				.inverted_time  = print_raw_inverted_time,
				.task_rstack    = print_raw_task_rstack,
				.kernel_start   = print_raw_kernel_start,
				.cpu_start      = print_raw_cpu_start,
				.kernel_func    = print_raw_kernel_rstack,
				.kernel_event   = print_raw_kernel_event,
				.lost           = print_raw_kernel_lost,
				.perf_start     = print_raw_perf_start,
				.perf_event     = print_raw_perf_event,
				.footer         = print_raw_footer,
			},
		};

		do_dump_file(&dump.ops, opts, &handle);
	}

	close_data_file(opts, &handle);

	return ret;
}
