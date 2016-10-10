#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <sys/stat.h>

#include "uftrace.h"
#include "utils/compiler.h"
#include "utils/list.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "utils/filter.h"
#include "libtraceevent/kbuffer.h"


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
			     struct ftrace_kernel *kernel);
	/* this is called when a cpu data start */
	void (*cpu_start)(struct uftrace_dump_ops *ops,
			  struct ftrace_kernel *kernel, int cpu);
	/* this is called for each kernel-level function entry/exit */
	void (*kernel)(struct uftrace_dump_ops *ops,
		       struct ftrace_kernel *kernel, int cpu,
		       struct ftrace_ret_stack *frs, char *name);
	/* thius is called when there's a lost record (usually in kernel) */
	void (*lost)(struct uftrace_dump_ops *ops,
		     uint64_t time, int tid, int losts);
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

static void pr_time(uint64_t timestamp)
{
	unsigned sec   = timestamp / 1000000000;
	unsigned nsec  = timestamp % 1000000000;

	pr_out("%u.%09u  ", sec, nsec);
}

static int pr_task(struct opts *opts)
{
	FILE *fp;
	char buf[PATH_MAX];
	struct ftrace_msg msg;
	struct ftrace_msg_task tmsg;
	struct ftrace_msg_sess smsg;
	char *exename;

	snprintf(buf, sizeof(buf), "%s/task", opts->dirname);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return -1;

	while (fread(&msg, sizeof(msg), 1, fp) == 1) {
		if (msg.magic != FTRACE_MSG_MAGIC) {
			pr_red("invalid message magic: %hx\n", msg.magic);
			goto out;
		}

		switch (msg.type) {
		case FTRACE_MSG_TID:
			if (fread(&tmsg, sizeof(tmsg), 1, fp) != 1) {
				pr_red("cannot read task message: %m\n");
				goto out;
			}

			pr_time(tmsg.time);
			pr_out("task tid %d (pid %d)\n", tmsg.tid, tmsg.pid);
			break;
		case FTRACE_MSG_FORK_END:
			if (fread(&tmsg, sizeof(tmsg), 1, fp) != 1) {
				pr_red("cannot read task message: %m\n");
				goto out;
			}

			pr_time(tmsg.time);
			pr_out("fork pid %d (ppid %d)\n", tmsg.tid, tmsg.pid);
			break;
		case FTRACE_MSG_SESSION:
			if (fread(&smsg, sizeof(smsg), 1, fp) != 1) {
				pr_red("cannot read session message: %m\n");
				goto out;
			}
			exename = xmalloc(ALIGN(smsg.namelen, 8));
			if (fread(exename, ALIGN(smsg.namelen, 8), 1,fp) != 1 ) {
				pr_red("cannot read executable name: %m\n");
				goto out;
			}

			pr_time(smsg.task.time);
			pr_out("session of task %d: %.*s (%s)\n",
			       smsg.task.tid, sizeof(smsg.sid), smsg.sid, exename);
			free(exename);
			break;
		default:
			pr_out("unknown message type: %u\n", msg.type);
			break;
		}
	}

out:
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
	struct ftrace_arg_spec *spec;
	void *ptr = args->data;
	size_t size;
	int i = 0;

	list_for_each_entry(spec, args->args, list) {
		/* skip return value info */
		if (spec->idx == RETVAL_IDX)
			continue;

		if (spec->fmt == ARG_FMT_STR) {
			char buf[64];
			const int null_str = -1;

			size = *(unsigned short *)ptr;
			strncpy(buf, ptr + 2, size);

			if (!memcmp(buf, &null_str, 4))
				strcpy(buf, "NULL");

			pr_out("  args[%d] str: %s\n", i , buf);
			size += 2;
		}
		else {
			long long val = 0;

			memcpy(&val, ptr, spec->size);
			pr_out("  args[%d] %c%d: %#llx\n", i,
			       ARG_SPEC_CHARS[spec->fmt], spec->size * 8, val);
			size = spec->size;
		}

		ptr += ALIGN(size, 4);
		i++;
	}
}

static void pr_retval(struct fstack_arguments *args)
{
	struct ftrace_arg_spec *spec;
	void *ptr = args->data;
	size_t size;
	int i = 0;

	list_for_each_entry(spec, args->args, list) {
		/* skip argument info */
		if (spec->idx != RETVAL_IDX)
			continue;

		if (spec->fmt == ARG_FMT_STR) {
			char buf[64];
			const int null_str = -1;

			size = *(unsigned short *)ptr;
			strncpy(buf, ptr + 2, size);

			if (!memcmp(buf, &null_str, 4))
				strcpy(buf, "NULL");

			pr_out("  retval[%d] str: %s\n", i , buf);
			size += 2;
		}
		else {
			long long val = 0;

			memcpy(&val, ptr, spec->size);
			pr_out("  retval[%d] %c%d: %#llx\n", i,
			       ARG_SPEC_CHARS[spec->fmt], spec->size * 8, val);
			size = spec->size;
		}

		ptr += ALIGN(size, 4);
		i++;
	}
}

static void print_raw_header(struct uftrace_dump_ops *ops,
			     struct ftrace_file_handle *handle,
			     struct opts *opts)
{
	int i;
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
	pr_out("uftrace file header: features      = %#"PRIx64"\n", handle->hdr.feat_mask);
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
	pr_out("reading %d.dat\n", task->tid);
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
	struct ftrace_ret_stack *frs = task->rstack;
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	pr_time(frs->time);
	pr_out("%5d: [%s] %s(%lx) depth: %u\n",
	       task->tid, frs->type == FTRACE_EXIT ? "exit " :
	       frs->type == FTRACE_ENTRY ? "entry" : "lost ",
	       name, (unsigned long)frs->addr, frs->depth);
	pr_hex(&raw->file_offset, frs, sizeof(*frs));

	if (frs->more) {
		if (frs->type == FTRACE_ENTRY) {
			pr_time(frs->time);
			pr_out("%5d: [%s] length = %d\n", task->tid, "args ",
			       task->args.len);
			pr_args(&task->args);
			pr_hex(&raw->file_offset, task->args.data, task->args.len);
		} else if (frs->type == FTRACE_EXIT) {
			pr_time(frs->time);
			pr_out("%5d: [%s] length = %d\n", task->tid, "retval",
			       task->args.len);
			pr_retval(&task->args);
			pr_hex(&raw->file_offset, task->args.data, task->args.len);
		} else
			abort();
	}
}

static void print_raw_kernel_start(struct uftrace_dump_ops *ops,
				   struct ftrace_kernel *kernel)
{
	pr_out("\n");
}

static void print_raw_cpu_start(struct uftrace_dump_ops *ops,
				struct ftrace_kernel *kernel, int cpu)
{
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);
	struct kbuffer *kbuf = kernel->kbufs[cpu];

	pr_out("reading kernel-cpu%d.dat\n", cpu);

	raw->file_offset = 0;
	raw->kbuf_offset = kbuffer_curr_offset(kbuf);
}

static void print_raw_kernel_rstack(struct uftrace_dump_ops *ops,
				    struct ftrace_kernel *kernel, int cpu,
				    struct ftrace_ret_stack *frs, char *name)
{
	int tid = kernel->tids[cpu];
	struct kbuffer *kbuf = kernel->kbufs[cpu];
	struct uftrace_raw_dump *raw = container_of(ops, typeof(*raw), ops);

	pr_time(frs->time);
	pr_out("%5d: [%s] %s(%lx) depth: %u\n",
	       tid, frs->type == FTRACE_EXIT ? "exit " :
	       frs->type == FTRACE_ENTRY ? "entry" : "lost",
	       name, (unsigned long)frs->addr, frs->depth);

	if (debug) {
		/* this is only needed for hex dump */
		void *data = kbuffer_read_at_offset(kbuf, raw->kbuf_offset, NULL);
		int size;

		size = kbuffer_event_size(kbuf);
		raw->file_offset = kernel->offsets[cpu] + kbuffer_curr_offset(kbuf);
		pr_hex(&raw->file_offset, data, size);

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
	struct ftrace_ret_stack *frs = task->rstack;
	enum argspec_string_bits str_mode = NEEDS_ESCAPE;
	struct uftrace_chrome_dump *chrome = container_of(ops, typeof(*chrome), ops);

	if (chrome->last_comma)
		pr_out(",\n");
	chrome->last_comma = true;

	if (frs->type == FTRACE_ENTRY) {
		ph = 'B';
		pr_out("{\"ts\":%lu,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
			frs->time / 1000, ph, task->tid, name);
		if (frs->more) {
			str_mode |= HAS_MORE;
			get_argspec_string(task, spec_buf, sizeof(spec_buf), str_mode);
			pr_out(",\"args\":{\"arguments\":\"%s\"}}",
				spec_buf);
		}
		else
			pr_out("}");
	}
	else if (frs->type == FTRACE_EXIT) {
		ph = 'E';
		pr_out("{\"ts\":%lu,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
			frs->time / 1000, ph, task->tid, name);
		if (frs->more) {
			str_mode |= IS_RETVAL | HAS_MORE;
			get_argspec_string(task, spec_buf, sizeof(spec_buf), str_mode);
			pr_out(",\"args\":{\"retval\":\"%s\"}}",
				spec_buf);
		}
		else
			pr_out("}");
	}
	else
		chrome->lost_event_cnt++;
}

static void print_chrome_kernel_start(struct uftrace_dump_ops *ops,
				      struct ftrace_kernel *kernel)
{
}

static void print_chrome_cpu_start(struct uftrace_dump_ops *ops,
				   struct ftrace_kernel *kernel, int cpu)
{
}

static void print_chrome_kernel_rstack(struct uftrace_dump_ops *ops,
				       struct ftrace_kernel *kernel, int cpu,
				       struct ftrace_ret_stack *frs, char *name)
{
}

static void print_chrome_kernel_lost(struct uftrace_dump_ops *ops,
				     uint64_t time, int tid, int losts)
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

	pr_out("\n], \"metadata\": {\n");
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
	struct ftrace_ret_stack *frs = task->rstack;
	struct uftrace_flame_dump *flame = container_of(ops, typeof(*flame), ops);
	struct fg_task *t = find_fg_task(&flame->tasks, task->tid);
	struct fg_node *node = t->node;

	if (frs->type == FTRACE_ENTRY)
		node = add_fg_node(node, name);
	else if (frs->type == FTRACE_EXIT)
		node = add_fg_time(node, task, flame->sample_time);
	else
		node = &fg_root;

	if (unlikely(node == NULL))
		node = &fg_root;

	t->node = node;
}

static void print_flame_kernel_start(struct uftrace_dump_ops *ops,
				     struct ftrace_kernel *kernel)
{
}

static void print_flame_cpu_start(struct uftrace_dump_ops *ops,
				  struct ftrace_kernel *kernel, int cpu)
{
}

static void print_flame_kernel_rstack(struct uftrace_dump_ops *ops,
				      struct ftrace_kernel *kernel, int cpu,
				      struct ftrace_ret_stack *frs, char *name)
{
}

static void print_flame_kernel_lost(struct uftrace_dump_ops *ops,
				    uint64_t time, int tid, int losts)
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

	ops->header(ops, handle, opts);

	for (i = 0; i < handle->info.nr_tid; i++) {
		int tid;

		if (opts->kernel && opts->kernel_only)
			continue;

		task = &handle->tasks[i];
		tid = task->tid;
		task->rstack = &task->ustack;

		prev_time = 0;

		ops->task_start(ops, task);

		while (!read_task_ustack(handle, task) && !ftrace_done) {
			struct ftrace_ret_stack *frs = &task->ustack;
			struct ftrace_session *sess = find_task_session(tid, frs->time);
			struct symtabs *symtabs;
			struct sym *sym = NULL;
			char *name;

			/* consume the rstack as it didn't call read_rstack() */
			fstack_consume(handle, task);

			if (prev_time > frs->time)
				ops->inverted_time(ops, task);
			prev_time = frs->time;

			if (!fstack_check_filter(task))
				continue;

			if (sess) {
				symtabs = &sess->symtabs;
				sym = find_symtabs(symtabs, frs->addr);
			}

			name = symbol_getname(sym, frs->addr);
			ops->task_rstack(ops, task, name);
			symbol_putname(sym, name);
		}
	}

	if (!opts->kernel || handle->kern == NULL || ftrace_done)
		goto footer;

	ops->kernel_start(ops, handle->kern);

	for (i = 0; i < handle->kern->nr_cpus; i++) {
		struct ftrace_kernel *kernel = handle->kern;
		struct ftrace_ret_stack *frs = &kernel->rstacks[i];
		struct sym *sym;
		char *name;

		ops->cpu_start(ops, kernel, i);

		while (!read_kernel_cpu_data(kernel, i) && !ftrace_done) {
			int tid = kernel->tids[i];
			int losts = kernel->missed_events[i];

			if (losts) {
				ops->lost(ops, frs->time, tid, losts);
				kernel->missed_events[i] = 0;
			}

			sym = find_symtabs(NULL, frs->addr);
			name = symbol_getname(sym, frs->addr);

			ops->kernel(ops, kernel, i, frs, name);

			symbol_putname(sym, name);
		}
	}

footer:
	ops->footer(ops, handle, opts);
}

static void do_dump_replay(struct uftrace_dump_ops *ops, struct opts *opts,
			   struct ftrace_file_handle *handle)
{
	uint64_t prev_time = 0;
	struct ftrace_task_handle *task;

	ops->header(ops, handle, opts);

	while (!read_rstack(handle, &task) && !ftrace_done) {
		struct ftrace_ret_stack *frs = task->rstack;
		struct ftrace_session *sess;
		struct symtabs *symtabs;
		struct sym *sym = NULL;
		char *name;

		if (opts->kernel) {
			if (opts->kernel_skip_out) {
				if (!task->user_stack_count &&
				    is_kernel_address(frs->addr))
					continue;
			}

			if (opts->kernel_only &&
			    !is_kernel_address(frs->addr))
				continue;
		}

		sess = find_task_session(task->tid, frs->time);
		if (sess || is_kernel_address(frs->addr)) {
			symtabs = &sess->symtabs;
			sym = find_symtabs(symtabs, frs->addr);
		}

		if (prev_time > frs->time)
			ops->inverted_time(ops, task);
		prev_time = frs->time;

		if (!fstack_check_filter(task))
			continue;

		name = symbol_getname(sym, frs->addr);
		ops->task_rstack(ops, task, name);
		symbol_putname(sym, name);
	}

	ops->footer(ops, handle, opts);
}

int command_dump(int argc, char *argv[], struct opts *opts)
{
	int ret;
	struct ftrace_file_handle handle;
	struct ftrace_kernel kern;

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		pr_err("cannot open data: %s", opts->dirname);

	if (opts->kernel && (handle.hdr.feat_mask & KERNEL)) {
		kern.output_dir = opts->dirname;
		kern.skip_out = opts->kernel_skip_out;
		if (setup_kernel_data(&kern) == 0) {
			handle.kern = &kern;
			load_kernel_symbol();
		}
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
				.kernel         = print_chrome_kernel_rstack,
				.lost           = print_chrome_kernel_lost,
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
				.kernel         = print_flame_kernel_rstack,
				.lost           = print_flame_kernel_lost,
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
				.kernel         = print_raw_kernel_rstack,
				.lost           = print_raw_kernel_lost,
				.footer         = print_raw_footer,
			},
		};

		do_dump_file(&dump.ops, opts, &handle);
	}

	if (handle.kern)
		finish_kernel_data(handle.kern);

	close_data_file(opts, &handle);

	return ret;
}
