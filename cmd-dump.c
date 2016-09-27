#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "uftrace.h"
#include "utils/compiler.h"
#include "utils/list.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "utils/filter.h"
#include "libmcount/mcount.h"
#include "libtraceevent/kbuffer.h"


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

static void dump_raw(int argc, char *argv[], struct opts *opts,
		     struct ftrace_file_handle *handle)
{
	int i;
	uint64_t prev_time;
	uint64_t file_offset = 0;
	struct ftrace_task_handle task;

	pr_out("ftrace file header: magic         = ");
	for (i = 0; i < UFTRACE_MAGIC_LEN; i++)
		pr_out("%02x", handle->hdr.magic[i]);
	pr_out("\n");
	pr_out("ftrace file header: version       = %u\n", handle->hdr.version);
	pr_out("ftrace file header: header size   = %u\n", handle->hdr.header_size);
	pr_out("ftrace file header: endian        = %u (%s)\n",
	       handle->hdr.endian, handle->hdr.endian == 1 ? "little" : "big");
	pr_out("ftrace file header: class         = %u (%s bit)\n",
	       handle->hdr.class, handle->hdr.class == 2 ? "64" : "32");
	pr_out("ftrace file header: features      = %#"PRIx64"\n", handle->hdr.feat_mask);
	pr_out("ftrace file header: info          = %#"PRIx64"\n", handle->hdr.info_mask);
	pr_hex(&file_offset, &handle->hdr, handle->hdr.header_size);
	pr_out("\n");

	if (debug) {
		pr_out("%d tasks found\n", handle->info.nr_tid);

		/* try to read task.txt first */
		if (pr_task_txt(opts) < 0 && pr_task(opts) < 0)
			pr_red("cannot open task file\n");

		pr_out("\n");
	}

	for (i = 0; i < handle->info.nr_tid; i++) {
		int tid = handle->info.tids[i];

		if (opts->kernel && opts->kernel_only)
			continue;

		setup_task_handle(handle, &task, tid);

		if (task.fp == NULL)
			continue;

		prev_time = 0;
		file_offset = 0;
		pr_out("reading %d.dat\n", tid);
		while (!read_task_ustack(handle, &task) && !ftrace_done) {
			struct ftrace_ret_stack *frs = &task.ustack;
			struct ftrace_session *sess = find_task_session(tid, frs->time);
			struct symtabs *symtabs;
			struct sym *sym = NULL;
			char *name;

			if (sess) {
				symtabs = &sess->symtabs;
				sym = find_symtabs(symtabs, frs->addr);
			}

			name = symbol_getname(sym, frs->addr);

			if (prev_time > frs->time) {
				pr_red("\n");
				pr_red("*************************************\n");
				pr_red("* inverted time - data seems broken *\n");
				pr_red("*************************************\n");
				pr_red("\n");
			}
			prev_time = frs->time;

			pr_time(frs->time);
			pr_out("%5d: [%s] %s(%lx) depth: %u\n",
			       tid, frs->type == FTRACE_EXIT ? "exit " :
			       frs->type == FTRACE_ENTRY ? "entry" : "lost ",
			       name, (unsigned long)frs->addr, frs->depth);
			pr_hex(&file_offset, frs, sizeof(*frs));

			if (frs->more) {
				if (frs->type == FTRACE_ENTRY) {
					pr_time(frs->time);
					pr_out("%5d: [%s] length = %d\n", tid, "args ",
							task.args.len);
					pr_args(&task.args);
					pr_hex(&file_offset, task.args.data, task.args.len);
				} else if (frs->type == FTRACE_EXIT) {
					pr_time(frs->time);
					pr_out("%5d: [%s] length = %d\n", tid, "retval",
							task.args.len);
					pr_retval(&task.args);
					pr_hex(&file_offset, task.args.data, task.args.len);
				} else
					abort();
			}

			/* force re-read in read_task_ustack() */
			task.valid = false;
			symbol_putname(sym, name);
		}
	}

	if (!opts->kernel || handle->kern == NULL || ftrace_done)
		return;

	pr_out("\n");
	for (i = 0; i < handle->kern->nr_cpus; i++) {
		struct ftrace_kernel *kernel = handle->kern;
		struct mcount_ret_stack *mrs = &kernel->rstacks[i];
		struct kbuffer *kbuf = kernel->kbufs[i];
		int offset, size;
		struct sym *sym;
		char *name;

		file_offset = 0;
		offset = kbuffer_curr_offset(kbuf);
		pr_out("reading kernel-cpu%d.dat\n", i);
		while (!read_kernel_cpu_data(kernel, i) && !ftrace_done) {
			int losts = kernel->missed_events[i];

			sym = find_symtabs(NULL, mrs->child_ip);
			name = symbol_getname(sym, mrs->child_ip);

			if (losts) {
				pr_time(mrs->end_time ?: mrs->start_time);
				pr_red("%5d: [%s ]: %d events\n",
				       mrs->tid, "lost", losts);
				kernel->missed_events[i] = 0;
			}

			pr_time(mrs->end_time ?: mrs->start_time);
			pr_out("%5d: [%s] %s(%lx) depth: %u\n",
			       mrs->tid, mrs->end_time ? "exit " : "entry",
			       name, mrs->child_ip, mrs->depth);

			if (debug) {
				/* this is only needed for hex dump */
				void *data = kbuffer_read_at_offset(kbuf, offset, NULL);

				size = kbuffer_event_size(kbuf);
				file_offset = kernel->offsets[i] + kbuffer_curr_offset(kbuf);
				pr_hex(&file_offset, data, size);

				if (kbuffer_next_event(kbuf, NULL))
					offset += size + 4;  // 4 = event header size
				else
					offset = 0;
			}

			symbol_putname(sym, name);
		}
	}
}

static void print_ustack_chrome_trace(struct ftrace_task_handle *task,
				      struct ftrace_ret_stack *frs,
				      int tid, const char* name)
{
	char ph;
	char spec_buf[1024];
	enum argspec_string_bits str_mode = NEEDS_ESCAPE;

	if (frs->type == FTRACE_ENTRY) {
		ph = 'B';
		pr_out("{\"ts\":%lu,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
			frs->time / 1000, ph, tid, name);
		if (frs->more) {
			str_mode |= HAS_MORE;
			get_argspec_string(task, spec_buf, sizeof(spec_buf), str_mode);
			pr_out(",\"args\":{\"arguments\":\"%s\"}}",
				spec_buf);
		} else
			pr_out("}");
	} else if (frs->type == FTRACE_EXIT) {
		ph = 'E';
		pr_out("{\"ts\":%lu,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
			frs->time / 1000, ph, tid, name);
		if (frs->more) {
			str_mode |= IS_RETVAL | HAS_MORE;
			get_argspec_string(task, spec_buf, sizeof(spec_buf), str_mode);
			pr_out(",\"args\":{\"retval\":\"%s\"}}",
				spec_buf);
		} else
			pr_out("}");
	} else
		abort();
}

static void print_kstack_chrome_trace(struct ftrace_task_handle *task,
				      struct mcount_ret_stack *mrs,
				      const char* name)
{
	char ph;
	uint64_t timestamp = mrs->end_time ?: mrs->start_time;
	enum ftrace_ret_stack_type rstack_type;

	if (mrs->end_time)
		rstack_type = FTRACE_EXIT;
	else
		rstack_type = FTRACE_ENTRY;

	/*
	 * We may add a category info with "cat" field later to distinguish that
	 * this record is from kernel function.
	 */
	if (rstack_type == FTRACE_ENTRY) {
		ph = 'B';
		pr_out("{\"ts\":%lu,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
			timestamp / 1000, ph, mrs->tid, name);
		/* kernel trace data doesn't have more field */
		pr_out("}");
	} else if (rstack_type == FTRACE_EXIT) {
		ph = 'E';
		pr_out("{\"ts\":%lu,\"ph\":\"%c\",\"pid\":%d,\"name\":\"%s\"",
			timestamp / 1000, ph, mrs->tid, name);
		/* kernel trace data doesn't have more field */
		pr_out("}");
	} else
		abort();
}

static void dump_chrome_trace(int argc, char *argv[], struct opts *opts,
			      struct ftrace_file_handle *handle)
{
	int i;
	struct ftrace_task_handle task;
	char buf[PATH_MAX];
	struct stat statbuf;
	unsigned lost_event_cnt = 0;

	/* read recorded date and time */
	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);
	if (stat(buf, &statbuf) < 0)
		return;

	ctime_r(&statbuf.st_mtime, buf);
	buf[strlen(buf) - 1] = '\0';

	pr_out("{\"traceEvents\":[\n");
	for (i = 0; i < handle->info.nr_tid; i++) {
		int tid = handle->info.tids[i];

		setup_task_handle(handle, &task, tid);

		if (task.fp == NULL)
			continue;

		while (!read_task_ustack(handle, &task) && !ftrace_done) {
			struct ftrace_ret_stack *frs = &task.ustack;
			struct ftrace_session *sess = find_task_session(tid, frs->time);
			struct symtabs *symtabs;
			struct sym *sym = NULL;
			char *name;
			static bool last_comma = false;

			if (sess) {
				symtabs = &sess->symtabs;
				sym = find_symtabs(symtabs, frs->addr);
			}

			name = symbol_getname(sym, frs->addr);

			if (last_comma)
				pr_out(",\n");

			print_ustack_chrome_trace(&task, frs, tid, name);

			last_comma = true;

			/* force re-read in read_task_ustack() */
			task.valid = false;
			symbol_putname(sym, name);
		}
	}

	if (!opts->kernel || handle->kern == NULL || ftrace_done)
		goto json_footer;

	pr_out(",\n");
	for (i = 0; i < handle->kern->nr_cpus; i++) {
		struct ftrace_kernel *kernel = handle->kern;
		struct mcount_ret_stack *mrs = &kernel->rstacks[i];
		struct sym *sym;
		char *name;

		while (!read_kernel_cpu_data(kernel, i) && !ftrace_done) {
			static bool last_comma = false;
			int losts = kernel->missed_events[i];

			sym = find_symtabs(NULL, mrs->child_ip);
			name = symbol_getname(sym, mrs->child_ip);

			if (last_comma)
				pr_out(",\n");

			/* it just counts the number of LOST events occured */
			if (losts) {
				kernel->missed_events[i] = 0;
				lost_event_cnt++;
			}

			print_kstack_chrome_trace(&task, mrs, name);
			last_comma = true;

			symbol_putname(sym, name);
		}
	}

json_footer:
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
	if (lost_event_cnt) {
		pr_warn("Some of function trace records are lost. "
			"(%d times shown)\n", lost_event_cnt);
		pr_warn("The output json format may not show the correct view "
			"in chrome browser.\n");
	}
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
		if (setup_kernel_data(&kern) == 0) {
			handle.kern = &kern;
			load_kernel_symbol();
		}
	}

	setup_task_filter(opts->tid, &handle);

	if (opts->chrome_trace)
		dump_chrome_trace(argc, argv, opts, &handle);
	else
		dump_raw(argc, argv, opts, &handle);

	close_data_file(opts, &handle);

	return ret;
}
