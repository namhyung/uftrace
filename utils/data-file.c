#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "utils/filter.h"
#include "utils/symbol.h"
#include "utils/kernel.h"
#include "utils/perf.h"
#include "libmcount/mcount.h"


/**
 * read_task_file - read 'task' file from data directory
 * @sess: session link to manage sessions and tasks
 * @dirname: name of the data directory
 * @needs_session: read session info too
 * @sym_rel_addr: whether symbol address is relative
 *
 * This function read the task file in the @dirname and build task
 * (and session when @needs_session is %true) information.  Note that
 * this functions is for backward compatibility.  Recent data
 * directory contains 'task.txt' file instead.
 *
 * It returns 0 for success, -1 for error.
 */
int read_task_file(struct uftrace_session_link *sess, char *dirname,
		   bool needs_session, bool sym_rel_addr)
{
	int fd;
	char pad[8];
	char buf[1024];
	struct uftrace_msg msg;
	struct uftrace_msg_task tmsg;
	struct uftrace_msg_sess smsg;
	int ret = -1;

	snprintf(buf, sizeof(buf), "%s/task", dirname);
	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -1;

	pr_dbg("reading task file\n");
	while (read_all(fd, &msg, sizeof(msg)) == 0) {
		if (msg.magic != UFTRACE_MSG_MAGIC)
			goto out;

		switch (msg.type) {
		case UFTRACE_MSG_SESSION:
			if (read_all(fd, &smsg, sizeof(smsg)) < 0)
				goto out;
			if (read_all(fd, buf, smsg.namelen) < 0)
				goto out;
			if (smsg.namelen % 8 &&
			    read_all(fd, pad, 8 - (smsg.namelen % 8)) < 0)
				goto out;

			if (needs_session)
				create_session(sess, &smsg, dirname, buf, sym_rel_addr);
			break;

		case UFTRACE_MSG_TASK_START:
			if (read_all(fd, &tmsg, sizeof(tmsg)) < 0)
				goto out;

			create_task(sess, &tmsg, false, needs_session);
			break;

		case UFTRACE_MSG_FORK_END:
			if (read_all(fd, &tmsg, sizeof(tmsg)) < 0)
				goto out;

			create_task(sess, &tmsg, true, needs_session);
			break;

		default:
			pr_dbg("invalid contents in task file\n");
			goto out;
		}
	}
	ret = 0;

out:
	close(fd);
	return ret;
}

/**
 * read_task_txt_file - read 'task.txt' file from data directory
 * @sess: session link to manage sessions and tasks
 * @dirname: name of the data directory
 * @needs_session: read session info too
 * @sym_rel_addr: whethere symbol address is relative
 *
 * This function read the task.txt file in the @dirname and build task
 * (and session when @needs_session is %true) information.
 *
 * It returns 0 for success, -1 for error.
 */
int read_task_txt_file(struct uftrace_session_link *sess, char *dirname,
		       bool needs_session, bool sym_rel_addr)
{
	FILE *fp;
	char *fname = NULL;
	char *line = NULL;
	size_t sz = 0;
	unsigned long sec, nsec;
	struct uftrace_msg_task tmsg;
	struct uftrace_msg_sess smsg;
	struct uftrace_msg_dlopen dlop;
	char *exename, *pos;

	xasprintf(&fname, "%s/%s", dirname, "task.txt");

	fp = fopen(fname, "r");
	if (fp == NULL) {
		free(fname);
		return -errno;
	}

	pr_dbg("reading %s file\n", fname);
	while (getline(&line, &sz, fp) >= 0) {
		if (!strncmp(line, "TASK", 4)) {
			sscanf(line + 5, "timestamp=%lu.%lu tid=%d pid=%d",
			       &sec, &nsec, &tmsg.tid, &tmsg.pid);

			tmsg.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			create_task(sess, &tmsg, false, needs_session);
		}
		else if (!strncmp(line, "FORK", 4)) {
			sscanf(line + 5, "timestamp=%lu.%lu pid=%d ppid=%d",
			       &sec, &nsec, &tmsg.tid, &tmsg.pid);

			tmsg.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			create_task(sess, &tmsg, true, needs_session);
		}
		else if (!strncmp(line, "SESS", 4)) {
			if (!needs_session)
				continue;

			sscanf(line + 5, "timestamp=%lu.%lu %*[^i]id=%d sid=%s",
			       &sec, &nsec, &smsg.task.pid, (char *)&smsg.sid);

			// Get the execname
			pos = strstr(line, "exename=");
			if (pos == NULL)
				pr_err_ns("invalid task.txt format");
			exename = pos + 8 + 1;  // skip double-quote
			pos = strrchr(exename, '\"');
			if (pos)
				*pos = '\0';

			smsg.task.tid = smsg.task.pid;
			smsg.task.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			smsg.namelen = strlen(exename);

			create_session(sess, &smsg, dirname, exename, sym_rel_addr);
		}
		else if (!strncmp(line, "DLOP", 4)) {
			struct uftrace_session *s;

			if (!needs_session)
				continue;

			sscanf(line + 5, "timestamp=%lu.%lu tid=%d sid=%s base=%"PRIx64,
			       &sec, &nsec, &dlop.task.tid, (char *)&dlop.sid,
			       &dlop.base_addr);

			pos = strstr(line, "libname=");
			if (pos == NULL)
				pr_err_ns("invalid task.txt format");
			exename = pos + 8 + 1;  // skip double-quote
			pos = strrchr(exename, '\"');
			if (pos)
				*pos = '\0';

			dlop.task.pid = dlop.task.tid;
			dlop.task.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			dlop.namelen = strlen(exename);

			s = get_session_from_sid(sess, dlop.sid);
			assert(s);
			session_add_dlopen(s, dlop.task.time,
					   dlop.base_addr, exename);
		}
	}

	free(line);
	fclose(fp);
	free(fname);
	return 0;
}

/**
 * read_events_file - read 'events.txt' file from data directory
 * @dirname: name of the data directory
 *
 * This function read the events file in the @dirname and build event
 * information (for userspace).
 *
 * It returns 0 for success, -1 for error.
 */
int read_events_file(struct ftrace_file_handle *handle)
{
	FILE *fp;
	char *fname = NULL;
	char *line = NULL;
	size_t sz = 0;

	xasprintf(&fname, "%s/%s", handle->dirname, "events.txt");

	fp = fopen(fname, "r");
	if (fp == NULL) {
		/* it might hit no events, so no file is ok */
		if (errno == ENOENT)
			errno = 0;

		free(fname);
		return -errno;
	}

	pr_dbg("reading %s file\n", fname);
	while (getline(&line, &sz, fp) >= 0) {
		char provider[512];
		char event[512];
		unsigned evt_id;
		struct uftrace_event *ev;

		if (!strncmp(line, "EVENT", 5)) {
			sscanf(line + 7, "%u %[^:]:%s",
			       &evt_id, provider, event);

			ev = xmalloc(sizeof(*ev));
			ev->id = evt_id;
			ev->provider = xstrdup(provider);
			ev->event = xstrdup(event);

			list_add_tail(&ev->list, &handle->events);
		}
	}

	free(line);
	fclose(fp);
	free(fname);
	return 0;
}

static void snprint_timestamp(char *buf, size_t sz, uint64_t timestamp)
{
	snprintf(buf, sz, "%"PRIu64".%09"PRIu64,  // sec.nsec
		 timestamp / NSEC_PER_SEC, timestamp % NSEC_PER_SEC);
}

void write_task_info(const char *dirname, struct uftrace_msg_task *tmsg)
{
	FILE *fp;
	char *fname = NULL;
	char ts[128];

	xasprintf(&fname, "%s/%s", dirname, "task.txt");

	fp = fopen(fname, "a");
	if (fp == NULL)
		pr_err("cannot open %s", fname);

	snprint_timestamp(ts, sizeof(ts), tmsg->time);
	fprintf(fp, "TASK timestamp=%s tid=%d pid=%d\n",
		ts, tmsg->tid, tmsg->pid);

	fclose(fp);
	free(fname);
}

void write_fork_info(const char *dirname, struct uftrace_msg_task *tmsg)
{
	FILE *fp;
	char *fname = NULL;
	char ts[128];

	xasprintf(&fname, "%s/%s", dirname, "task.txt");

	fp = fopen(fname, "a");
	if (fp == NULL)
		pr_err("cannot open %s", fname);

	snprint_timestamp(ts, sizeof(ts), tmsg->time);
	fprintf(fp, "FORK timestamp=%s pid=%d ppid=%d\n",
		ts, tmsg->tid, tmsg->pid);

	fclose(fp);
	free(fname);
}

void write_session_info(const char *dirname, struct uftrace_msg_sess *smsg,
			const char *exename)
{
	FILE *fp;
	char *fname = NULL;
	char ts[128];

	xasprintf(&fname, "%s/%s", dirname, "task.txt");

	fp = fopen(fname, "a");
	if (fp == NULL)
		pr_err("cannot open %s", fname);

	snprint_timestamp(ts, sizeof(ts), smsg->task.time);
	fprintf(fp, "SESS timestamp=%s pid=%d sid=%s exename=\"%s\"\n",
	        ts, smsg->task.pid, smsg->sid, exename);

	fclose(fp);
	free(fname);
}

void write_dlopen_info(const char *dirname, struct uftrace_msg_dlopen *dmsg,
		       const char *libname)
{
	FILE *fp;
	char *fname = NULL;
	char ts[128];

	xasprintf(&fname, "%s/%s", dirname, "task.txt");

	fp = fopen(fname, "a");
	if (fp == NULL)
		pr_err("cannot open %s", fname);

	snprint_timestamp(ts, sizeof(ts), dmsg->task.time);
	fprintf(fp, "DLOP timestamp=%s tid=%d sid=%s base=%"PRIx64" libname=\"%s\"\n",
		ts, dmsg->task.tid, dmsg->sid, dmsg->base_addr, libname);

	fclose(fp);
	free(fname);
}

static void check_data_order(struct ftrace_file_handle *handle)
{
	union {
		struct uftrace_record s;
		uint64_t d[2];
	} data;

	handle->needs_byte_swap = (get_elf_endian() != handle->hdr.endian);
	if (handle->needs_byte_swap)
		pr_dbg("byte order is different!\n");

	/* the s.magic should be in bit[3:5] in the second word */
	data.d[1] = RECORD_MAGIC << 3;

	handle->needs_bit_swap = (data.s.magic != RECORD_MAGIC);
	if (handle->needs_bit_swap)
		pr_dbg("bitfield order is different!\n");
}

int open_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	int ret = -1;
	FILE *fp;
	char buf[PATH_MAX];
	int saved_errno = 0;

	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);

	fp = fopen(buf, "rb");
	if (fp != NULL)
		goto ok;

	/* if default dirname is failed */
	if (!strcmp(opts->dirname, UFTRACE_DIR_NAME)) {
		/* try again inside the current directory */
		fp = fopen("./info", "rb");
		if (fp != NULL) {
			opts->dirname = "./";
			goto ok;
		}

		/* retry with old default dirname */
		snprintf(buf, sizeof(buf), "%s/info", UFTRACE_DIR_OLD_NAME);
		fp = fopen(buf, "rb");
		if (fp != NULL) {
			opts->dirname = UFTRACE_DIR_OLD_NAME;
			goto ok;
		}

		saved_errno = errno;

		/* restore original file name for error reporting */
		snprintf(buf, sizeof(buf), "%s/info", opts->dirname);
	}

	/* data file loading is failed */
	pr_dbg("cannot open %s file\n", buf);
	goto out;

ok:
	handle->fp = fp;
	handle->dirname = opts->dirname;
	handle->depth = opts->depth;
	handle->nr_tasks = 0;
	handle->tasks = NULL;
	handle->time_filter = opts->threshold;
	handle->time_range = opts->range;
	handle->sessions.root  = RB_ROOT;
	handle->sessions.tasks = RB_ROOT;
	handle->sessions.first = NULL;
	handle->kernel = NULL;
	handle->nr_perf = 0;
	handle->perf = NULL;
	handle->last_perf_idx = -1;
	handle->perf_event_processed = false;
	INIT_LIST_HEAD(&handle->events);

	if (fread(&handle->hdr, sizeof(handle->hdr), 1, fp) != 1)
		pr_err("cannot read header data");

	if (memcmp(handle->hdr.magic, UFTRACE_MAGIC_STR, UFTRACE_MAGIC_LEN))
		pr_err_ns("invalid magic string found!\n");

	check_data_order(handle);

	if (handle->needs_byte_swap) {
		handle->hdr.version   = bswap_32(handle->hdr.version);
		handle->hdr.feat_mask = bswap_64(handle->hdr.feat_mask);
		handle->hdr.info_mask = bswap_64(handle->hdr.info_mask);
		handle->hdr.max_stack = bswap_16(handle->hdr.max_stack);
	}

	if (handle->hdr.version < UFTRACE_FILE_VERSION_MIN ||
	    handle->hdr.version > UFTRACE_FILE_VERSION)
		pr_err_ns("unsupported file version: %u\n", handle->hdr.version);

	if (read_uftrace_info(handle->hdr.info_mask, handle) < 0)
		pr_err_ns("cannot read uftrace header info!\n");

	fclose(fp);

	if (opts->exename == NULL)
		opts->exename = handle->info.exename;

	if (handle->hdr.feat_mask & TASK_SESSION) {
		bool sym_rel = false;
		struct uftrace_session_link *sessions = &handle->sessions;

		if (handle->hdr.feat_mask & SYM_REL_ADDR)
			sym_rel = true;

		/* read old task file first and then try task.txt file */
		if (read_task_file(sessions, opts->dirname, true, sym_rel) < 0 &&
		    read_task_txt_file(sessions, opts->dirname, true, sym_rel) < 0) {
			if (errno == ENOENT)
				saved_errno = ENODATA;
			else
				saved_errno = errno;
		}
	}

	if (handle->hdr.info_mask & ARG_SPEC) {
		if (handle->hdr.feat_mask & AUTO_ARGS) {
			setup_auto_args_str(handle->info.autoarg,
					    handle->info.autoret,
					    handle->info.autoenum);
		}

		setup_fstack_args(handle->info.argspec, handle->info.retspec,
				  handle, false, handle->info.patt_type);

		if (handle->info.auto_args_enabled) {
			char *autoarg = handle->info.autoarg;
			char *autoret = handle->info.autoret;

			if (handle->hdr.feat_mask & DEBUG_INFO) {
				if (handle->info.patt_type == PATT_REGEX)
					autoarg = autoret = ".";
				else  /* PATT_GLOB */
					autoarg = autoret = "*";
			}

			setup_fstack_args(autoarg, autoret,
					  handle, true, handle->info.patt_type);
		}
	}

	if (!(handle->hdr.feat_mask & MAX_STACK))
		handle->hdr.max_stack = MCOUNT_RSTACK_MAX;

	if (handle->hdr.feat_mask & KERNEL) {
		struct uftrace_kernel_reader *kernel;

		kernel = xzalloc(sizeof(*kernel));

		kernel->handle   = handle;
		kernel->dirname  = opts->dirname;
		kernel->skip_out = opts->kernel_skip_out;

		if (setup_kernel_data(kernel) == 0) {
			handle->kernel = kernel;
			load_kernel_symbol(opts->dirname);
		}
		else {
			free(kernel);
			handle->kernel = NULL;
		}
	}

	if (handle->hdr.feat_mask & EVENT)
		read_events_file(handle);

	if (handle->hdr.feat_mask & PERF_EVENT)
		setup_perf_data(handle);

	if (saved_errno)
		errno = saved_errno;
	else
		ret = 0;

out:
	return ret;
}

void close_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	if (opts->exename == handle->info.exename)
		opts->exename = NULL;

	if (has_kernel_data(handle->kernel)) {
		finish_kernel_data(handle->kernel);
		free(handle->kernel);
	}

	if (has_perf_data(handle))
		finish_perf_data(handle);

	delete_sessions(&handle->sessions);

	if (handle->hdr.feat_mask & AUTO_ARGS)
		finish_auto_args();

	clear_uftrace_info(&handle->info);
	reset_task_handle(handle);
}
