#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/fstack.h"


/**
 * read_task_file - read 'task' file from data directory
 * @dirname: name of the data directory
 * @needs_session: read session info too
 *
 * This function read the task file in the @dirname and build task
 * (and session when @needs_session is %true) information.  Note that
 * this functions is for backward compatibility.  Recent data
 * directory contains 'task.txt' file instead.
 *
 * It returns 0 for success, -1 for error.
 */
int read_task_file(char *dirname, bool needs_session)
{
	int fd;
	char pad[8];
	char buf[1024];
	struct ftrace_msg msg;
	struct ftrace_msg_task task;
	struct ftrace_msg_sess sess;

	snprintf(buf, sizeof(buf), "%s/task", dirname);
	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -1;

	pr_dbg("reading task file\n");
	while (read_all(fd, &msg, sizeof(msg)) == 0) {
		if (msg.magic != FTRACE_MSG_MAGIC)
			return -1;

		switch (msg.type) {
		case FTRACE_MSG_SESSION:
			if (read_all(fd, &sess, sizeof(sess)) < 0)
				return -1;
			if (read_all(fd, buf, sess.namelen) < 0)
				return -1;
			if (sess.namelen % 8 &&
			    read_all(fd, pad, 8 - (sess.namelen % 8)) < 0)
				return -1;

			if (needs_session)
				create_session(&sess, dirname, buf);
			break;

		case FTRACE_MSG_TID:
			if (read_all(fd, &task, sizeof(task)) < 0)
				return -1;

			create_task(&task, false, needs_session);
			break;

		case FTRACE_MSG_FORK_END:
			if (read_all(fd, &task, sizeof(task)) < 0)
				return -1;

			create_task(&task, true, needs_session);
			break;

		default:
			pr_log("invalid contents in task file\n");
			return -1;
		}
	}

	close(fd);
	return 0;
}

/**
 * read_task_txt_file - read 'task.txt' file from data directory
 * @dirname: name of the data directory
 * @needs_session: read session info too
 *
 * This function read the task.txt file in the @dirname and build task
 * (and session when @needs_session is %true) information.
 *
 * It returns 0 for success, -1 for error.
 */
int read_task_txt_file(char *dirname, bool needs_session)
{
	FILE *fp;
	char *fname = NULL;
	char *line = NULL;
	size_t sz = 0;
	long sec, nsec;
	struct ftrace_msg_task task;
	struct ftrace_msg_sess sess;
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
			       &sec, &nsec, &task.tid, &task.pid);

			task.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			create_task(&task, false, needs_session);
		}
		else if (!strncmp(line, "FORK", 4)) {
			sscanf(line + 5, "timestamp=%lu.%lu pid=%d ppid=%d",
			       &sec, &nsec, &task.tid, &task.pid);

			task.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			create_task(&task, true, needs_session);
		}
		else if (!strncmp(line, "SESS", 4)) {
			if (!needs_session)
				continue;

			sscanf(line + 5, "timestamp=%lu.%lu tid=%d sid=%s",
			       &sec, &nsec, &sess.task.tid, (char *)&sess.sid);

			pos = strstr(line, "exename=");
			if (pos == NULL)
				pr_err_ns("invalid task.txt format");
			exename = pos + 8 + 1;  // skip double-quote
			pos = strrchr(exename, '\"');
			if (pos)
				*pos = '\0';

			sess.task.pid = sess.task.tid;
			sess.task.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			sess.namelen = strlen(exename);

			create_session(&sess, dirname, exename);
		}
	}

	fclose(fp);
	free(fname);
	return 0;
}

static void snprint_timestamp(char *buf, size_t sz, uint64_t timestamp)
{
	snprintf(buf, sz, "%"PRIu64".%09"PRIu64,  // sec.nsec
		 timestamp / NSEC_PER_SEC, timestamp % NSEC_PER_SEC);
}

void write_task_info(const char *dirname, struct ftrace_msg_task *tmsg)
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

void write_fork_info(const char *dirname, struct ftrace_msg_task *tmsg)
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

void write_session_info(const char *dirname, struct ftrace_msg_sess *smsg,
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
	fprintf(fp, "SESS timestamp=%s tid=%d sid=%s exename=\"%s\"\n",
		ts, smsg->task.tid, smsg->sid, exename);

	fclose(fp);
	free(fname);
}

#define RECORD_MSG  "Was '%s' compiled with -pg or\n"		\
"\t-finstrument-functions flag and ran with ftrace record?\n"

int open_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	int ret = -1;
	FILE *fp;
	char buf[PATH_MAX];
	bool again = false;

	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);

retry:
	fp = fopen(buf, "rb");
	if (fp == NULL) {
		if (again) {
			/* restore original file name for error reporting */
			snprintf(buf, sizeof(buf), "%s/info", opts->dirname);
		}

		if (errno == ENOENT) {
			if (!again && !strcmp(opts->dirname, FTRACE_DIR_NAME)) {
				/* retry with old default dirname */
				snprintf(buf, sizeof(buf), "%s/info",
					FTRACE_DIR_OLD_NAME);

				again = true;
				goto retry;
			}

			pr_log("cannot find %s file!\n", buf);

			if (opts->exename)
				pr_err(RECORD_MSG, opts->exename);
		} else {
			pr_err("cannot open %s file", buf);
		}
		goto out;
	}

	if (again) {
		/* found data in old dirname, rename it */
		opts->dirname = FTRACE_DIR_OLD_NAME;
	}

	handle->fp = fp;
	handle->dirname = opts->dirname;
	handle->depth = opts->depth;
	handle->kern = NULL;
	handle->nr_tasks = 0;
	handle->tasks = NULL;

	if (fread(&handle->hdr, sizeof(handle->hdr), 1, fp) != 1)
		pr_err("cannot read header data");

	if (memcmp(handle->hdr.magic, FTRACE_MAGIC_STR, FTRACE_MAGIC_LEN))
		pr_err("invalid magic string found!");

	if (handle->hdr.version < FTRACE_FILE_VERSION_MIN ||
	    handle->hdr.version > FTRACE_FILE_VERSION)
		pr_err("unsupported file version: %u", handle->hdr.version);

	if (read_ftrace_info(handle->hdr.info_mask, handle) < 0)
		pr_err("cannot read ftrace header info!");

	fclose(fp);

	if (opts->exename == NULL)
		opts->exename = handle->info.exename;

	if (handle->hdr.feat_mask & TASK_SESSION) {
		// read task.txt first and then try old task file
		if (read_task_txt_file(opts->dirname, true) < 0 &&
		    read_task_file(opts->dirname, true) < 0)
			pr_err("invalid task file");
	}

	if (handle->hdr.feat_mask & (ARGUMENT | RETVAL))
		setup_fstack_args(handle->info.argspec);

	ret = 0;

out:
	return ret;
}

void close_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	if (opts->exename == handle->info.exename)
		opts->exename = NULL;

	clear_ftrace_info(&handle->info);
	reset_task_handle(handle);
}
