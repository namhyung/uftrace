#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "ftrace.h"
#include "utils/utils.h"
#include "utils/fstack.h"


char *map_file;
struct ftrace_proc_maps *proc_maps;

static void read_map_file(char *filename, struct ftrace_proc_maps **maps)
{
	FILE *fp;
	char buf[PATH_MAX];

	fp = fopen(filename, "rb");
	if (fp == NULL)
		pr_err("cannot open maps file: %s", filename);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		unsigned long start, end;
		char prot[5];
		char path[PATH_MAX];
		size_t namelen;
		struct ftrace_proc_maps *map;

		/* skip anon mappings */
		if (sscanf(buf, "%lx-%lx %s %*x %*x:%*x %*d %s\n",
			   &start, &end, prot, path) != 4)
			continue;

		/* skip non-executable mappings */
		if (prot[2] != 'x')
			continue;

		namelen = ALIGN(strlen(path) + 1, 4);

		map = xmalloc(sizeof(*map) + namelen);

		map->start = start;
		map->end = end;
		map->len = namelen;
		memcpy(map->prot, prot, 4);
		memcpy(map->libname, path, namelen);
		map->libname[strlen(path)] = '\0';

		map->next = *maps;
		*maps = map;
	}
	fclose(fp);
}

#define RECORD_MSG  "Was '%s' compiled with -pg or\n"		\
"\t-finstrument-functions flag and ran with ftrace record?\n"

int read_task_file(char *dirname)
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

			create_session(&sess, dirname, buf);

			if (map_file == NULL)
				xasprintf(&map_file, "sid-%.16s.map", sess.sid);
			break;

		case FTRACE_MSG_TID:
			if (read_all(fd, &task, sizeof(task)) < 0)
				return -1;

			create_task(&task, false);
			break;

		case FTRACE_MSG_FORK_END:
			if (read_all(fd, &task, sizeof(task)) < 0)
				return -1;

			create_task(&task, true);
			break;

		default:
			pr_log("invalid contents in task file\n");
			return -1;
		}
	}

	close(fd);
	return 0;
}

int open_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	int ret = -1;
	FILE *fp;
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);

	fp = fopen(buf, "rb");
	if (fp == NULL) {
		if (errno == ENOENT) {
			pr_log("cannot find %s file!\n", buf);

			if (opts->exename)
				pr_err(RECORD_MSG, opts->exename);
		} else {
			pr_err("cannot open %s file", buf);
		}
		goto out;
	}

	handle->fp = fp;
	handle->dirname = opts->dirname;
	handle->depth = opts->depth;
	handle->kern = NULL;

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
		if (read_task_file(opts->dirname) < 0)
			pr_err("invalid task file");
	} else
		map_file = "maps";

	snprintf(buf, sizeof(buf), "%s/%s", opts->dirname, map_file);
	read_map_file(buf, &proc_maps);

	reset_task_handle();

	ret = 0;

out:
	return ret;
}

void close_data_file(struct opts *opts, struct ftrace_file_handle *handle)
{
	struct ftrace_proc_maps *map;

	if (opts->exename == handle->info.exename)
		opts->exename = NULL;

	clear_ftrace_info(&handle->info);

	while (proc_maps) {
		map = proc_maps;
		proc_maps = map->next;

		free(map);
	}

	reset_task_handle();
}
