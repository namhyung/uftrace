#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libmcount/mcount.h"
#include "uftrace.h"
#include "utils/event.h"
#include "utils/filter.h"
#include "utils/fstack.h"
#include "utils/kernel.h"
#include "utils/perf.h"
#include "utils/symbol.h"
#include "utils/utils.h"

/**
 * read_task_file - read 'task' file from data directory
 * @sess: session link to manage sessions and tasks
 * @dirname: name of the data directory
 * @needs_symtab: read session symbol tables too
 * @sym_rel_addr: whether symbol address is relative
 * @needs_srcline: whether debug info loading is needed
 *
 * This function read the task file in the @dirname and build task
 * (and session when @needs_session is %true) information.  Note that
 * this functions is for backward compatibility.  Recent data
 * directory contains 'task.txt' file instead.
 *
 * It returns 0 for success, -1 for error.
 */
int read_task_file(struct uftrace_session_link *sess, char *dirname, bool needs_symtab,
		   bool sym_rel_addr, bool needs_srcline)
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
			if (smsg.namelen % 8 && read_all(fd, pad, 8 - (smsg.namelen % 8)) < 0)
				goto out;

			create_session(sess, &smsg, dirname, dirname, buf, sym_rel_addr,
				       needs_symtab, needs_srcline);
			break;

		case UFTRACE_MSG_TASK_START:
			if (read_all(fd, &tmsg, sizeof(tmsg)) < 0)
				goto out;

			create_task(sess, &tmsg, false);
			break;

		case UFTRACE_MSG_FORK_END:
			if (read_all(fd, &tmsg, sizeof(tmsg)) < 0)
				goto out;

			create_task(sess, &tmsg, true);
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
 * @needs_symtab: read session symbol tables too
 * @sym_rel_addr: whethere symbol address is relative
 * @needs_srcline: whether debug info loading is needed
 *
 * This function read the task.txt file in the @dirname and build task
 * (and session when @needs_session is %true) information.
 *
 * It returns 0 for success, -1 for error.
 */
int read_task_txt_file(struct uftrace_session_link *sess, char *dirname, char *symdir,
		       bool needs_symtab, bool sym_rel_addr, bool needs_srcline)
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
	int ret = -1;
	int num;

	xasprintf(&fname, "%s/%s", dirname, "task.txt");

	fp = fopen(fname, "r");
	if (fp == NULL) {
		free(fname);
		return -errno;
	}

	pr_dbg("reading %s file\n", fname);
	while (getline(&line, &sz, fp) >= 0) {
		if (!strncmp(line, "TASK", 4)) {
			num = sscanf(line + 5, "timestamp=%lu.%lu tid=%d pid=%d", &sec, &nsec,
				     &tmsg.tid, &tmsg.pid);
			if (num != 4)
				goto out;

			tmsg.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			create_task(sess, &tmsg, false);
		}
		else if (!strncmp(line, "FORK", 4)) {
			num = sscanf(line + 5, "timestamp=%lu.%lu pid=%d ppid=%d", &sec, &nsec,
				     &tmsg.tid, &tmsg.pid);
			if (num != 4)
				goto out;

			tmsg.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			create_task(sess, &tmsg, true);
		}
		else if (!strncmp(line, "SESS", 4)) {
			num = sscanf(line + 5, "timestamp=%lu.%lu %*[^i]id=%d sid=%s", &sec, &nsec,
				     &smsg.task.pid, (char *)&smsg.sid);
			if (num != 4)
				goto out;

			// Get the execname
			pos = strstr(line, "exename=");
			if (pos == NULL)
				goto out;

			exename = pos + 8 + 1; // skip double-quote
			pos = strrchr(exename, '\"');
			if (pos)
				*pos = '\0';

			smsg.task.tid = smsg.task.pid;
			smsg.task.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			smsg.namelen = strlen(exename);

			create_session(sess, &smsg, dirname, symdir, exename, sym_rel_addr,
				       needs_symtab, needs_srcline);
		}
		else if (!strncmp(line, "DLOP", 4)) {
			struct uftrace_session *s;

			if (!needs_symtab)
				continue;

			num = sscanf(line + 5, "timestamp=%lu.%lu tid=%d sid=%s base=%" PRIx64,
				     &sec, &nsec, &dlop.task.tid, (char *)&dlop.sid,
				     &dlop.base_addr);
			if (num != 5)
				goto out;

			pos = strstr(line, "libname=");
			if (pos == NULL)
				goto out;

			exename = pos + 8 + 1; // skip double-quote
			pos = strrchr(exename, '\"');
			if (pos)
				*pos = '\0';

			dlop.task.pid = dlop.task.tid;
			dlop.task.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			dlop.namelen = strlen(exename);

			s = get_session_from_sid(sess, dlop.sid);
			ASSERT(s);
			session_add_dlopen(s, dlop.task.time, dlop.base_addr, exename,
					   needs_srcline);
		}
	}
	ret = 0;

out:
	free(line);
	fclose(fp);
	free(fname);

	if (ret != 0)
		errno = EINVAL;

	return ret;
}

static void snprint_timestamp(char *buf, size_t sz, uint64_t timestamp)
{
	snprintf(buf, sz, "%" PRIu64 ".%09" PRIu64, // sec.nsec
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
	fprintf(fp, "TASK timestamp=%s tid=%d pid=%d\n", ts, tmsg->tid, tmsg->pid);

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
	fprintf(fp, "FORK timestamp=%s pid=%d ppid=%d\n", ts, tmsg->tid, tmsg->pid);

	fclose(fp);
	free(fname);
}

void write_session_info(const char *dirname, struct uftrace_msg_sess *smsg, const char *exename)
{
	FILE *fp;
	char *fname = NULL;
	char ts[128];

	xasprintf(&fname, "%s/%s", dirname, "task.txt");

	fp = fopen(fname, "a");
	if (fp == NULL)
		pr_err("cannot open %s", fname);

	snprint_timestamp(ts, sizeof(ts), smsg->task.time);
	fprintf(fp, "SESS timestamp=%s pid=%d sid=%.*s exename=\"%s\"\n", ts, smsg->task.pid,
		SESSION_ID_LEN, smsg->sid, exename);

	fclose(fp);
	free(fname);
}

void write_dlopen_info(const char *dirname, struct uftrace_msg_dlopen *dmsg, const char *libname)
{
	FILE *fp;
	char *fname = NULL;
	char ts[128];

	xasprintf(&fname, "%s/%s", dirname, "task.txt");

	fp = fopen(fname, "a");
	if (fp == NULL)
		pr_err("cannot open %s", fname);

	snprint_timestamp(ts, sizeof(ts), dmsg->task.time);
	fprintf(fp, "DLOP timestamp=%s tid=%d sid=%.*s base=%" PRIx64 " libname=\"%s\"\n", ts,
		dmsg->task.tid, SESSION_ID_LEN, dmsg->sid, dmsg->base_addr, libname);

	fclose(fp);
	free(fname);
}

static void check_data_order(struct uftrace_data *handle)
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

static bool check_data_file(struct uftrace_data *handle, const char *pattern)
{
	glob_t g;
	size_t i;
	bool found = false;

	if (glob(pattern, 0, NULL, &g) == GLOB_ERR) {
		pr_dbg("glob matching failed: %s: %m\n", pattern);
		return false;
	}

	for (i = 0; i < g.gl_pathc; i++) {
		struct stat stbuf;

		if (stat(g.gl_pathv[i], &stbuf) == 0 && stbuf.st_size) {
			found = true;
			break;
		}
	}

	globfree(&g);
	return found;
}

bool data_is_lp64(struct uftrace_data *handle)
{
	return handle->hdr.elf_class == ELFCLASS64;
}

int open_info_file(struct uftrace_opts *opts, struct uftrace_data *handle)
{
	FILE *fp;
	char buf[PATH_MAX];
	int saved_errno = 0;
	struct stat stbuf;

	memset(handle, 0, sizeof(*handle));

	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);

	fp = fopen(buf, "rb");
	if (fp != NULL)
		goto ok;

	saved_errno = errno;
	/* provide a better error code for empty/invalid directories */
	if (stat(opts->dirname, &stbuf) == 0)
		saved_errno = EINVAL;

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

	return -saved_errno;
ok:
	saved_errno = 0;
	handle->fp = fp;
	handle->dirname = opts->dirname;
	handle->depth = opts->depth;
	handle->time_filter = opts->threshold;
	handle->size_filter = opts->size_filter;
	handle->time_range = opts->range;
	handle->sessions.root = RB_ROOT;
	handle->sessions.tasks = RB_ROOT;
	handle->last_perf_idx = -1;
	INIT_LIST_HEAD(&handle->events);

	if (fread(&handle->hdr, sizeof(handle->hdr), 1, fp) != 1)
		pr_err("cannot read header data");

	if (memcmp(handle->hdr.magic, UFTRACE_MAGIC_STR, UFTRACE_MAGIC_LEN))
		pr_err_ns("invalid magic string found!\n");

	check_data_order(handle);

	if (handle->needs_byte_swap) {
		handle->hdr.version = bswap_32(handle->hdr.version);
		handle->hdr.feat_mask = bswap_64(handle->hdr.feat_mask);
		handle->hdr.info_mask = bswap_64(handle->hdr.info_mask);
		handle->hdr.max_stack = bswap_16(handle->hdr.max_stack);
	}

	if (handle->hdr.version < UFTRACE_FILE_VERSION_MIN ||
	    handle->hdr.version > UFTRACE_FILE_VERSION)
		pr_err_ns("unsupported file version: %u\n", handle->hdr.version);

	if (read_uftrace_info(handle->hdr.info_mask, handle) < 0)
		pr_err_ns("cannot read uftrace header info!\n");

	if (opts->exename == NULL)
		opts->exename = handle->info.exename;

	fclose(fp);
	return 0;
}

int open_data_file(struct uftrace_opts *opts, struct uftrace_data *handle)
{
	int ret;
	char buf[PATH_MAX];
	int saved_errno = 0;

	ret = open_info_file(opts, handle);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	if (handle->info.nr_tid == 0) {
		errno = ENODATA;
		return -1;
	}

	if (handle->hdr.feat_mask & TASK_SESSION) {
		bool sym_rel = false;
		struct uftrace_session_link *sessions = &handle->sessions;
		int i;

		if (handle->hdr.feat_mask & SYM_REL_ADDR)
			sym_rel = true;

		/* read old task file first and then try task.txt file */
		if (read_task_file(sessions, opts->dirname, true, sym_rel, opts->srcline) < 0 &&
		    read_task_txt_file(sessions, opts->dirname, opts->with_syms ?: opts->dirname,
				       true, sym_rel,
				       opts->srcline | (opts->loc_filter != NULL)) < 0) {
			if (errno == ENOENT)
				saved_errno = ENODATA;
			else
				saved_errno = errno;

			goto out;
		}

		if (sessions->first == NULL) {
			saved_errno = EINVAL;
			goto out;
		}

		for (i = 0; i < handle->info.nr_tid; i++) {
			int tid = handle->info.tids[i];

			if (find_task(sessions, tid))
				break;
		}

		if (i == handle->info.nr_tid) {
			saved_errno = ENODATA;
			goto out;
		}
	}

	if (handle->hdr.info_mask & ARG_SPEC) {
		struct uftrace_filter_setting setting = {
			.ptype = handle->info.patt_type,
			.allow_kernel = true,
			.auto_args = false,
			.lp64 = data_is_lp64(handle),
			.arch = handle->arch,
		};

		if (handle->hdr.feat_mask & AUTO_ARGS) {
			setup_auto_args_str(handle->info.autoarg, handle->info.autoret,
					    handle->info.autoenum, &setting);
		}

		setup_fstack_args(handle->info.argspec, handle->info.retspec, handle, &setting);

		if (handle->info.auto_args_enabled) {
			char *autoarg = handle->info.autoarg;
			char *autoret = handle->info.autoret;

			if (handle->hdr.feat_mask & DEBUG_INFO) {
				if (handle->info.patt_type == PATT_REGEX)
					autoarg = autoret = ".";
				else /* PATT_GLOB */
					autoarg = autoret = "*";
			}

			setting.auto_args = true;
			setup_fstack_args(autoarg, autoret, handle, &setting);
		}
	}

	if (!(handle->hdr.feat_mask & MAX_STACK))
		handle->hdr.max_stack = MCOUNT_RSTACK_MAX;

	if (handle->hdr.feat_mask & KERNEL) {
		struct uftrace_kernel_reader *kernel;

		kernel = xzalloc(sizeof(*kernel));

		kernel->handle = handle;
		kernel->dirname = opts->dirname;
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

	setup_extern_data(handle, opts);

	/* check there are data files actually */
	snprintf(buf, sizeof(buf), "%s/[0-9]*.dat", opts->dirname);
	if (!check_data_file(handle, buf)) {
		if (handle->kernel) {
			snprintf(buf, sizeof(buf), "%s/kernel-*.dat", opts->dirname);

			if (check_data_file(handle, buf))
				goto out;
		}

		if (saved_errno == 0)
			saved_errno = ENODATA;
	}

out:
	if (saved_errno) {
		close_data_file(opts, handle);
		errno = saved_errno;
		ret = -1;
	}
	else
		ret = 0;

	return ret;
}

void __close_data_file(struct uftrace_opts *opts, struct uftrace_data *handle, bool unload_modules)
{
	if (opts->exename == handle->info.exename)
		opts->exename = NULL;

	if (has_kernel_data(handle->kernel)) {
		finish_kernel_data(handle->kernel);
		free(handle->kernel);
	}

	finish_events_file(handle);

	if (has_perf_data(handle))
		finish_perf_data(handle);

	if (has_extern_data(handle))
		finish_extern_data(handle);

	delete_sessions(&handle->sessions);

	if (unload_modules)
		unload_module_symtabs();

	if (handle->hdr.feat_mask & AUTO_ARGS)
		finish_auto_args();

	clear_uftrace_info(&handle->info);
	reset_task_handle(handle);
}

#ifdef UNIT_TEST
#define TEST_SESSION_ID "test-session-id"
#define TEST_EXIT_STATUS 37
#define TEST_INFO_MASK (EXE_NAME | EXIT_STATUS | TASKINFO)

static int create_test_data(struct uftrace_opts *opts)
{
	struct uftrace_msg_sess sess_msg = {
		.task = { .time = 100, .pid = 10 },
		.sid = TEST_SESSION_ID,
	};
	struct uftrace_msg_task task_msg = {
		.time = 200,
		.pid = 10,
		.tid = 10,
	};
	struct uftrace_msg_task fork_msg = {
		.time = 300,
		.pid = 10,
		.tid = 20,
	};
	struct uftrace_msg_dlopen dlopen_msg = {
		.task = { .time = 400, .tid = 20 },
		.sid = TEST_SESSION_ID,
		.base_addr = 0x123000,
	};
	struct uftrace_record parent_funcs[] = {
		/* ignore symbols for now */
		{
			.time = 201,
			.type = UFTRACE_ENTRY,
			.magic = RECORD_MAGIC,
			.depth = 0,
		},
		{
			.time = 202,
			.type = UFTRACE_ENTRY,
			.magic = RECORD_MAGIC,
			.depth = 1,
		},
		{
			.time = 203,
			.type = UFTRACE_ENTRY,
			.magic = RECORD_MAGIC,
			.depth = 2,
		},
		{
			.time = 204,
			.type = UFTRACE_ENTRY,
			.magic = RECORD_MAGIC,
			.depth = 3,
		},
		{
			.time = 205,
			.type = UFTRACE_EXIT,
			.magic = RECORD_MAGIC,
			.depth = 3,
		},
		{
			.time = 206,
			.type = UFTRACE_EXIT,
			.magic = RECORD_MAGIC,
			.depth = 2,
		},
		{
			.time = 207,
			.type = UFTRACE_EXIT,
			.magic = RECORD_MAGIC,
			.depth = 1,
		},
		{
			.time = 208,
			.type = UFTRACE_EXIT,
			.magic = RECORD_MAGIC,
			.depth = 0,
		},
	};
	struct uftrace_record child_funcs[] = {
		{
			.time = 301,
			.type = UFTRACE_ENTRY,
			.magic = RECORD_MAGIC,
			.depth = 0,
		},
		{
			.time = 302,
			.type = UFTRACE_ENTRY,
			.magic = RECORD_MAGIC,
			.depth = 1,
		},
		{
			.time = 303,
			.type = UFTRACE_EXIT,
			.magic = RECORD_MAGIC,
			.depth = 1,
		},
		{
			.time = 304,
			.type = UFTRACE_EXIT,
			.magic = RECORD_MAGIC,
			.depth = 0,
		},
	};

	char *filename = NULL;
	FILE *fp;

	if (create_directory(opts->dirname) < 0)
		return -1;

	write_session_info(opts->dirname, &sess_msg, opts->exename);
	write_task_info(opts->dirname, &task_msg);
	write_fork_info(opts->dirname, &fork_msg);
	write_dlopen_info(opts->dirname, &dlopen_msg, "libnothing.so");

	/* create_session() requires a map file even if it's empty */
	TEST_GE(asprintf(&filename, "%s/sid-%.*s.map", opts->dirname, SESSION_ID_LEN,
			 TEST_SESSION_ID),
		0);
	creat(filename, 0644);
	free(filename);

	TEST_GE(asprintf(&filename, "%s/%d.dat", opts->dirname, task_msg.pid), 0);
	fp = fopen(filename, "w");
	fwrite(parent_funcs, sizeof(*parent_funcs), ARRAY_SIZE(parent_funcs), fp);
	fclose(fp);
	free(filename);

	TEST_GE(asprintf(&filename, "%s/%d.dat", opts->dirname, fork_msg.tid), 0);
	fp = fopen(filename, "w");
	fwrite(child_funcs, sizeof(*child_funcs), ARRAY_SIZE(child_funcs), fp);
	fclose(fp);
	free(filename);

	fill_file_header(opts, TEST_EXIT_STATUS, NULL, (char *)"1ms");

	return 0;
}

static int remove_test_data(struct uftrace_opts *opts)
{
	return remove_directory(opts->dirname);
}

int prepare_test_data(struct uftrace_opts *opts, struct uftrace_data *handle)
{
	FILE *dev_null;

	if (create_test_data(opts) < 0)
		return -1;

	dev_null = fopen("/dev/null", "w+");
	if (dev_null == NULL) {
		remove_test_data(opts);
		return -1;
	}

	/* prevent any output message during the test */
	outfp = dev_null;

	open_data_file(opts, handle);
	fstack_setup_filters(opts, handle);

	if (handle->sessions.first == NULL) {
		close_data_file(opts, handle);
		remove_test_data(opts);
		return -1;
	}
	handle->sessions.first->sym_info.kernel_base = -1ULL;

	return 0;
}

int release_test_data(struct uftrace_opts *opts, struct uftrace_data *handle)
{
	FILE *dev_null = outfp;

	close_data_file(opts, handle);

	outfp = stdout;
	fclose(dev_null);

	if (remove_test_data(opts) < 0) {
		pr_dbg("failed to remove data\n");
		return -1;
	}
	return 0;
}

TEST_CASE(data_basic)
{
	struct uftrace_opts opts = {
		.dirname = "data-test",
		.exename = read_exename(),
		.max_stack = 10,
	};
	struct uftrace_data handle;
	struct uftrace_session *s;
	struct uftrace_task *t;

	pr_dbg("create test data\n");
	if (create_test_data(&opts) < 0)
		return TEST_SKIP;

	open_data_file(&opts, &handle);

	pr_dbg("verify header info\n");
	TEST_NE(handle.hdr.feat_mask & TASK_SESSION, 0);
	TEST_EQ(handle.hdr.info_mask & TEST_INFO_MASK, TEST_INFO_MASK);
	TEST_EQ(handle.info.exit_status, TEST_EXIT_STATUS);
	TEST_STREQ(handle.info.exename, opts.exename);

	pr_dbg("verify session info\n");
	TEST_NE(handle.sessions.first, NULL);
	s = handle.sessions.first;

	TEST_EQ(s->start_time, 100);
	TEST_EQ(s->pid, 10);
	TEST_STREQ(s->sid, TEST_SESSION_ID);
	TEST_STREQ(s->exename, opts.exename);
	TEST_EQ(list_empty(&s->dlopen_libs), false);

	pr_dbg("verify task info\n");
	TEST_NE(handle.sessions.first_task, NULL);
	t = handle.sessions.first_task;

	TEST_EQ(t->tid, 10);
	TEST_EQ(t->tid, t->pid);
	TEST_STREQ(t->comm, uftrace_basename(opts.exename));

	close_data_file(&opts, &handle);

	pr_dbg("delete test data\n");
	if (remove_test_data(&opts) < 0)
		pr_dbg("failed to remove data\n");

	return TEST_OK;
}
#endif /* UNIT_TEST */
