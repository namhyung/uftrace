/**
 * external data support
 *
 * An external data comes with a text file containing following info:
 *
 *  #        TIMESTAMP MESSAGE
 *  16414531.193431732 this is random text
 *  16414631.732980320 next message
 *  16414706.137491843 3rd message
 *  ...
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "fstack"
#define PR_DOMAIN DBG_FSTACK

#include "uftrace.h"
#include "utils/fstack.h"
#include "utils/utils.h"

#define DEFAULT_FILENAME "extern.dat"

int setup_extern_data(struct uftrace_data *handle, struct uftrace_opts *opts)
{
	struct uftrace_extern_reader *extn;
	char *filename;
	FILE *fp;

	handle->extn = NULL;

	filename = opts->extern_data;
	if (filename == NULL)
		xasprintf(&filename, "%s/%s", opts->dirname, DEFAULT_FILENAME);

	fp = fopen(filename, "r");

	if (opts->extern_data == NULL)
		free(filename);

	if (fp == NULL) {
		if (errno == ENOENT)
			return 0;

		/* report other error code */
		pr_dbg("opening external data filed: %m\n");
		return -1;
	}

	extn = xzalloc(sizeof(*extn));
	extn->fp = fp;

	handle->extn = extn;
	return 1;
}

int read_extern_data(struct uftrace_data *handle, struct uftrace_extern_reader *extn)
{
	char buf[EXTERN_DATA_MAX + 64];
	char *pos;
	int len;

	if (extn == NULL)
		return -1;

	if (extn->valid)
		return 0;

retry:
	do {
		pos = fgets(buf, sizeof(buf), extn->fp);
		if (pos == NULL)
			return -1; /* end of file */

		buf[sizeof(buf) - 1] = '\0';
		while (isspace(*pos))
			pos++;
	} while (*pos == '#' || *pos == '\n'); /* ignore comment or blank */

	extn->time = parse_timestamp(pos);

	if (!check_time_range(&handle->time_range, extn->time))
		goto retry;

	pos = strpbrk(pos, "\t ");
	if (pos == NULL)
		goto retry; /* invalid data */

	while (isspace(*pos))
		pos++;

	len = strlen(pos);
	if (pos[len - 1] == '\n')
		pos[len - 1] = '\0';

	if (len == 0)
		goto retry; /* no message */

	if (unlikely(len >= EXTERN_DATA_MAX))
		len = EXTERN_DATA_MAX - 1;

	strncpy(extn->msg, pos, len);
	extn->msg[len] = '\0';

	extn->valid = true;
	return 0;
}

struct uftrace_record *get_extern_record(struct uftrace_extern_reader *extn,
					 struct uftrace_record *rec)
{
	rec->time = extn->time;
	rec->type = UFTRACE_EVENT;
	rec->addr = EVENT_ID_EXTERN_DATA;
	rec->more = 1;
	rec->magic = RECORD_MAGIC;

	return rec;
}

int finish_extern_data(struct uftrace_data *handle)
{
	struct uftrace_extern_reader *extn = handle->extn;

	if (extn && extn->fp != NULL) {
		fclose(extn->fp);
		extn->fp = NULL;

		free(extn);
		handle->extn = NULL;
	}
	return 0;
}

#ifdef UNIT_TEST

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

TEST_CASE(fstack_extern_data1)
{
	int fd;
	struct uftrace_data handle = {
		.dirname = "extern.test",
	};
	struct uftrace_opts opts = {
		.dirname = "extern.test",
	};
	const char extern_data[] = "# test data\n"
				   "1234.987654320\n" /* invalid data */
				   "1234.987654321 first data\n"
				   "1234.987654322 \n" /* empty data */
				   "1234.123456789 second data\n";

	pr_dbg("creating external data file\n");
	mkdir("extern.test", 0755);
	fd = creat("extern.test/" DEFAULT_FILENAME, 0644);
	TEST_NE(fd, -1);
	if (write(fd, extern_data, sizeof(extern_data) - 1) < 0)
		return TEST_NG;
	close(fd);

	setup_extern_data(&handle, &opts);

	pr_dbg("first read should return first data\n");
	read_extern_data(&handle, handle.extn);
	TEST_EQ(handle.extn->valid, true);
	TEST_EQ(handle.extn->time, 1234987654321ULL);
	TEST_STREQ(handle.extn->msg, "first data");

	pr_dbg("next read should return same data\n");
	read_extern_data(&handle, handle.extn);
	TEST_EQ(handle.extn->time, 1234987654321ULL);
	TEST_STREQ(handle.extn->msg, "first data");

	pr_dbg("after invalidate, a read should return second data\n");
	handle.extn->valid = false;
	read_extern_data(&handle, handle.extn);

	TEST_EQ(handle.extn->valid, true);
	TEST_EQ(handle.extn->time, 1234123456789);
	TEST_STREQ(handle.extn->msg, "second data");

	finish_extern_data(&handle);

	unlink("extern.test/" DEFAULT_FILENAME);
	rmdir("extern.test");

	return TEST_OK;
}

TEST_CASE(fstack_extern_data2)
{
	int fd;
	struct uftrace_data handle = {
		.dirname = "extern.test",
	};
	struct uftrace_opts opts = {
		.dirname = "extern.test",
	};
	const char test_data[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
	int msg_size = EXTERN_DATA_MAX * 2;
	char *extern_data;

	extern_data = xmalloc(msg_size + 1);
	for (int i = 0; i < msg_size; i += sizeof(test_data) - 1)
		strcpy(&extern_data[i], test_data);

	pr_dbg("creating external data file\n");
	mkdir("extern.test", 0755);
	fd = creat("extern.test/" DEFAULT_FILENAME, 0644);
	TEST_NE(fd, -1);
	if (write(fd, "1234.987654321 ", 15) < 0)
		return TEST_NG;
	if (write(fd, extern_data, msg_size) < 0)
		return TEST_NG;
	free(extern_data);
	close(fd);

	setup_extern_data(&handle, &opts);

	pr_dbg("read very very long data\n");
	read_extern_data(&handle, handle.extn);
	TEST_EQ(handle.extn->valid, true);
	TEST_EQ(handle.extn->time, 1234987654321ULL);

	/* check the first pattern only */
	if (strncmp(handle.extn->msg, test_data, sizeof(test_data) - 1)) {
		pr_dbg("test failed at %s:%d\n", __FILE__, __LINE__ - 1);
		pr_dbg("  expected = %s\n", test_data);
		handle.extn->msg[sizeof(test_data) - 1] = '\0';
		pr_dbg("    actual = %s\n", handle.extn->msg);
		return TEST_NG;
	}

	finish_extern_data(&handle);

	unlink("extern.test/" DEFAULT_FILENAME);
	rmdir("extern.test");

	return TEST_OK;
}

#endif /* UNIT_TEST */
