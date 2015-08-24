#include <stdio.h>
#include <dirent.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>

#include "utils.h"


volatile bool ftrace_done;

void sighandler(int sig)
{
	ftrace_done = true;
}

int read_all(int fd, void *buf, size_t size)
{
	int ret;

	while (size) {
		ret = read(fd, buf, size);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return -1;

		buf += ret;
		size -= ret;
	}
	return 0;
}

int write_all(int fd, void *buf, size_t size)
{
	int ret;

	while (size) {
		ret = write(fd, buf, size);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			return -1;

		buf += ret;
		size -= ret;
	}
	return 0;
}

int remove_directory(char *dirname)
{
	DIR *dp;
	struct dirent *ent;
	char buf[PATH_MAX];

	dp = opendir(dirname);
	if (dp == NULL)
		return -1;

	pr_dbg("removing %s directory\n", dirname);

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", dirname, ent->d_name);
		unlink(buf);
	}

	closedir(dp);
	rmdir(dirname);
	return 0;
}

void print_time_unit(uint64_t delta_nsec)
{
	uint64_t delta = delta_nsec;
	uint64_t delta_small = 0;
	char *unit[] = { "us", "ms", "s", "m", "h", };
	unsigned limit[] = { 1000, 1000, 1000, 60, 24, INT_MAX, };
	unsigned idx;

	if (delta_nsec == 0UL) {
		printf(" %7s %2s", "", "");
		return;
	}

	for (idx = 0; idx < ARRAY_SIZE(unit); idx++) {
		delta_small = delta % limit[idx];
		delta = delta / limit[idx];

		if (delta < limit[idx+1])
			break;
	}

	assert(idx < ARRAY_SIZE(unit));

	printf(" %3"PRIu64".%03"PRIu64" %2s", delta, delta_small, unit[idx]);
}
