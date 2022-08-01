#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "utils/tracefs.h"
#include "utils/utils.h"

#define PROC_MOUNTINFO "/proc/self/mountinfo"

static char *TRACING_DIR = NULL;

static bool find_tracing_dir(void)
{
	FILE *fp;
	char *line = NULL, fs_type[NAME_MAX], mount_point[PATH_MAX];
	static char debugfs_suffix[] = "tracing";
	bool debugfs_found = false;
	size_t len;

	if (TRACING_DIR)
		return false;

	fp = fopen(PROC_MOUNTINFO, "r");
	if (fp == NULL)
		return false;

	while (getline(&line, &len, fp) > 0) {
		/*
		 * /proc/<pid>/mountinfo format:
		 * 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 .... ....
		 * (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9) (10) (11)
		 *                mount_point                  fs_type
		 *
		 * (9) is the file system type, (5) is the mount point relative
		 * to self's root directory.
		 */
		sscanf(line, "%*i %*i %*u:%*u %*s %s %*s %*s - %s %*s %*s\n", mount_point, fs_type);

		if (!strcmp(fs_type, "tracefs")) {
			/* discard previously kept debugfs tracing dir */
			if (TRACING_DIR)
				free(TRACING_DIR);
			xasprintf(&TRACING_DIR, "%s", mount_point);
			pr_dbg2("Found tracefs at %s\n", mount_point);
			pr_dbg2("Use %s as TRACING_DIR\n", TRACING_DIR);
			return true;
		}

		if (!strcmp(fs_type, "debugfs")) {
			xasprintf(&TRACING_DIR, "%s/%s", mount_point, debugfs_suffix);
			pr_dbg2("Found debugfs at %s\n", mount_point);
			pr_dbg2("Keep searching for tracefs...\n");
			debugfs_found = true;
		}
	}

	/* we couldn't find a tracefs, but found a debugfs... */
	if (debugfs_found) {
		pr_dbg2("Use %s as TRACING_DIR\n", TRACING_DIR);
		return true;
	}

	pr_dbg2("No tracefs or debugfs found..!\n");
	return false;
}

char *get_tracing_file(const char *name)
{
	char *file = NULL;

	if (!TRACING_DIR && !find_tracing_dir())
		return NULL;

	xasprintf(&file, "%s/%s", TRACING_DIR, name);
	return file;
}

void put_tracing_file(char *file)
{
	free(file);
}

int open_tracing_file(const char *name, int flags)
{
	char *file;
	int fd;
	file = get_tracing_file(name);
	if (!file) {
		pr_dbg("cannot get tracing file: %s: %m\n", name);
		return -1;
	}

	fd = open(file, flags);
	if (fd < 0)
		pr_dbg("cannot open tracing file: %s: %m\n", name);

	put_tracing_file(file);
	return fd;
}

ssize_t read_tracing_file(const char *name, char *buf, size_t len)
{
	ssize_t ret;
	int fd = open_tracing_file(name, O_RDONLY);

	if (fd < 0)
		return -1;

	ret = read(fd, buf, len);
	close(fd);

	return ret;
}

int __write_tracing_file(int fd, const char *name, const char *val, bool append,
			 bool correct_sys_prefix)
{
	int ret = -1;
	ssize_t size = strlen(val);

	if (correct_sys_prefix) {
		char *newval = (char *)val;

		if (!strncmp(val, "sys_", 4))
			newval[0] = newval[2] = 'S';
		else if (!strncmp(val, "compat_sys_", 11))
			newval[7] = newval[9] = 'S';
		else
			correct_sys_prefix = false;
	}

	pr_dbg2("%s '%s' to tracing/%s\n", append ? "appending" : "writing", val, name);

	if (write(fd, val, size) == size)
		ret = 0;

	if (correct_sys_prefix) {
		char *newval = (char *)val;

		if (!strncmp(val, "SyS_", 4))
			newval[0] = newval[2] = 's';
		else if (!strncmp(val, "compat_SyS_", 11))
			newval[7] = newval[9] = 's';

		/* write a whitespace to distinguish the previous pattern */
		if (write(fd, " ", 1) < 0)
			ret = -1;

		pr_dbg2("%s '%s' to tracing/%s\n", append ? "appending" : "writing", val, name);

		if (write(fd, val, size) == size)
			ret = 0;
	}

	if (ret < 0)
		pr_dbg("write '%s' to tracing/%s failed: %m\n", val, name);

	return ret;
}

int write_tracing_file(const char *name, const char *val)
{
	int ret;
	int fd = open_tracing_file(name, O_WRONLY | O_TRUNC);

	if (fd < 0)
		return -1;

	ret = __write_tracing_file(fd, name, val, false, false);

	close(fd);
	return ret;
}

int append_tracing_file(const char *name, const char *val)
{
	int ret;
	int fd = open_tracing_file(name, O_WRONLY | O_APPEND);

	if (fd < 0)
		return -1;

	ret = __write_tracing_file(fd, name, val, true, false);

	close(fd);
	return ret;
}

int set_tracing_pid(int pid)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d", pid);
	if (append_tracing_file("set_ftrace_pid", buf) < 0)
		return -1;

	/* ignore error on old kernel */
	append_tracing_file("set_event_pid", buf);
	return 0;
}

int set_tracing_clock(char *clock_str)
{
	/* set to default clock source if not given */
	if (clock_str == NULL)
		clock_str = "mono";
	return write_tracing_file("trace_clock", clock_str);
}
