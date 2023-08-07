#include <fcntl.h>
#include <linux/magic.h>
#include <mntent.h>
#include <stdio.h>
#include <string.h>
#include <sys/vfs.h>

#include "utils/tracefs.h"
#include "utils/utils.h"

#define PROC_MOUNTS_DIR_PATH "/proc/mounts"
#define TRACEFS_DIR_PATH "/sys/kernel/tracing"
#define OLD_TRACEFS_DIR_PATH "/sys/kernel/debug/tracing"

static char *TRACING_DIR = NULL;

static bool find_tracing_dir(void)
{
	FILE *fp;
	struct mntent *ent;
	struct statfs fs;

	if (TRACING_DIR)
		return true;

	if (!statfs(TRACEFS_DIR_PATH, &fs) && fs.f_type == TRACEFS_MAGIC) {
		xasprintf(&TRACING_DIR, "%s", TRACEFS_DIR_PATH);
		return true;
	}
	else if (!statfs(OLD_TRACEFS_DIR_PATH, &fs) && fs.f_type == TRACEFS_MAGIC) {
		xasprintf(&TRACING_DIR, "%s", OLD_TRACEFS_DIR_PATH);
		return true;
	}

	fp = setmntent(PROC_MOUNTS_DIR_PATH, "r");
	if (fp == NULL)
		return false;

	while ((ent = getmntent(fp)) != NULL) {
		if (!strcmp(ent->mnt_fsname, "tracefs")) {
			xasprintf(&TRACING_DIR, "%s", ent->mnt_dir);
			break;
		}
	}
	endmntent(fp);

	if (!TRACING_DIR) {
		pr_dbg2("No tracefs or debugfs found..!\n");
		return false;
	}

	return true;
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
