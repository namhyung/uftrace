#include <stdio.h>
#include <dirent.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include "utils/utils.h"


volatile bool ftrace_done;

void sighandler(int sig)
{
	ftrace_done = true;
}

void setup_signal(void)
{
	signal(SIGINT,  sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGPIPE, sighandler);
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

int fread_all(void *buf, size_t size, FILE *fp)
{
	size_t ret;

	while (size) {
		if (feof(fp))
			return -1;

		ret = fread(buf, 1, size, fp);
		if (ferror(fp))
			return -1;

		buf  += ret;
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

int writev_all(int fd, struct iovec *iov, int count)
{
	int i, ret;
	int size = 0;

	for (i = 0; i < count; i++)
		size += iov[i].iov_len;

	while (size) {
		ret = writev(fd, iov, count);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			return -1;

		size -= ret;
		if (size == 0)
			break;

		while (ret > (int)iov->iov_len) {
			ret -= iov->iov_len;

			if (count == 0)
				pr_err_ns("invalid iovec count?");

			count--;
			iov++;
		}

		iov->iov_base += ret;
		iov->iov_len  -= ret;
	}
	return 0;
}

int remove_directory(char *dirname)
{
	DIR *dp;
	struct dirent *ent;
	char buf[PATH_MAX];
	int saved_errno = 0;
	int ret = 0;

	dp = opendir(dirname);
	if (dp == NULL)
		return -1;

	pr_dbg("removing %s directory\n", dirname);

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", dirname, ent->d_name);
		if (unlink(buf) < 0) {
			saved_errno = errno;
			ret = -1;
			break;
		}
	}

	closedir(dp);
	if (rmdir(dirname) < 0 && ret == 0)
		ret = -1;
	else
		errno = saved_errno;
	return ret;
}

int create_directory(char *dirname)
{
	int ret = -1;
	char *oldname = NULL;

	xasprintf(&oldname, "%s.old", dirname);

	if (!access(oldname, F_OK)) {
		if (remove_directory(oldname) < 0) {
			pr_log("removing old directory failed: %m\n");
			goto out;
		}
	}

	if (!access(dirname, F_OK) && rename(dirname, oldname) < 0) {
		pr_log("rename %s -> %s failed: %m\n", dirname, oldname);
		goto out;
	}

	ret = mkdir(dirname, 0755);

out:
	free(oldname);
	return ret;
}

int chown_directory(char *dirname)
{
	DIR *dp;
	struct dirent *ent;
	char buf[PATH_MAX];
	char *uidstr;
	char *gidstr;
	uid_t uid;
	gid_t gid;
	int ret = 0;

	/* When invoked with sudo, real uid is also 0.  Use env instead. */
	uidstr = getenv("SUDO_UID");
	gidstr = getenv("SUDO_GID");
	if (uidstr == NULL || gidstr == NULL)
		return 0;

	uid = strtol(uidstr, NULL, 0);
	gid = strtol(gidstr, NULL, 0);

	dp = opendir(dirname);
	if (dp == NULL)
		return -1;

	pr_dbg("chown %s directory to (%d:%d)\n", dirname, (int)uid, (int)gid);

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", dirname, ent->d_name);
		if (chown(buf, uid, gid) < 0)
			ret = -1;
	}

	closedir(dp);
	if (chown(dirname, uid, gid) < 0)
		ret = -1;
	return ret;
}

char *read_exename(void)
{
	int len;
	static char exename[4096];

	if (!*exename) {
		len = readlink("/proc/self/exe", exename, sizeof(exename)-1);
		if (len < 0)
			pr_err("cannot read executable name");

		exename[len] = '\0';
	}

	return exename;
}

bool check_time_range(struct uftrace_time_range *range, uint64_t timestamp)
{
	if (range->start && range->start > timestamp)
		return false;
	if (range->stop && range->stop < timestamp)
		return false;

	return true;
}
