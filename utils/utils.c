#include <stdio.h>
#include <dirent.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/stat.h>

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

int create_directory(char *dirname)
{
	int ret = 0;
	char *oldname = NULL;

	xasprintf(&oldname, "%s.old", dirname);

	if (!access(oldname, F_OK))
		remove_directory(oldname);

	if (!access(dirname, F_OK) && rename(dirname, oldname) < 0) {
		pr_log("rename %s -> %s failed: %m\n", dirname, oldname);
		/* don't care about the failure */
	}

	ret = mkdir(dirname, 0755);

	free(oldname);
	return ret;
}
