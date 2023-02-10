#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils/shmem.h"

#ifdef __ANDROID__

const char *uftrace_shmem_root(void)
{
	static char uftrace_dir[PATH_MAX] = "";

	if (uftrace_dir[0] == 0) {
		const char *tmpdir;
		tmpdir = getenv("TMPDIR");
		if (!tmpdir)
			tmpdir = "/tmp";

		snprintf(uftrace_dir, sizeof(uftrace_dir), "%s/uftrace", tmpdir);
	}

	return uftrace_dir;
}

int uftrace_shmem_open(const char *name, int oflag, mode_t mode)
{
	const char *uftrace_dir;
	char *fname;
	int fd;
	int status;

	uftrace_dir = uftrace_shmem_root();

	status = mkdir(uftrace_dir, mode);
	if (status < 0 && errno != EEXIST)
		return -1;

	if (asprintf(&fname, "%s/%s", uftrace_dir, name) < 0)
		return -1;

	fd = open(fname, oflag, mode);
	if (fd >= 0) {
		int flags = fcntl(fd, F_GETFD, 0);
		flags |= FD_CLOEXEC;
		if (fcntl(fd, F_SETFD, flags) < 0) {
			int saved_errno = errno;
			close(fd);
			fd = -1;
			errno = saved_errno;
		}
	}

	free(fname);

	return fd;
}

int uftrace_shmem_unlink(const char *name)
{
	const char *uftrace_dir;
	char *fname;
	int status;

	uftrace_dir = uftrace_shmem_root();

	if (asprintf(&fname, "%s/%s", uftrace_dir, name))
		return -1;
	status = unlink(fname);
	free(fname);

	return status;
}

#else /* ! __ANDROID__ */

#include <sys/mman.h>

const char *uftrace_shmem_root(void)
{
	return "/dev/shm";
}

int uftrace_shmem_open(const char *name, int oflag, mode_t mode)
{
	return shm_open(name, oflag, mode);
}

int uftrace_shmem_unlink(const char *name)
{
	return shm_unlink(name);
}

#endif
