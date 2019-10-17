#ifndef POSIX_H
#define POSIX_H

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef HAVE_POSIX_SHM
# define UFTRACE_SHMDIR_NAME "/dev/shm"
#else
# define UFTRACE_SHMDIR_NAME "uftrace.shm"
#endif

#ifndef HAVE_POSIX_SHM
static inline int shm_open(const char *file, int oflag, mode_t mode)
{
	int ret;
	char* path;

	if (mkdir(UFTRACE_SHMDIR_NAME, 700) && errno != EEXIST)
		return -1;

	xasprintf(&path, "%s%s", UFTRACE_SHMDIR_NAME, file);
	ret = open(path, oflag, mode);
	free(path);

	if (fcntl(ret, F_SETFD, FD_CLOEXEC) == -1) {
		close(ret);
		return -1;
	}

	return ret;
}

static inline int shm_unlink(const char *file)
{
	int ret;
	char* path;

	if (mkdir(UFTRACE_SHMDIR_NAME, 700) && errno != EEXIST)
		return -1;

	xasprintf(&path, "%s%s", UFTRACE_SHMDIR_NAME, file);
	ret = unlink(path);
	free(path);

	return ret;
}
#endif

#endif /* POSIX_H */
