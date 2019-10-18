#ifndef POSIX_H
#define POSIX_H

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef HAVE_POSIX_SHM
# define UFTRACE_SHMDIR_NAME "/dev/shm"
#else
# define UFTRACE_SHMDIR_NAME "uftrace.data/shm"
#endif

#ifndef HAVE_POSIX_SHM
static inline int shm_open(const char *file, int oflag, mode_t mode)
{
	int ret;
	char* path;
	if (mkdir(UFTRACE_SHMDIR_NAME, S_IRWXU | S_IRWXG | S_IRWXO) && errno != EEXIST)
		return -1;
	const size_t path_size = sizeof(UFTRACE_SHMDIR_NAME) - 1 + strlen(file) + 1;
	path = calloc(path_size, sizeof(char));
	strncat(path, UFTRACE_SHMDIR_NAME, path_size - strlen(path) - 1);
	strncat(path, file, path_size - strlen(path) - 1);
	ret = open(path, oflag, mode);
	free(path);
	return ret;
}

static inline int shm_unlink(const char *file)
{
	int ret;
	char* path;
	if (mkdir(UFTRACE_SHMDIR_NAME, S_IRWXU | S_IRWXG | S_IRWXO) && errno != EEXIST)
		return -1;
	const size_t path_size = sizeof(UFTRACE_SHMDIR_NAME) - 1 + strlen(file) + 1;
	path = calloc(path_size, sizeof(char));
	strncat(path, UFTRACE_SHMDIR_NAME, path_size - strlen(path) - 1);
	strncat(path, file, path_size - strlen(path) - 1);
	ret = unlink(path);
	free(path);
	return ret;
}
#endif

#ifndef HAVE_STRCOLL
static inline int strcoll(const char *a, const char *b) {
	return strcmp(a, b);
}
#endif

#endif /* POSIX_H */
