#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils/shmem.h"
#include "utils/utils.h"

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

#ifdef UNIT_TEST
TEST_CASE(uftrace_shmem)
{
	int fd;
	void *buf;
	const char bufname[] = "test_shmem";
	int bufsize = 4096;

	pr_dbg("check if shmem root returns a valid path\n");
	TEST_NE(uftrace_shmem_root(), NULL);

	pr_dbg("open a test shmem buffer\n");
	fd = uftrace_shmem_open(bufname, O_RDWR | O_CREAT | O_TRUNC, UFTRACE_SHMEM_PERMISSION_MODE);
	TEST_GE(fd, 0);

	pr_dbg("allocate the shmem buffer for %d bytes\n", bufsize);
	TEST_GE(ftruncate(fd, bufsize), 0);

	buf = mmap(NULL, bufsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_NE(buf, MAP_FAILED);

	pr_dbg("touch the test shmem buffer\n");
	memset(buf, 0, bufsize);

	pr_dbg("close the test shmem buffer\n");
	close(fd);
	TEST_EQ(uftrace_shmem_unlink("test_shmem"), 0);

	return TEST_OK;
}
#endif /* UNIT_TEST */
