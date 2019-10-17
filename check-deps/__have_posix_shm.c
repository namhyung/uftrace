#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void)
{
	shm_open("/uftrace_test", O_RDWR, 0600);
	shm_unlink("/uftrace_test");
	return 0;
}
