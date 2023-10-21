#include <linux/membarrier.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
	syscall(__NR_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
	syscall(__NR_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
	return 0;
}
