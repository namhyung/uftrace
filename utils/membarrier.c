#include "utils/membarrier.h"
#include <sys/syscall.h>
#include <unistd.h>

int membarrier(int cmd, unsigned int flags, int cpu_id) {
	return syscall(__NR_membarrier, cmd, flags, cpu_id);
}
