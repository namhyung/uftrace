#ifndef UTILS_MEMBARRIER_H
#define UTILS_MEMBARRIER_H

#include <linux/membarrier.h>

int membarrier(int cmd, unsigned int flags, int cpu_id);

#endif /* UTILS_MEMBARRIER_H */