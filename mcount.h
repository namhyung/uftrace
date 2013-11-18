#ifndef FTRACE_MCOUNT_H
#define FTRACE_MCOUNT_H

#include <stdint.h>

#define likely(x)  __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

#define MCOUNT_RSTACK_MAX  128
#define MCOUNT_NOTRACE_IDX 0x10000

#define MCOUNT_FILTERED_IP 0xEEEEFFFF

struct mcount_ret_stack {
	unsigned long parent_ip;
	unsigned long child_ip;
	/* time in usec (CLOCK_MONOTONIC) */
	unsigned long start_time;
	unsigned long end_time;
	unsigned long child_time;
	int tid;
	int depth;
};

#define FTRACE_MAGIC_LEN  8
#define FTRACE_MAGIC_STR  "Ftrace!"
#define FTRACE_VERSION  1
#define FTRACE_FILE_NAME  "ftrace.data"


/* file data are written in little-endian */
struct ftrace_file_header {
	char magic[FTRACE_MAGIC_LEN];
	uint32_t version;
	uint32_t padding;
	uint64_t length;
	uint64_t unused;
};

#endif /* FTRACE_MCOUNT_H */
