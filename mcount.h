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
	uint64_t start_time;
	uint64_t end_time;
	uint64_t child_time;
	int tid;
	int depth;
};

extern __thread int mcount_rstack_idx;
extern __thread struct mcount_ret_stack *mcount_rstack;

int mcount_entry(unsigned long parent, unsigned long child);
unsigned long mcount_exit(void);
void __monstartup(unsigned long low, unsigned long high);
void _mcleanup(void);


#define FTRACE_MAGIC_LEN  8
#define FTRACE_MAGIC_STR  "Ftrace!"
#define FTRACE_VERSION  1
#define FTRACE_FILE_NAME  "ftrace.data"

/* file data are written in little-endian */
struct ftrace_file_header {
	char magic[FTRACE_MAGIC_LEN];
	uint32_t version;
	uint16_t header_size;
	uint8_t  endian;
	uint8_t  class;
	uint64_t length;
	uint64_t unused;
};

#endif /* FTRACE_MCOUNT_H */
