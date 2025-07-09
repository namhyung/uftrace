/*
 * data structures for handling mcount records
 *
 * Copyright (C) 2014-2018, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef UFTRACE_MCOUNT_H
#define UFTRACE_MCOUNT_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>

#include "utils/rbtree.h"

#define UFTRACE_DIR_NAME "uftrace.data"

#define MCOUNT_RSTACK_MAX OPT_RSTACK_DEFAULT
#define MCOUNT_DEFAULT_DEPTH OPT_DEPTH_DEFAULT

#define MCOUNT_NOTRACE_IDX 0x10000
#define MCOUNT_INVALID_DYNIDX 0xefefefef

enum mcount_rstack_flag {
	MCOUNT_FL_SETJMP = (1U << 0),
	MCOUNT_FL_LONGJMP = (1U << 1),
	MCOUNT_FL_NORECORD = (1U << 2),
	MCOUNT_FL_NOTRACE = (1U << 3),
	MCOUNT_FL_FILTERED = (1U << 4),
	MCOUNT_FL_VFORK = (1U << 5),
	MCOUNT_FL_WRITTEN = (1U << 6),
	MCOUNT_FL_DISABLED = (1U << 7),
	MCOUNT_FL_RECOVER = (1U << 8),
	MCOUNT_FL_RETVAL = (1U << 9),
	MCOUNT_FL_TRACE = (1U << 10),
	MCOUNT_FL_ARGUMENT = (1U << 11),
	MCOUNT_FL_READ = (1U << 12),
	MCOUNT_FL_CALLER = (1U << 13),
	MCOUNT_FL_CYGPROF = (1U << 14),
};

struct plthook_data;
struct list_head;

struct mcount_ret_stack {
	unsigned long *parent_loc;
	unsigned long parent_ip;
	unsigned long child_ip;
	enum mcount_rstack_flag flags;
	unsigned dyn_idx;
	/* time in nsec (CLOCK_MONOTONIC) */
	uint64_t start_time;
	uint64_t end_time;
	uint64_t filter_time;
	unsigned filter_size;
	unsigned short depth;
	unsigned short filter_depth;
	unsigned short filter_max_depth;
	unsigned short nr_events;
	unsigned short event_idx;
	struct plthook_data *pd;
	/* set arg_spec at function entry and use it at exit */
	struct list_head *pargs;
};

void __monstartup(unsigned long low, unsigned long high);
void _mcleanup(void);
void mcount_restore(void);
void mcount_reset(void);



#define SHMEM_BUFFER_SIZE_KB 128
#define SHMEM_BUFFER_SIZE (SHMEM_BUFFER_SIZE_KB * KB)

enum shmem_buffer_flags {
	SHMEM_FL_NEW = (1U << 0),
	SHMEM_FL_WRITTEN = (1U << 1),
	SHMEM_FL_RECORDING = (1U << 2),
};

struct mcount_shmem_buffer {
	unsigned size;
	unsigned flag;
	unsigned unused[2];
	char data[];
};

/* must be in sync with enum debug_domain (bits) */
#define DBG_DOMAIN_STR "TSDFfsKMpPERWw"

#endif /* UFTRACE_MCOUNT_H */
