/*
 * data structures for handling mcount records
 *
 * Copyright (C) 2014-2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef FTRACE_MCOUNT_H
#define FTRACE_MCOUNT_H

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>

#include "ftrace.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"

#define FTRACE_FILE_NAME  "ftrace.data"
#define FTRACE_DIR_NAME   "ftrace.dir"

#define MCOUNT_RSTACK_MAX  1024
#define MCOUNT_NOTRACE_IDX 0x10000
#define MCOUNT_INVALID_DYNIDX 0xffff
#define MCOUNT_DEFAULT_DEPTH  (INT_MAX - 1)

enum {
	MCOUNT_FL_SETJMP	= (1U << 0),
	MCOUNT_FL_LONGJMP	= (1U << 1),
	MCOUNT_FL_NORECORD	= (1U << 2),
	MCOUNT_FL_NOTRACE	= (1U << 3),
	MCOUNT_FL_FILTERED	= (1U << 4),
	MCOUNT_FL_VFORK		= (1U << 5),
	MCOUNT_FL_WRITTEN	= (1U << 6),
	MCOUNT_FL_DISABLED	= (1U << 7),
	MCOUNT_FL_RECOVER	= (1U << 8),
};

struct mcount_ret_stack {
	unsigned long *parent_loc;
	unsigned long parent_ip;
	unsigned long child_ip;
	unsigned long flags;
	/* time in nsec (CLOCK_MONOTONIC) */
	uint64_t start_time;
	uint64_t end_time;
	int tid;
	int filter_depth;
	unsigned short depth;
	unsigned short dyn_idx;
};

void __monstartup(unsigned long low, unsigned long high);
void _mcleanup(void);
void mcount_restore(void);
void mcount_reset(void);

#define SHMEM_BUFFER_SIZE  (128 * 1024)

enum shmem_buffer_flags {
	SHMEM_FL_NEW		= (1U << 0),
	SHMEM_FL_WRITTEN	= (1U << 1),
};

struct mcount_shmem_buffer {
	unsigned size;
	unsigned flag;
	unsigned unused[2];
	char data[];
};

/* must be in sync with enum debug_domain (bits) */
#define DBG_DOMAIN_STR  "TSDFfsKM"

enum filter_result {
	FILTER_NOTRACE = -1,
	FILTER_OUT,
	FILTER_IN,
	FILTER_MATCH,
};

#endif /* FTRACE_MCOUNT_H */
