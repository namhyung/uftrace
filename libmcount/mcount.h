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

#include "../ftrace.h"
#include "../utils/rbtree.h"
#include "../utils/symbol.h"

#define FTRACE_FILE_NAME  "ftrace.data"
#define FTRACE_DIR_NAME   "ftrace.dir"

#define MCOUNT_RSTACK_MAX  1024
#define MCOUNT_NOTRACE_IDX 0x10000
#define MCOUNT_INVALID_DYNIDX 0xffff
#define MCOUNT_DEFAULT_DEPTH  (INT_MAX - 1)

struct mcount_ret_stack {
	unsigned long *parent_loc;
	unsigned long parent_ip;
	unsigned long child_ip;
	/* time in nsec (CLOCK_MONOTONIC) */
	uint64_t start_time;
	uint64_t end_time;
	int tid;
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
	char data[];
};

#define FTRACE_MSG_MAGIC 0xface

#define FTRACE_MSG_REC_START  1U
#define FTRACE_MSG_REC_END    2U
#define FTRACE_MSG_TID        3U
#define FTRACE_MSG_FORK_START 4U
#define FTRACE_MSG_FORK_END   5U
#define FTRACE_MSG_SESSION    6U
#define FTRACE_MSG_LOST       7U

/* msg format for communicating by pipe */
struct ftrace_msg {
	unsigned short magic; /* FTRACE_MSG_MAGIC */
	unsigned short type;  /* FTRACE_MSG_REC_* */
	unsigned int len;
	unsigned char data[];
};

struct ftrace_msg_task {
	uint64_t time;
	int32_t  pid;
	int32_t  tid;
};

struct ftrace_msg_sess {
	struct ftrace_msg_task task;
	char sid[16];
	int  unused;
	int  namelen;
	char exename[];
};

#endif /* FTRACE_MCOUNT_H */
