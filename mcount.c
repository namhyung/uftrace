#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <sys/syscall.h>

#include "mcount.h"

__thread int mcount_rstack_idx;
__thread struct mcount_ret_stack *mcount_rstack;

static FILE *fout;
static bool debug;

static unsigned long *filter_trace;
static unsigned nr_filter;
static unsigned long *filter_notrace;
static unsigned nr_notrace;

static unsigned long mcount_gettime(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int gettid(void)
{
	return syscall(SYS_gettid);
}

static void mcount_init_file(void)
{
	struct ftrace_file_header ffh = {
		.magic = FTRACE_MAGIC_STR,
		.version = FTRACE_VERSION,
	};
	char *filename = getenv("FTRACE_FILE");

	if (filename == NULL)
		filename = FTRACE_FILE_NAME;

	fout = fopen(filename, "wb");
	if (fout == NULL) {
		perror("mcount_init_file");
		exit(1);
	}

	if (fwrite(&ffh, sizeof(ffh), 1, fout) != 1) {
		perror("mcount_init_file");
		exit(1);
	}
}

static void mcount_prepare(void)
{
	static pthread_once_t once_control = PTHREAD_ONCE_INIT;

	mcount_rstack = malloc(MCOUNT_RSTACK_MAX * sizeof(*mcount_rstack));
	if (mcount_rstack == NULL) {
		perror("mcount_prepare");
		exit(1);
	}

	pthread_once(&once_control, mcount_init_file);
}

#define CALL_SIZE  9  /* 1 for push; 3 for mov; 5 for call */

static bool mcount_match(unsigned long ip1, unsigned long ip2)
{
	if (ip1 + CALL_SIZE == ip2)
		return true;

	if (ip1 < ip2 && ip1 >= ip2 - CALL_SIZE)
		return true;

	return false;
}

/*
 * return 1 if it should be traced, 0 if it should not.
 * return -1 if it's filtered at notrace - needs special treatment.
 */
static int mcount_filter(unsigned long ip)
{
	/*
	 * mcount_rstack_idx > 0 means it's now traced (not filtered)
	 */
	int ret = mcount_rstack_idx >= 0;
	unsigned i;

	if (mcount_rstack_idx < 0)
		return 0;

	if (nr_filter && mcount_rstack_idx == 0) {
		for (i = 0; i < nr_filter; i++) {
			if (mcount_match(filter_trace[i], ip))
				return 1;
		}
		ret = 0;
	}

	if (nr_notrace && ret) {
		for (i = 0; i < nr_notrace; i++) {
			if (mcount_match(filter_notrace[i], ip))
				return -1;
		}
	}
	return ret;
}

int mcount_entry(unsigned long parent, unsigned long child)
{
	int filtered;
	struct mcount_ret_stack *rstack;

	if (unlikely(mcount_rstack == NULL))
		mcount_prepare();

	if (mcount_rstack_idx >= MCOUNT_RSTACK_MAX) {
		printf("mcount: too deeply nested calls\n");
		return -1;
	}

	filtered = mcount_filter(child);
	if (filtered == 0)
		return -1;

	rstack = &mcount_rstack[mcount_rstack_idx++];

	rstack->tid = gettid();
	rstack->depth = mcount_rstack_idx - 1;
	rstack->parent_ip = parent;
	rstack->child_ip = filtered > 0 ? child : MCOUNT_FILTERED_IP;
	rstack->start_time = mcount_gettime();
	rstack->end_time = 0;
	rstack->child_time = 0;

	if (filtered > 0)
		fwrite(rstack, sizeof(*rstack), 1, fout);
	else
		mcount_rstack_idx -= MCOUNT_NOTRACE_IDX; /* see below */

	return 0;
}

unsigned long mcount_exit(void)
{
	bool was_filtered = false;
	struct mcount_ret_stack *rstack;

	/*
	 * We subtracted big number for notrace filtered functions
	 * so that it can be identified when entering the exit handler.
	 */
	if (mcount_rstack_idx < 0) {
		mcount_rstack_idx += MCOUNT_NOTRACE_IDX;
		was_filtered = true;
	}

	if (mcount_rstack_idx <= 0) {
		printf("mcount: broken ret stack (%d)\n", mcount_rstack_idx);
		exit(1);
	}

	rstack = &mcount_rstack[--mcount_rstack_idx];

	if (rstack->tid != gettid() || rstack->depth != mcount_rstack_idx ||
	    rstack->end_time != 0) {
		printf("mcount: corrupted mcount ret stack found!\n");
		//exit(1);
	}

	if (was_filtered) {
		assert(rstack->child_ip == MCOUNT_FILTERED_IP);
		return rstack->parent_ip;
	}

	rstack->end_time = mcount_gettime();
	fwrite(rstack, sizeof(*rstack), 1, fout);

	if (mcount_rstack_idx > 0) {
		int idx = mcount_rstack_idx - 1;
		struct mcount_ret_stack *parent = &mcount_rstack[idx];

		parent->child_time += rstack->end_time - rstack->start_time;
	}
	return rstack->parent_ip;
}

static void mcount_finish(void)
{
	fclose(fout);
	fout = NULL;
}

static int mcount_setup_filter(char *envstr, unsigned long **filter, unsigned *size)
{
	unsigned int i, nr;
	char *str = getenv(envstr);
	char *pos;

	if (str == NULL)
		return 0;

	pos = str;
	nr = 0;
	while (pos) {
		nr++;
		pos = strchr(pos, ':');
		if (pos)
			pos++;
	}

	*filter = malloc(sizeof(long) * nr);
	if (*filter == NULL) {
		printf("failed to allocate memory for %s\n", envstr);
		return -1;
	}

	*size = nr;

	pos = str;
	for (i = 0; i < nr; i++) {
		(*filter)[i] = strtoul(pos, &pos, 16);
		if (*pos && *pos != ':') {
			printf("invalid filter string for %s\n", envstr);
			return -1;
		}
		pos++;
	}

	if (debug) {
		printf("%s: ", envstr);
		for (i = 0; i < nr; i++)
			printf(" 0x%lx", (*filter)[i]);
		putchar('\n');
	}
	return 0;
}

static void mcount_cleanup_filter(unsigned long **filter, unsigned *size)
{
	free(*filter);
	*filter = NULL;
	*size = 0;
}

/*
 * external interfaces
 */
void __attribute__((visibility("default")))
__monstartup(unsigned long low, unsigned long high)
{
	if (getenv("FTRACE_DEBUG"))
		debug = true;

	if (mcount_setup_filter("FTRACE_FILTER", &filter_trace, &nr_filter) < 0)
		exit(1);

	if (mcount_setup_filter("FTRACE_NOTRACE", &filter_notrace, &nr_notrace) < 0)
		exit(1);
}

void __attribute__((visibility("default")))
_mcleanup(void)
{
	mcount_finish();

	mcount_cleanup_filter(&filter_trace, &nr_filter);
	mcount_cleanup_filter(&filter_notrace, &nr_notrace);
}
