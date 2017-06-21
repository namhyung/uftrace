#ifndef __UFTRACE_PERF_H__
#define __UFTRACE_PERF_H__

#include <linux/perf_event.h>

#define PERF_MMAP_SIZE  (132 * 1024)  /* 32 + 1 pages */
#define PERF_WATERMARK  (8 * 1024)    /* 2 pages */

struct uftrace_perf_writer {
	int			*event_fd;
	void			**page;
	uint64_t		*data_pos;
	FILE			**fp;
	int			nr_event;
};

#ifdef HAVE_PERF_CLOCKID

int setup_perf_record(struct uftrace_perf_writer *perf, int nr_cpu, int pid,
		      const char *dirname);
void finish_perf_record(struct uftrace_perf_writer *perf);
void record_perf_data(struct uftrace_perf_writer *perf, int cpu);

#else  /* !HAVE_PERF_CLOCKID */

static inline int setup_perf_record(struct uftrace_perf_writer *perf,
				    int nr_cpu, int pid, const char *dirname)
{
	return -1;
}

static inline void finish_perf_record(struct uftrace_perf_writer *perf) {}
static inline void record_perf_data(struct uftrace_perf_writer *perf, int cpu) {}

#endif /* HAVE_PERF_CLOCKID */

#endif /* UFTRACE_PERF_H */
