#ifndef UFTRACE_PERF_H
#define UFTRACE_PERF_H

#include <stdint.h>
#include <stdbool.h>
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

struct perf_context_switch_event {
	/*
	 * type: PERF_RECORD_SWITCH (14)
	 * misc: PERF_RECORD_MISC_SWITCH_OUT (0x2000)
	 * size: 24
	 */
	struct perf_event_header header;

	struct sample_id {
		uint32_t   pid;
		uint32_t   tid;
		uint64_t   time;
	} sample_id;
};

struct uftrace_ctxsw {
	uint64_t	time;
	int		tid;
	bool		out;
};

#ifdef HAVE_PERF_CLOCKID

int setup_perf_record(struct uftrace_perf_writer *perf, int nr_cpu, int pid,
		      const char *dirname);
void finish_perf_record(struct uftrace_perf_writer *perf);
void record_perf_data(struct uftrace_perf_writer *perf, int cpu, int sock);

#else  /* !HAVE_PERF_CLOCKID */

static inline int setup_perf_record(struct uftrace_perf_writer *perf,
				    int nr_cpu, int pid, const char *dirname)
{
	return -1;
}

static inline void finish_perf_record(struct uftrace_perf_writer *perf) {}
static inline void record_perf_data(struct uftrace_perf_writer *perf,
				    int cpu, int sock) {}

#endif /* HAVE_PERF_CLOCKID */

#ifdef HAVE_PERF_CTXSW
# define PERF_CTXSW_AVAILABLE  1
# define INIT_CTXSW_ATTR	.context_switch = 1,

#else  /* !HAVE_PERF_CTXSW */
# define PERF_CTXSW_AVAILABLE  0
# define INIT_CTXSW_ATTR

# define PERF_RECORD_SWITCH           14
# define PERF_RECORD_MISC_SWITCH_OUT  (1 << 13)

#endif /* HAVE_PERF_CTXSW */

struct uftrace_perf_reader {
	FILE			*fp;
	bool			valid;
	bool			done;
	struct uftrace_ctxsw	ctxsw;
};

struct ftrace_file_handle;
struct uftrace_record;

int setup_perf_data(struct ftrace_file_handle *handle);
void finish_perf_data(struct ftrace_file_handle *handle);
int read_perf_data(struct ftrace_file_handle *handle);
struct uftrace_record * get_perf_record(struct ftrace_file_handle *handle,
					struct uftrace_perf_reader *perf);

#endif /* UFTRACE_PERF_H */
