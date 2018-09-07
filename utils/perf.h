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

struct sample_id {
	uint32_t   pid;
	uint32_t   tid;
	uint64_t   time;
};

struct perf_task_event {
	/*
	 * type: PERF_RECORD_FORK (7) or PERF_RECORD_EXIT (4)
	 */
	uint32_t		 pid, ppid;
	uint32_t		 tid, ptid;
	uint64_t		 time;
	struct sample_id	 sample_id;
};

struct perf_comm_event {
	/*
	 * type: PERF_RECORD_COMM (3)
	 */
	uint32_t		 pid, tid;
	char			 comm[16];   /* variable length (aligned to 8) */
	struct sample_id	 sample_id;  /* needs to be read separately */
};

struct perf_context_switch_event {
	/*
	 * type: PERF_RECORD_SWITCH (14)
	 * misc: PERF_RECORD_MISC_SWITCH_OUT (0x2000)
	 * size: 24
	 */
	struct sample_id	 sample_id;
};

struct uftrace_ctxsw_event {
	bool		out;
};

struct uftrace_task_event {
	int		pid;
	int		ppid;
};

struct uftrace_comm_event {
	int		pid;
	bool		exec;
	char		comm[16];
};

#ifdef HAVE_PERF_CLOCKID

int setup_perf_record(struct uftrace_perf_writer *perf, int nr_cpu, int pid,
		      const char *dirname, int use_ctxsw);
void finish_perf_record(struct uftrace_perf_writer *perf);
void record_perf_data(struct uftrace_perf_writer *perf, int cpu, int sock);

#else  /* !HAVE_PERF_CLOCKID */

static inline int setup_perf_record(struct uftrace_perf_writer *perf,
				    int nr_cpu, int pid, const char *dirname,
				    int use_ctxsw)
{
	return -1;
}

static inline void finish_perf_record(struct uftrace_perf_writer *perf) {}
static inline void record_perf_data(struct uftrace_perf_writer *perf,
				    int cpu, int sock) {}

#endif /* HAVE_PERF_CLOCKID */

#ifndef  PERF_RECORD_MISC_COMM_EXEC
# define PERF_RECORD_MISC_COMM_EXEC  (1 << 13)
#endif

#ifdef HAVE_PERF_CTXSW
# define PERF_CTXSW_AVAILABLE  1

#else  /* !HAVE_PERF_CTXSW */
# define PERF_CTXSW_AVAILABLE  0

# define PERF_RECORD_SWITCH           14
# define PERF_RECORD_MISC_SWITCH_OUT  (1 << 13)

#endif /* HAVE_PERF_CTXSW */

struct uftrace_perf_reader {
	FILE			*fp;
	bool			valid;
	bool			done;
	int			type;
	int			tid;
	uint64_t		time;
	union {
		struct uftrace_ctxsw_event	ctxsw;
		struct uftrace_task_event	task;
		struct uftrace_comm_event	comm;
	} u;
};

struct ftrace_file_handle;
struct uftrace_record;

int setup_perf_data(struct ftrace_file_handle *handle);
void finish_perf_data(struct ftrace_file_handle *handle);
int read_perf_data(struct ftrace_file_handle *handle);
struct uftrace_record * get_perf_record(struct ftrace_file_handle *handle,
					struct uftrace_perf_reader *perf);
void update_perf_task_comm(struct ftrace_file_handle *handle);
void process_perf_event(struct ftrace_file_handle *handle);

#endif /* UFTRACE_PERF_H */
