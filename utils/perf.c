#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <glob.h>
#include <errno.h>
#include <unistd.h>
#include <byteswap.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "uftrace.h"
#include "utils/perf.h"
#include "utils/fstack.h"
#include "utils/compiler.h"

/* It needs to synchronize records using monotonic clock */
#ifdef HAVE_PERF_CLOCKID

#define PERF_PARANOID_CHECK  "/proc/sys/kernel/perf_event_paranoid"

static bool use_perf = true;

static int open_perf_event(int pid, int cpu, int use_ctxsw)
{
	/* use dummy events to get scheduling info (Linux v4.3 or later) */
	struct perf_event_attr attr = {
		.size			= sizeof(attr),
		.type			= PERF_TYPE_SOFTWARE,
		.config			= PERF_COUNT_SW_DUMMY,
		.sample_type		= PERF_SAMPLE_TIME | PERF_SAMPLE_TID,
		.sample_period		= 1,
		.sample_id_all		= 1,
		.exclude_kernel		= 1,
		.disabled		= 1,
		.enable_on_exec		= 1,
		.inherit		= 1,
		.watermark		= 1,
		.wakeup_watermark	= PERF_WATERMARK,
		.task			= 1,
		.comm			= 1,
		.use_clockid		= 1,
		.clockid		= CLOCK_MONOTONIC,
#ifdef HAVE_PERF_CTXSW
		.context_switch		= use_ctxsw,
#endif
	};
	unsigned long flag = PERF_FLAG_FD_NO_GROUP;

	return syscall(SYS_perf_event_open, &attr, pid, cpu, -1, flag);
}

/**
 * setup_perf_record - prepare recording perf events
 * @perf: data structure for perf record
 * @nr_cpu: total number of cpus to record
 * @pid: process id to record
 * @dirname: directory name to save perf record data
 * @use_ctxsw: whether to use context_switch attribute
 *
 * This function prepares recording linux perf events.  The perf_event
 * fd should be opened and mmaped for each cpu.
 *
 * It returns 0 for success, -1 if failed.  Callers should call
 * finish_perf_record() after recording.
 */
int setup_perf_record(struct uftrace_perf_writer *perf, int nr_cpu, int pid,
		      const char *dirname, int use_ctxsw)
{
	char filename[PATH_MAX];
	int fd, cpu;

	perf->event_fd = xcalloc(nr_cpu, sizeof(*perf->event_fd));
	perf->data_pos = xcalloc(nr_cpu, sizeof(*perf->data_pos));
	perf->page     = xcalloc(nr_cpu, sizeof(*perf->page));
	perf->fp       = xcalloc(nr_cpu, sizeof(*perf->fp));
	perf->nr_event = nr_cpu;

	memset(perf->event_fd, -1, nr_cpu * sizeof(fd));

	if (!PERF_CTXSW_AVAILABLE && use_ctxsw) {
		/* Operation not supported */
		pr_dbg("linux:schedule event is not supported for this kernel\n");
		use_ctxsw = 0;
	}

	for (cpu = 0; cpu < nr_cpu; cpu++) {
		fd = open_perf_event(pid, cpu, use_ctxsw);
		if (fd < 0) {
			int saved_errno = errno;

			pr_dbg("skipping perf event due to error: %m\n");

			if (saved_errno == EACCES)
				pr_dbg("please check %s\n", PERF_PARANOID_CHECK);

			use_perf = false;
			break;
		}
		perf->event_fd[cpu] = fd;

		perf->page[cpu] = mmap(NULL, PERF_MMAP_SIZE, PROT_READ|PROT_WRITE,
				       MAP_SHARED, fd, 0);
		if (perf->page[cpu] == MAP_FAILED) {
			pr_warn("failed to mmap perf event: %m\n");
			use_perf = false;
			break;
		}

		snprintf(filename, sizeof(filename),
			 "%s/perf-cpu%d.dat", dirname, cpu);

		perf->fp[cpu] = fopen(filename, "w");
		if (perf->fp[cpu] == NULL) {
			pr_warn("failed to create perf data file: %m\n");
			use_perf = false;
			break;
		}
	}

	if (!use_perf) {
		finish_perf_record(perf);
		return -1;
	}

	return 0;
}

/**
 * finish_perf_record - destroy data structure for perf recording
 * @perf: data structure for perf record
 *
 * This function releases all resources in the @perf.
 */
void finish_perf_record(struct uftrace_perf_writer *perf)
{
	int cpu;

	for (cpu = 0; cpu < perf->nr_event; cpu++) {
		close(perf->event_fd[cpu]);
		munmap(perf->page[cpu], PERF_MMAP_SIZE);
		if (perf->fp[cpu])
			fclose(perf->fp[cpu]);
	}

	free(perf->event_fd);
	free(perf->page);
	free(perf->data_pos);
	free(perf->fp);

	perf->event_fd = NULL;
	perf->page     = NULL;
	perf->data_pos = NULL;
	perf->fp       = NULL;

	perf->nr_event = 0;
}

/**
 * record_perf_data - record perf event data to file or socket
 * @perf: data structure for perf record
 * @cpu: cpu number for perf event
 * @sock: socket fd to send perf data
 *
 * This function copies contents in the perf ring buffer to a file
 * or a network socket.
 */
void record_perf_data(struct uftrace_perf_writer *perf, int cpu, int sock)
{
	struct perf_event_mmap_page *pc = perf->page[cpu];
	unsigned char *data = perf->page[cpu] + pc->data_offset;
	volatile uint64_t *ptr = (void *)&pc->data_head;
	uint64_t mask = pc->data_size - 1;
	uint64_t old, pos, start, end;
	unsigned long size;
	unsigned char *buf;

	pos = *ptr;
	old = perf->data_pos[cpu];

	/* ensure reading the data head first */
	read_memory_barrier();

	if (pos == old)
		return;

	size = pos - old;
	if (size > (unsigned long)(mask) + 1) {
		static bool once = true;

		if (once) {
			pr_warn("failed to keep up with mmap data.\n");
			once = false;
		}

		pc->data_tail = pos;
		perf->data_pos[cpu] = pos;
		return;
	}

	start = old;
	end   = pos;

	/* handle wrap around */
	if ((start & mask) + size != (end & mask)) {
		buf = &data[start & mask];
		size = mask + 1 - (start & mask);
		start += size;

		if (sock > 0)
			send_trace_perf_data(sock, cpu, buf, size);
		else if (fwrite(buf, 1, size, perf->fp[cpu]) != size) {
			pr_dbg("failed to write perf data: %m\n");
			goto out;
		}
	}

	buf = &data[start & mask];
	size = end - start;
	start += size;

	if (sock > 0)
		send_trace_perf_data(sock, cpu, buf, size);
	else if (fwrite(buf, 1, size, perf->fp[cpu]) != size)
		pr_dbg("failed to write perf data: %m\n");

out:
	/* ensure all reads are done before we write the tail. */
	full_memory_barrier();

	pc->data_tail = pos;
	perf->data_pos[cpu] = pos;
}
#endif /* HAVE_PERF_CLOCKID */

/**
 * setup_perf_data - preapre reading perf event data
 * @handle - uftrace data file handle
 *
 * This function prepares to read perf event data from perf-cpu*.dat
 * files.  It returns 0 on success, -1 on failure.  Callers should
 * call finish_perf_data() after reading all perf event data.
 */
int setup_perf_data(struct ftrace_file_handle *handle)
{
	struct uftrace_perf_reader *perf;
	glob_t globbuf;
	char *pattern;
	size_t i;
	int ret = -1;

	xasprintf(&pattern, "%s/perf-cpu*.dat", handle->dirname);
	if (glob(pattern, GLOB_ERR, NULL, &globbuf)) {
		pr_dbg("failed to search perf data file\n");
		handle->hdr.feat_mask &= ~PERF_EVENT;
		goto out;
	}

	perf = xcalloc(globbuf.gl_pathc, sizeof(*perf));

	for (i = 0; i < globbuf.gl_pathc; i++) {
		perf[i].fp = fopen(globbuf.gl_pathv[i], "r");
		if (perf[i].fp == NULL)
			pr_err("open failed: %s", globbuf.gl_pathv[i]);
	}

	handle->nr_perf = globbuf.gl_pathc;
	handle->perf = perf;
	ret = 0;

out:
	globfree(&globbuf);
	free(pattern);
	return ret;
}

/**
 * finish_perf_data - destroy resources for perf event data
 * @handle - uftrace data file handle
 *
 * This function releases all resources regarding perf event.
 */
void finish_perf_data(struct ftrace_file_handle *handle)
{
	int i;

	if (handle->perf == NULL)
		return;

	for (i = 0; i < handle->nr_perf; i++)
		fclose(handle->perf[i].fp);

	free(handle->perf);
	handle->perf = NULL;
}

static int read_perf_event(struct ftrace_file_handle *handle,
			   struct uftrace_perf_reader *perf)
{
	struct perf_event_header h;
	union {
		struct perf_context_switch_event cs;
		struct perf_task_event t;
		struct perf_comm_event c;
	} u;
	size_t len;
	int comm_len;

	if (perf->done || perf->fp == NULL)
		return -1;

again:
	if (fread(&h, sizeof(h), 1, perf->fp) != 1) {
		perf->done = true;
		return -1;
	}

	if (handle->needs_byte_swap) {
		h.type = bswap_32(h.type);
		h.misc = bswap_16(h.misc);
		h.size = bswap_16(h.size);
	}

	len = h.size - sizeof(h);

	switch (h.type) {
	case PERF_RECORD_SWITCH:
		if (fread(&u.cs, len, 1, perf->fp) != 1)
			return -1;

		if (handle->needs_byte_swap) {
			u.cs.sample_id.time = bswap_64(u.cs.sample_id.time);
			u.cs.sample_id.tid  = bswap_32(u.cs.sample_id.tid);
		}

		perf->u.ctxsw.out  = h.misc & PERF_RECORD_MISC_SWITCH_OUT;

		perf->time = u.cs.sample_id.time;
		perf->tid  = u.cs.sample_id.tid;
		break;

	case PERF_RECORD_FORK:
	case PERF_RECORD_EXIT:
		if (fread(&u.t, len, 1, perf->fp) != 1)
			return -1;

		if (handle->needs_byte_swap) {
			u.t.tid  = bswap_32(u.t.tid);
			u.t.pid  = bswap_32(u.t.pid);
			u.t.ppid = bswap_32(u.t.ppid);
			u.t.time = bswap_64(u.t.time);
		}

		perf->u.task.pid  = u.t.pid;
		perf->u.task.ppid = u.t.ppid;

		perf->time = u.t.time;
		perf->tid  = u.t.tid;
		break;

	case PERF_RECORD_COMM:
		/* length of comm event is variable */
		comm_len = ALIGN(len - sizeof(u.c.sample_id), 8);
		if (fread(&u.c, comm_len, 1, perf->fp) != 1)
			return -1;

		if (fread(&u.c.sample_id, sizeof(u.c.sample_id), 1, perf->fp) != 1)
			return -1;

		if (handle->needs_byte_swap) {
			u.c.tid            = bswap_32(u.c.tid);
			u.c.pid            = bswap_32(u.c.pid);
			u.c.sample_id.time = bswap_64(u.c.sample_id.time);
		}

		perf->u.comm.pid  = u.c.pid;
		perf->u.comm.exec = h.misc & PERF_RECORD_MISC_COMM_EXEC;
		strncpy(perf->u.comm.comm, u.c.comm, sizeof(perf->u.comm.comm));

		perf->time = u.c.sample_id.time;
		perf->tid  = u.c.tid;
		break;

	default:
		pr_dbg3("skip unknown event: %u\n", h.type);

		if (fseek(perf->fp, len, SEEK_CUR) < 0) {
			pr_warn("skipping perf data failed: %m\n");
			perf->done = true;
			return -1;
		}

		goto again;
	}

	if (unlikely(get_task_handle(handle, perf->tid) == NULL))
		goto again;

	perf->type = h.type;
	perf->valid = true;
	return 0;
}

/**
 * read_perf_data - read perf event data
 * @handle: uftrace data file handle
 *
 * This function reads perf events for each cpu data file and returns
 * the (cpu) index of earliest event.  The event info can be found in
 * @handle->perf[idx].
 *
 * It's important that callers should reset the valid bit after using
 * the event so that it can read next event for the cpu data file.
 */
int read_perf_data(struct ftrace_file_handle *handle)
{
	struct uftrace_perf_reader *perf;
	uint64_t min_time = ~0ULL;
	int best = -1;
	int i;

	for (i = 0; i < handle->nr_perf; i++) {
		perf = &handle->perf[i];

		if (perf->done)
			continue;
		if (!perf->valid) {
			if (read_perf_event(handle, perf) < 0)
				continue;
		}

		if (perf->time < min_time) {
			min_time = perf->time;
			best = i;
		}
	}

	handle->last_perf_idx = best;
	return best;
}

/**
 * get_perf_record - convert perf event into uftrace record format
 * @handle: uftrace data file handle
 * @perf: data structure for perf event
 *
 * This function converts the last perf event into an uftrace record
 * so that it can be handled in the fstack code like normal function
 * record.  This is useful for schedule event treated as a function.
 *
 * Normally this is called after read_perf_data() so it knows current
 * event.  But do_dump_file() calls it directly without the above
 * function in order to access to the raw file contents.
 */
struct uftrace_record * get_perf_record(struct ftrace_file_handle *handle,
					struct uftrace_perf_reader *perf)
{
	static struct uftrace_record rec;

	if (!perf->valid) {
		if (read_perf_event(handle, perf) < 0)
			return NULL;
	}

	rec.type  = UFTRACE_EVENT;
	rec.time  = perf->time;
	rec.magic = RECORD_MAGIC;

	switch (perf->type) {
	case PERF_RECORD_FORK:
		rec.addr = EVENT_ID_PERF_TASK;
		break;
	case PERF_RECORD_EXIT:
		rec.addr = EVENT_ID_PERF_EXIT;
		break;
	case PERF_RECORD_COMM:
		rec.addr = EVENT_ID_PERF_COMM;
		break;
	case PERF_RECORD_SWITCH:
		if (perf->u.ctxsw.out)
			rec.addr = EVENT_ID_PERF_SCHED_OUT;
		else
			rec.addr = EVENT_ID_PERF_SCHED_IN;
		break;
	}

	return &rec;
}

/**
 * update_perf_task_comm - read perf event data and update task's comm
 * @handle: uftrace data file handle
 *
 * This function reads perf events for each cpu data file and updates
 * task->comm for each PERF_RECORD_COMM.
 */
void update_perf_task_comm(struct ftrace_file_handle *handle)
{
	struct uftrace_perf_reader *perf;
	struct uftrace_task *task;
	int i;

	for (i = 0; i < handle->nr_perf; i++) {
		perf = &handle->perf[i];

		while (!perf->done) {
			if (read_perf_event(handle, perf) < 0)
				continue;

			if (perf->type != PERF_RECORD_COMM)
				continue;

			task = find_task(&handle->sessions, perf->tid);
			if (task == NULL)
				continue;

			memcpy(task->comm, perf->u.comm.comm, sizeof(task->comm));
		}
	}
}

/**
 * remove_perf_schedule_event - apply time filter for schedule event
 * @perf: data structure for perf event
 * @task: task has sched-out event
 * @time_filter: time threshold to remove
 *
 * This function reads perf event from the current cpu and compares it
 * to match to the current task's schedule event.  If so and the time delta
 * is less than the time filter, it removes the event and returns #true.
 * Otherwise returns #false.
 *
 * See __fstack_consume() how it deals with peeking a perf event.
 */
bool remove_perf_schedule_event(struct uftrace_perf_reader *perf,
				struct ftrace_task_handle *task,
				uint64_t time_filter)
{
	struct uftrace_record *rec = task->rstack;  /* sched-out */

	if (read_perf_event(task->h, perf) < 0)
		return false;

	perf->peek = true;
	perf->valid = true;

	if (perf->tid != task->tid)
		return false;

	if (perf->type != PERF_RECORD_SWITCH)
		return false;

	if (perf->u.ctxsw.out)
		return false;

	if (perf->time - rec->time >= time_filter)
		return false;

	perf->peek = false;
	perf->valid = false;
	return true;
}
