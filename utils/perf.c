#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "uftrace.h"
#include "utils/perf.h"
#include "utils/compiler.h"

/* It needs to synchronize records using monotonic clock */
#ifdef HAVE_PERF_CLOCKID

static bool use_perf = true;

static int open_perf_event(int pid, int cpu)
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
		.use_clockid		= 1,
		.clockid		= CLOCK_MONOTONIC,
		INIT_CTXSW_ATTR
	};
	unsigned long flag = PERF_FLAG_FD_NO_GROUP;
	int fd;

	if (!PERF_CTXSW_AVAILABLE) {
		/* Operation not supported */
		errno = ENOTSUP;
		return -1;
	}

	fd = syscall(SYS_perf_event_open, &attr, pid, cpu, -1, flag);
	if (fd < 0)
		pr_dbg("perf event open failed: %m\n");

	return fd;
}

int setup_perf_record(struct uftrace_perf_writer *perf, int nr_cpu, int pid,
		      const char *dirname)
{
	char filename[PATH_MAX];
	int fd, cpu;

	perf->event_fd = xcalloc(nr_cpu, sizeof(*perf->event_fd));
	perf->data_pos = xcalloc(nr_cpu, sizeof(*perf->data_pos));
	perf->page     = xcalloc(nr_cpu, sizeof(*perf->page));
	perf->fp       = xcalloc(nr_cpu, sizeof(*perf->fp));
	perf->nr_event = nr_cpu;

	memset(perf->event_fd, -1, nr_cpu * sizeof(fd));

	for (cpu = 0; cpu < nr_cpu; cpu++) {
		fd = open_perf_event(pid, cpu);
		if (fd < 0) {
			pr_dbg("failed to open perf event: %m\n");
			use_perf = false;
			break;
		}
		perf->event_fd[cpu] = fd;

		perf->page[cpu] = mmap(NULL, PERF_MMAP_SIZE, PROT_READ|PROT_WRITE,
				       MAP_SHARED, fd, 0);
		if (perf->page[cpu] == MAP_FAILED) {
			pr_dbg("failed to mmap perf event: %m\n");
			use_perf = false;
			break;
		}

		snprintf(filename, sizeof(filename),
			 "%s/perf-cpu%d.dat", dirname, cpu);

		perf->fp[cpu] = fopen(filename, "w");
		if (perf->fp[cpu] == NULL) {
			pr_dbg("failed to create perf data file: %m\n");
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
