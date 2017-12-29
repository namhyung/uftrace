#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/list.h"

struct pmu_data {
	struct list_head list;
	enum uftrace_event_id evt_id;
	int fd[];
};

static LIST_HEAD(pmu_fds);

static int open_perf_event(uint32_t type, uint64_t config, int group_fd)
{
	struct perf_event_attr attr = {
		.size			= sizeof(attr),
		.type			= type,
		.config			= config,
		.exclude_kernel		= 1,
		.read_format		= PERF_FORMAT_GROUP,
	};
	unsigned long flag = PERF_FLAG_FD_CLOEXEC;

	return syscall(SYS_perf_event_open, &attr, 0, -1, group_fd, flag);
}

static void read_perf_event(int fd, void *buf, ssize_t len)
{
	if (read(fd, buf, len) != len)
		pr_dbg("reading perf_event failed: %m\n");
}

int prepare_pmu_event(enum uftrace_event_id id)
{
	struct pmu_data *pd;

	list_for_each_entry(pd, &pmu_fds, list) {
		if (pd->evt_id == id)
			return 0;
	}

	pr_dbg("setup PMU event (%d) using perf syscall\n", id);

	switch (id) {
	case EVENT_ID_READ_PMU_CYCLE:
		pd = xmalloc(sizeof(*pd) + 2 * sizeof(int));
		pd->evt_id = id;

		pd->fd[0] = open_perf_event(PERF_TYPE_HARDWARE,
					    PERF_COUNT_HW_CPU_CYCLES,
					    -1);
		if (pd->fd[0] < 0) {
			pr_warn("failed to open 'cpu-cycles' perf event: %m\n");
			free(pd);
			return -1;
		}

		pd->fd[1] = open_perf_event(PERF_TYPE_HARDWARE,
					    PERF_COUNT_HW_INSTRUCTIONS,
					    pd->fd[0]);
		if (pd->fd[1] < 0) {
			pr_warn("failed to open 'instructions' perf event: %m\n");
			close(pd->fd[0]);
			free(pd);
			return -1;
		}
		break;

	case EVENT_ID_READ_PMU_CACHE:
		pd = xmalloc(sizeof(*pd) + 2 * sizeof(int));
		pd->evt_id = id;

		pd->fd[0] = open_perf_event(PERF_TYPE_HARDWARE,
					    PERF_COUNT_HW_CACHE_REFERENCES,
					    -1);
		if (pd->fd[0] < 0) {
			pr_warn("failed to open 'cache-references' perf event: %m\n");
			free(pd);
			return -1;
		}

		pd->fd[1] = open_perf_event(PERF_TYPE_HARDWARE,
					    PERF_COUNT_HW_CACHE_MISSES,
					    pd->fd[0]);
		if (pd->fd[1] < 0) {
			pr_warn("failed to open 'cache-misses' perf event: %m\n");
			close(pd->fd[0]);
			free(pd);
			return -1;
		}
		break;

	default:
		pr_dbg("unknown pmu event: %d - ignoring\n", id);
		return 0;
	}

	list_add_tail(&pd->list, &pmu_fds);
	return 0;
}

int read_pmu_event(enum uftrace_event_id id, void *buf)
{
	struct pmu_data *pd;
	struct uftrace_pmu_cycle *cycle;
	struct uftrace_pmu_cache *cache;
	struct {
		uint64_t	nr_members;
		uint64_t	data[2];
	} read_buf;

	list_for_each_entry(pd, &pmu_fds, list) {
		if (pd->evt_id == id)
			break;
	}

	if (list_no_entry(pd, &pmu_fds, list)) {
		/* unsupported pmu events */
		return -1;
	}

	switch (id) {
	case EVENT_ID_READ_PMU_CYCLE:
		/* read group events at once */
		read_perf_event(pd->fd[0], &read_buf, sizeof(read_buf));

		cycle = buf;
		cycle->cycles = read_buf.data[0];
		cycle->instrs = read_buf.data[1];
		break;
	case EVENT_ID_READ_PMU_CACHE:
		/* read group events at once */
		read_perf_event(pd->fd[0], &read_buf, sizeof(read_buf));

		cache = buf;
		cache->refers = read_buf.data[0];
		cache->misses = read_buf.data[1];
		break;
	default:
		break;
	}

	return 0;
}

void finish_pmu_event(void)
{
	struct pmu_data *pd, *tmp;

	list_for_each_entry_safe(pd, tmp, &pmu_fds, list) {
		list_del(&pd->list);

		switch (pd->evt_id) {
		case EVENT_ID_READ_PMU_CYCLE:
		case EVENT_ID_READ_PMU_CACHE:
			close(pd->fd[0]);
			close(pd->fd[1]);
			break;
		default:
			break;
		}
		free(pd);
	}
}
