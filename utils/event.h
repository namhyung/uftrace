#ifndef UFTRACE_EVENT_H
#define UFTRACE_EVENT_H

#include <stdbool.h>
#include <stdint.h>

struct uftrace_data;
struct uftrace_symbol;

/* please see man proc(5) for /proc/[pid]/statm */
struct uftrace_proc_statm {
	uint64_t vmsize; /* total program size in KB */
	uint64_t vmrss; /* resident set size in KB */
	uint64_t shared; /* shared rss in KB (Rssfile + RssShmem) */
};

struct uftrace_page_fault {
	uint64_t major; /* major page faults */
	uint64_t minor; /* minor page faults */
};

struct uftrace_pmu_cycle {
	uint64_t cycles; /* cpu cycles */
	uint64_t instrs; /* cpu instructions */
};

struct uftrace_pmu_cache {
	uint64_t refers; /* cache references */
	uint64_t misses; /* cache misses */
};

struct uftrace_pmu_branch {
	uint64_t branch; /* branch instructions */
	uint64_t misses; /* branch misses */
};

char *event_get_name(struct uftrace_data *handle, unsigned evt_id);
char *event_get_data_str(struct uftrace_data *handle, unsigned evt_id, void *data, int len,
			 struct uftrace_symbol *sym, bool verbose);

void finish_events_file(struct uftrace_data *handle);
int read_events_file(struct uftrace_data *handle);

#endif /* UFTRACE_EVENT_H */
