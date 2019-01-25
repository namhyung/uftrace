#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "event"
#define PR_DOMAIN DBG_EVENT

#include "uftrace.h"
#include "utils/event.h"
#include "utils/fstack.h"
#include "utils/kernel.h"
#include "utils/utils.h"

#define EVENT_FILE_NAME "events.txt"

/**
 * event_get_name - find event name from event id
 * @handle - handle to uftrace data
 * @evt_id - event id
 *
 * This function returns a string of event name matching to @evt_id.
 * Callers must free the returned string.  This is moved from utils.c
 * since it needs to call libtraceevent function for kernel events
 * which is not linked into libmcount.
 */
char *event_get_name(struct uftrace_data *handle, unsigned evt_id)
{
	char *evt_name = NULL;
	struct event_format *event;

	if (evt_id == EVENT_ID_EXTERN_DATA) {
		evt_name = xstrdup("external-data");
		goto out;
	}

	if (evt_id >= EVENT_ID_USER) {
		struct uftrace_event *ev;

		list_for_each_entry(ev, &handle->events, list) {
			if (ev->id == evt_id) {
				xasprintf(&evt_name, "%s:%s", ev->provider, ev->event);
				goto out;
			}
		}
		xasprintf(&evt_name, "user_event:%u", evt_id);
		goto out;
	}

	if (evt_id >= EVENT_ID_PERF) {
		const char *event_name;

		switch (evt_id) {
		case EVENT_ID_PERF_SCHED_IN:
			event_name = "sched-in";
			break;
		case EVENT_ID_PERF_SCHED_OUT:
			event_name = "sched-out";
			break;
		case EVENT_ID_PERF_SCHED_OUT_PREEMPT:
			event_name = "sched-out (pre-empted)";
			break;
		case EVENT_ID_PERF_SCHED_BOTH:
			event_name = "schedule";
			break;
		case EVENT_ID_PERF_SCHED_BOTH_PREEMPT:
			event_name = "schedule (pre-empted)";
			break;
		case EVENT_ID_PERF_TASK:
			event_name = "task-new";
			break;
		case EVENT_ID_PERF_EXIT:
			event_name = "task-exit";
			break;
		case EVENT_ID_PERF_COMM:
			event_name = "task-name";
			break;
		default:
			event_name = "unknown";
			break;
		}
		xasprintf(&evt_name, "linux:%s", event_name);
		goto out;
	}

	if (evt_id >= EVENT_ID_BUILTIN) {
		switch (evt_id) {
		case EVENT_ID_READ_PROC_STATM:
			xasprintf(&evt_name, "read:proc/statm");
			break;
		case EVENT_ID_READ_PAGE_FAULT:
			xasprintf(&evt_name, "read:page-fault");
			break;
		case EVENT_ID_READ_PMU_CYCLE:
			xasprintf(&evt_name, "read:pmu-cycle");
			break;
		case EVENT_ID_READ_PMU_CACHE:
			xasprintf(&evt_name, "read:pmu-cache");
			break;
		case EVENT_ID_READ_PMU_BRANCH:
			xasprintf(&evt_name, "read:pmu-branch");
			break;
		case EVENT_ID_DIFF_PROC_STATM:
			xasprintf(&evt_name, "diff:proc/statm");
			break;
		case EVENT_ID_DIFF_PAGE_FAULT:
			xasprintf(&evt_name, "diff:page-fault");
			break;
		case EVENT_ID_DIFF_PMU_CYCLE:
			xasprintf(&evt_name, "diff:pmu-cycle");
			break;
		case EVENT_ID_DIFF_PMU_CACHE:
			xasprintf(&evt_name, "diff:pmu-cache");
			break;
		case EVENT_ID_DIFF_PMU_BRANCH:
			xasprintf(&evt_name, "diff:pmu-branch");
			break;
		case EVENT_ID_WATCH_CPU:
			xasprintf(&evt_name, "watch:cpu");
			break;
		case EVENT_ID_WATCH_ADDR:
			xasprintf(&evt_name, "watch:addr");
			break;
		case EVENT_ID_WATCH_VAR:
			xasprintf(&evt_name, "watch:var");
			break;
		default:
			xasprintf(&evt_name, "builtin_event:%u", evt_id);
			break;
		}
		goto out;
	}

	/* kernel events */
	if (has_kernel_data(handle->kernel)) {
		char buf[512];

		event = kparser_find_event(&handle->kernel->parser, evt_id);
		kparser_event_name(&handle->kernel->parser, event, buf, sizeof(buf));
		evt_name = xstrdup(buf);
	}

out:
	return evt_name;
}

/**
 * event_get_data_str - convert event data to a string
 * @handle - handle to uftrace data
 * @evt_id - event id
 * @data - raw event data
 * @len - length of event data
 * @sym - associated symbol (if any)
 * @verbose - whether it needs the verbose format
 *
 * This function returns a string of event name matching to @evt_id.
 * Callers must free the returned string.
 */
char *event_get_data_str(struct uftrace_data *handle, unsigned evt_id, void *data, int len,
			 struct uftrace_symbol *sym, bool verbose)
{
	char *str = NULL;
	const char *diff = "";
	char vbuf[128];
	union {
		struct uftrace_proc_statm statm;
		struct uftrace_page_fault pgfault;
		struct uftrace_pmu_cycle cycle;
		struct uftrace_pmu_cache cache;
		struct uftrace_pmu_branch branch;
		struct uftrace_watch_event watch;
	} u;

	switch (evt_id) {
	case EVENT_ID_EXTERN_DATA:
		xasprintf(&str, "msg=\"%s\"", (char *)data);
		break;

	case EVENT_ID_PERF_COMM:
		xasprintf(&str, "comm=\"%s\"", (char *)data);
		break;

	case EVENT_ID_DIFF_PROC_STATM:
		if (verbose)
			diff = "+";
		/* fall through */
	case EVENT_ID_READ_PROC_STATM:
		memcpy(&u.statm, data, sizeof(u.statm));
		xasprintf(&str,
			  "vmsize=%s%" PRIu64 "KB vmrss=%s%" PRIu64 "KB shared=%s%" PRIu64 "KB",
			  diff, u.statm.vmsize, diff, u.statm.vmrss, diff, u.statm.shared);
		break;

	case EVENT_ID_DIFF_PAGE_FAULT:
		if (verbose)
			diff = "+";
		/* fall through */
	case EVENT_ID_READ_PAGE_FAULT:
		memcpy(&u.pgfault, data, sizeof(u.pgfault));
		xasprintf(&str, "major=%s%" PRIu64 " minor=%s%" PRIu64, diff, u.pgfault.major, diff,
			  u.pgfault.minor);
		break;

	case EVENT_ID_DIFF_PMU_CYCLE:
		if (verbose)
			diff = "+";
		/* fall through */
	case EVENT_ID_READ_PMU_CYCLE:
		memcpy(&u.cycle, data, sizeof(u.cycle));
		xasprintf(&str, "cycles=%s%" PRIu64 " instructions=%s%" PRIu64, diff,
			  u.cycle.cycles, diff, u.cycle.instrs);
		if (diff[0] == '+') {
			snprintf(vbuf, sizeof(vbuf), "IPC=%.2f",
				 (float)u.cycle.instrs / u.cycle.cycles);
			str = strjoin(str, vbuf, " ");
		}
		break;

	case EVENT_ID_DIFF_PMU_CACHE:
		if (verbose)
			diff = "+";
		/* fall through */
	case EVENT_ID_READ_PMU_CACHE:
		memcpy(&u.cache, data, sizeof(u.cache));
		xasprintf(&str, "refers=%s%" PRIu64 " misses=%s%" PRIu64, diff, u.cache.refers,
			  diff, u.cache.misses);
		if (diff[0] == '+') {
			snprintf(vbuf, sizeof(vbuf), "hit=%.2f%%",
				 100.0 * (u.cache.refers - u.cache.misses) / u.cache.refers);
			str = strjoin(str, vbuf, " ");
		}
		break;

	case EVENT_ID_DIFF_PMU_BRANCH:
		if (verbose)
			diff = "+";
		/* fall through */
	case EVENT_ID_READ_PMU_BRANCH:
		memcpy(&u.branch, data, sizeof(u.branch));
		xasprintf(&str, "branch=%s%" PRIu64 " misses=%s%" PRIu64, diff, u.branch.branch,
			  diff, u.branch.misses);
		if (diff[0] == '+') {
			snprintf(vbuf, sizeof(vbuf), "predict=%.2f%%",
				 100.0 * (u.branch.branch - u.branch.misses) / u.branch.branch);
			str = strjoin(str, vbuf, " ");
		}
		break;

	case EVENT_ID_WATCH_CPU:
		memcpy(&u.watch, data, sizeof(u.watch.cpu));
		xasprintf(&str, "cpu=%d", u.watch.cpu);
		break;

	case EVENT_ID_WATCH_ADDR:
		memset(&u.watch.addr, 0, sizeof(u.watch.addr));
		if (data_is_lp64(handle)) {
			memcpy(&u.watch.addr.addr, data, 8);
			memcpy(&u.watch.addr.data, data + 8, len - 8);
		}
		else {
			memcpy(&u.watch.addr.addr, data, 4);
			memcpy(&u.watch.addr.data, data + 4, len - 4);
		}
		xasprintf(&str, "[%#" PRIx64 "]=%" PRIx64, u.watch.addr.addr, u.watch.addr.data);
		break;

	case EVENT_ID_WATCH_VAR:
		u.watch.var.addr = 0;
		u.watch.var.data = 0;

		if (data_is_lp64(handle)) {
			memcpy(&u.watch.var.addr, data, 8);
			memcpy(&u.watch.var.data, data + 8, len - 8);
		}
		else {
			memcpy(&u.watch.var.addr, data, 4);
			memcpy(&u.watch.var.data, data + 4, len - 4);
		}

		if (sym)
			xasprintf(&str, "%s=%" PRIx64, sym->name, u.watch.var.data);
		else
			xasprintf(&str, "[%#" PRIx64 "]=%" PRIx64, u.watch.var.addr,
				  u.watch.var.data);
		break;

	default:
		/* kernel tracepoints */
		if (evt_id < EVENT_ID_BUILTIN)
			str = xstrdup((char *)data);
		else
			pr_dbg3("unexpected event data: %u\n", evt_id);
		break;
	}

	return str;
}

/**
 * finish_events_file - cleanup memory for events in the given handle
 * @handle: uftrace_data data structure
 */
void finish_events_file(struct uftrace_data *handle)
{
	struct uftrace_event *ev, *tmp;

	list_for_each_entry_safe(ev, tmp, &handle->events, list) {
		list_del(&ev->list);
		free(ev->provider);
		free(ev->event);
		free(ev);
	}
}

/**
 * read_events_file - read 'events.txt' file from data directory
 * @handle: uftrace_data data structure
 *
 * This function read the events file in the @handle->dirname and build event
 * information (for userspace).
 *
 * It returns 0 for success, -1 for error.
 */
int read_events_file(struct uftrace_data *handle)
{
	FILE *fp;
	char *fname = NULL;
	char *line = NULL;
	size_t sz = 0;

	xasprintf(&fname, "%s/%s", handle->dirname, EVENT_FILE_NAME);

	fp = fopen(fname, "r");
	if (fp == NULL) {
		/* it might hit no events, so no file is ok */
		if (errno == ENOENT)
			errno = 0;

		free(fname);
		return -errno;
	}

	pr_dbg("reading %s file\n", fname);
	while (getline(&line, &sz, fp) >= 0) {
		char provider[512];
		char event[512];
		unsigned evt_id;
		struct uftrace_event *ev;

		if (!strncmp(line, "EVENT", 5) &&
		    sscanf(line + 7, "%u %[^:]:%s", &evt_id, provider, event) == 3) {
			ev = xmalloc(sizeof(*ev));
			ev->id = evt_id;
			ev->provider = xstrdup(provider);
			ev->event = xstrdup(event);

			list_add_tail(&ev->list, &handle->events);
		}
	}

	free(line);
	fclose(fp);
	free(fname);
	return 0;
}

#ifdef UNIT_TEST

TEST_CASE(event_name)
{
	unsigned i;
	struct uftrace_data handle = {};
	struct {
		unsigned evt_id;
		char *evt_name;
	} expected[] = {
		{ EVENT_ID_EXTERN_DATA, "external-data" },
		{ EVENT_ID_PERF_SCHED_IN, "linux:sched-in" },
		{ EVENT_ID_PERF_COMM, "linux:task-name" },
		{ EVENT_ID_READ_PROC_STATM, "read:proc/statm" },
		{ EVENT_ID_DIFF_PROC_STATM, "diff:proc/statm" },
		{ EVENT_ID_READ_PMU_CACHE, "read:pmu-cache" },
		{ EVENT_ID_DIFF_PMU_CACHE, "diff:pmu-cache" },
		{ EVENT_ID_WATCH_CPU, "watch:cpu" },
	};

	pr_dbg("testing event name strings\n");
	for (i = 0; i < ARRAY_SIZE(expected); i++) {
		char *got = event_get_name(&handle, expected[i].evt_id);
		TEST_STREQ(expected[i].evt_name, got);
		free(got);
	}

	return TEST_OK;
}

TEST_CASE(event_data)
{
	char msg[] = "this is external data.";
	char comm[] = "taskname";
	struct uftrace_data handle = {};
	struct uftrace_page_fault pgfault = { 1977, 1102 };
	struct uftrace_pmu_cycle cycle = { 1024, 2048 };
	int cpu = 123;
	unsigned i;

	struct {
		unsigned evt_id;
		void *data;
		char *str;
	} expected[] = {
		{ EVENT_ID_EXTERN_DATA, msg, "msg=\"this is external data.\"" },
		{ EVENT_ID_PERF_COMM, comm, "comm=\"taskname\"" },
		{ EVENT_ID_READ_PAGE_FAULT, &pgfault, "major=1977 minor=1102" },
		{ EVENT_ID_DIFF_PMU_CYCLE, &cycle, "cycles=+1024 instructions=+2048 IPC=2.00" },
		{ EVENT_ID_WATCH_CPU, &cpu, "cpu=123" },
	};

	pr_dbg("testing event data strings\n");
	for (i = 0; i < ARRAY_SIZE(expected); i++) {
		char *got = event_get_data_str(&handle, expected[i].evt_id, expected[i].data, 0,
					       NULL, true);
		TEST_STREQ(expected[i].str, got);
		free(got);
	}
	return TEST_OK;
}

TEST_CASE(event_read_from_file)
{
	FILE *fp;
	char *fname = NULL;
	struct uftrace_event *ev;

	struct uftrace_data handle = {
		.dirname = ".",
	};
	INIT_LIST_HEAD(&handle.events);

	xasprintf(&fname, "%s/%s", handle.dirname, EVENT_FILE_NAME);

	fp = fopen(fname, "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "EVENT: 1000000 uftrace:event\n");
	fclose(fp);

	pr_dbg("testing event read from file\n");
	TEST_EQ(read_events_file(&handle), 0);

	ev = list_first_entry(&handle.events, typeof(*ev), list);
	TEST_EQ(ev->id, EVENT_ID_USER);
	TEST_STREQ(ev->provider, "uftrace");
	TEST_STREQ(ev->event, "event");

	finish_events_file(&handle);

	TEST_EQ(unlink(fname), 0);
	free(fname);

	return TEST_OK;
}

#endif /* UNIT_TEST */
