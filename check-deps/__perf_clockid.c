#define _GNU_SOURCE
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

int main(void)
{
	struct perf_event_attr attr = {
		.use_clockid	= 1,
		.clockid	= CLOCK_MONOTONIC,
	};

	syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
	return 0;
}
