#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
	struct perf_event_attr attr = {
		.context_switch = 1,
	};

	syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);

	if (PERF_RECORD_SWITCH != 14 || PERF_RECORD_MISC_SWITCH_OUT != (1 << 13))
		return -1;

	return 0;
}
