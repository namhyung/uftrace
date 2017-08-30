#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

int main(void)
{
	struct perf_event_attr attr = {
		.context_switch	= 1,
	};

	syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
	return 0;
}
