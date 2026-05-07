#define _GNU_SOURCE
#include <sched.h>

static void pin_to_cpu(int cpu)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

static void work(void)
{
	volatile int i;
	for (i = 0; i < 10000; i++)
		continue;
}

static void shared_work(void)
{
	work();
}

void func_cpu0(void)
{
	pin_to_cpu(0);
	shared_work();
}
void func_cpu1(void)
{
	pin_to_cpu(1);
	shared_work();
}

int main(void)
{
	func_cpu0();
	func_cpu1();

	return 0;
}
