#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>

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
		;
}

static void shared_work(void)
{
	work();
}

void task_a(void)
{
	pin_to_cpu(0);
	shared_work();
}
void task_b(void)
{
	pin_to_cpu(1);
	shared_work();
}
void task_c(void)
{
	pin_to_cpu(2);
	work();
}
void task_d(void)
{
	pin_to_cpu(3);
	shared_work();
}

int main(void)
{
	int ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	task_a();
	task_b();
	if (ncpus > 2)
		task_c();
	if (ncpus > 3)
		task_d();

	return 0;
}
