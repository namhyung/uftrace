#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include "../utils/compiler.h"

__attribute__((noinline)) void foo(void);
__attribute__((noinline)) void bar(void);

volatile int count;
volatile int max = 3;

void foo(void)
{
	while (count < max)
		bar();
}

void bar(void)
{
	int prev = count;

	/* wait for signal */
	while (prev == count)
		cpu_relax();
}

void sighandler(int sig)
{
	count++;
}

int main(int argc, char *argv[])
{
	struct itimerval it = {
		.it_value = {
			.tv_usec = 1,
		},
		.it_interval = {
			.tv_usec = 1,
		},
	};

	if (argc > 1)
		max = atoi(argv[1]);

	signal(SIGPROF, sighandler);
	setitimer(ITIMER_PROF, &it, NULL);

	foo();

	return 0;
}
