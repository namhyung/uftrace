#include <signal.h>
#include <stdlib.h>

__attribute__((noinline)) void foo(void);
__attribute__((noinline)) void bar(int n);

volatile int dummy;

void foo(void)
{
	if (dummy == 0)
		dummy = 1;
	else
		dummy = 0;
}

void bar(int n)
{
	dummy = n;
}

void sighandler(int sig)
{
	bar(sig);
}

int main(int argc, char *argv[])
{
	int sig = SIGUSR1;

	if (argc > 1)
		sig = atoi(argv[1]);

	foo();
	signal(sig, sighandler);
	raise(sig);
	foo();

	return 0;
}
