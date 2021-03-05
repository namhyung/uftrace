#include <signal.h>
#include <stdlib.h>

volatile int dummy;

typedef void (*sighandler_t)(int sig);
sighandler_t old_handler;

int foo(void)
{
	return dummy;
}

void bar(int n)
{
	dummy = n;
}

void sighandler(int sig)
{
	bar(sig);

	if (old_handler != SIG_DFL)
		old_handler(sig);
}

int main(int argc, char *argv[])
{
	int sig = SIGUSR1;

	if (argc > 1)
		sig = atoi(argv[1]);

	foo();
	old_handler = signal(sig, sighandler);
	raise(sig);
	foo();

	return 0;
}
