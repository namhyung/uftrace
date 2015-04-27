#include <signal.h>
#include <stdlib.h>

void sighandler(int sig)
{
	/* do nothing */
}

int main(int argc, char *argv[])
{
	int sig = SIGUSR1;

	if (argc > 1)
		sig = atoi(argv[1]);

	signal(sig, sighandler);
	raise(sig);

	return 0;
}
