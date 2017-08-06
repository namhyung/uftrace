#include <stdlib.h>
#include <unistd.h>

int bar(int do_sleep)
{
	if (do_sleep)
		usleep(100);
}

int foo(int do_sleep)
{
	if (do_sleep)
		usleep(1000);

	bar(do_sleep);
}

int main(int argc, char *argv[])
{
	int do_sleep = 0;

	if (argc > 1)
		do_sleep = atoi(argv[1]);

	if (do_sleep)
		usleep(10);

	foo(do_sleep);
	return 0;
}
