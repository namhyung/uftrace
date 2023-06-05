#include <stdlib.h>
#include <unistd.h>

int bar(void)
{
	usleep(100);
}

int foo(void)
{
	usleep(1000);
	bar();
}

int main(int argc, char *argv[])
{
	int do_sleep = 0;

	if (argc > 1)
		do_sleep = atoi(argv[1]);

	if (do_sleep) {
		usleep(10);
		foo();
		bar();
	}
	foo();

	return 0;
}
