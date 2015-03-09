#include <unistd.h>
#include <stdlib.h>

static volatile int __attribute__((noinline)) a(int);
static volatile int __attribute__((noinline)) b(int);
static volatile int __attribute__((noinline)) c(int);

static volatile int a(int n)
{
	return b(n) - 1;
}

static volatile int b(int n)
{
	return c(n) + 1;
}

static volatile int c(int n)
{
	return n;
}

int main(int argc, char *argv[])
{
	int i;
	int n;

	if (argc > 1)
		n = strtol(argv[1], NULL, 0);

	if (fork() < 0)
		return -1;

	for (i = 0; i < 1000; i++)
		n += a(n);

	return n;
}
