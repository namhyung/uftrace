#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>

int __attribute__((noinline)) foo(int);
int __attribute__((noinline)) bar(int);

int foo(int c)
{
	char *ptr = alloca(c);
	snprintf(ptr, c, "%s", "hello world\n");
	return c;
}

int bar(int c)
{
	return foo(c) + foo(c - 2);
}

int main(int argc, char *argv[])
{
	int c = 12;

	if (argc > 1)
		c = atoi(argv[1]);

	foo(c);
	bar(c);

	return 0;
}
