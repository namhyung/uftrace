#include <alloca.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int foo(int c)
{
	char *ptr = alloca(c);
	strncpy(ptr, "hello world\n", c);
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
