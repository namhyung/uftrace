/*
 * This is a test to trace functions in a library.
 * This file is not built with tracing, but library functions are,
 * so the result will only contain lib_a() and its children.
 */
#include <stdlib.h>
#include <unistd.h>

extern int lib_a(int mask);

int foo(void)
{
	return lib_a(0xfff);
}

int main(int argc, char *argv[])
{
	int ret = 0;

	if (argc > 1)
		ret = atoi(argv[1]);

	ret += foo();
	return ret ? 0 : 1;
}
