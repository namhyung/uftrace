#include <execinfo.h>
#include <stdlib.h>

int foo(int count)
{
	void *buf[count];

	return backtrace(buf, count);
}

int c(int n)
{
	return foo(n);
}

int b(int n)
{
	return c(n);
}

int a(int n)
{
	return b(n);
}

int main(int argc, char *argv[])
{
	int n = 5;

	if (argc > 1)
		n = atoi(argv[1]);

	a(n);
	return 0;
}
