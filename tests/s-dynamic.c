#include <stdio.h>
#include <stdlib.h>

int foo(int n)
{
	volatile int i = 0;
	int sum = 0;

	for (i = 0; i < n; i++)
		sum += i;

	return sum;
}

int bar(int n)
{
	int i = 0;
	volatile int sum = 0;

	for (i = 0; i < n; i++)
		sum += i;

	return sum;
}

int main(int argc, char *argv[])
{
	int n = 5;

	if (argc > 1)
		n = atoi(argv[1]);

	foo(n);
	bar(n);

	return 0;
}
