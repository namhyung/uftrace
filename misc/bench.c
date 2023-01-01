#include <stdlib.h>

int foo(volatile int *ptr)
{
	*ptr += 1;
	return *ptr;
}

void baz(volatile int *ptr)
{
	*ptr += 1;
}

int bar(volatile int *ptr)
{
	baz(ptr);
	return *ptr;
}

int bench(int count)
{
	volatile int result = 0;

	for (int i = 0; i < count; i++) {
		if (i % 2 == 0)
			foo(&result);
		else
			bar(&result);
	}
	return result;
}

int main(int argc, char *argv[])
{
	int n = 1;
	int loop = 1000000;
	int result = 0;

	if (argc > 1)
		n = atoi(argv[1]);
	if (argc > 2)
		loop = atoi(argv[2]);

	for (int i = 0; i < n; i++)
		result += bench(loop);

	return result ? 0 : 1;
}
