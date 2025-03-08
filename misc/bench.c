#include <stdlib.h>

int leaf(volatile int *ptr)
{
	*ptr += 1;
	return *ptr;
}

void nested_child(volatile int *ptr)
{
	*ptr += 1;
}

int nested_parent(volatile int *ptr)
{
	nested_child(ptr);
	return *ptr;
}

int bench(int count)
{
	volatile int result = 0;
	int i;

	for (i = 0; i < count; i++) {
		if (i % 2 == 0)
			leaf(&result);
		else
			nested_parent(&result);
	}
	return result;
}

int main(int argc, char *argv[])
{
	int n = 1;
	int i;
	int loop = 1000000;
	int result = 0;

	if (argc > 1)
		n = atoi(argv[1]);
	if (argc > 2)
		loop = atoi(argv[2]);

	for (i = 0; i < n; i++)
		result += bench(loop);

	return result ? 0 : 1;
}
