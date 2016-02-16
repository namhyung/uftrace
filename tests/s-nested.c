#include <stdlib.h>

int foo(void)
{
	int count = 0;

	__attribute__((noinline)) int foo_internal(void) {
		return count++;
	}

	return foo_internal();
}

int bar(void)
{
	int arr[3] = { 2, 3, 1 };

	__attribute__((noinline)) int compar(const void *a, const void *b) {
		const int *ai = a;
		const int *bi = b;

		return *ai - *bi;
	}

	qsort(arr, sizeof(arr)/sizeof(arr[0]), sizeof(arr[0]), compar);

	if (arr[0] != 1 || arr[1] != 2 || arr[2] != 3)
		return 1;
	return 0;
}

int main(int argc, char *argv[])
{
	int n = 1;

	if (argc > 1)
		n = strtol(argv[1], NULL, 0);

	while (n--)
		foo();

	return bar();
}
