#include <stdlib.h>

extern int lib_a(int);
extern void foo(int);

int main(int argc, char *argv[])
{
	int n = 1;

	if (argc > 1)
		n = atoi(argv[1]);

	lib_a(n);
	foo(n);

	return 0;
}
