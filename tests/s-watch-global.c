#include <stdlib.h>

volatile int mydata;

void bar(int n)
{
	if (n)
		mydata = -1;
}

void foo(int n)
{
	mydata = 1;
	bar(n);
	mydata = 2;
}

int main(int argc, char *argv[])
{
	int n = 0;

	if (argc > 1)
		n = atoi(argv[1]);

	foo(n);
	return 0;
}
