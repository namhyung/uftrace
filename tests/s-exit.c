#include <stdlib.h>

static void foo(int status)
{
	exit(status);
}

int main(int argc, char *argv[])
{
	foo(argc - 1);
	return 0;
}
