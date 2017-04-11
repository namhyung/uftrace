#include <stdlib.h>
#include <sys/sdt.h>

void foo(int n)
{
	STAP_PROBE(uftrace, event);
}

int main(int argc, char *argv[])
{
	int n = 1;

	if (argc > 1)
		n = atoi(argv[1]);

	foo(n);
	return 0;
}
