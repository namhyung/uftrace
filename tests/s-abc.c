/*
 * This is a basic test to verify whether uftrace works on the system.
 */
#include <stdlib.h>
#include <unistd.h>

static int a(void);
static int b(void);
static int c(void);

static int a(void)
{
	return b() - 1;
}

static int b(void)
{
	return c() + 1;
}

static int c(void)
{
	return getpid() % 100000;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	if (argc > 1)
		ret = atoi(argv[1]);

	ret += a();
	return ret ? 0 : 1;
}
