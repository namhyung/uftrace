/*
 * This is test to trace child task after calling fork().
 */
#include <stdlib.h>
#include <unistd.h>

static int __attribute__((noinline)) a(void);
static int __attribute__((noinline)) b(void);
static int __attribute__((noinline)) c(void);

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

	switch (fork()) {
	case -1:
		return 1;
	default:
		wait(NULL);
		/* fall through */
	case 0:
		ret += a();
		break;
	}

	return ret ? 0 : 1;
}
