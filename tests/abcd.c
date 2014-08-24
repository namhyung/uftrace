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
	return getpid() % 1000;
}

int main(void)
{
	if (daemon(0, 0) < 0)
		return -1;
	return a() + 1;
}
