#include <unistd.h>

static volatile int __attribute__((noinline)) a(void);
static volatile int __attribute__((noinline)) b(void);
static volatile int __attribute__((noinline)) c(void);

static volatile int a(void)
{
	return b() - 1;
}

static volatile int b(void)
{
	return c() + 1;
}

static volatile int c(void)
{
	return 0;
}

int main(void)
{
	int i;
	int n;

	if (fork() < 0)
		return -1;

	for (i = 0; i < 1000; i++)
		n += a();

	return n;
}
