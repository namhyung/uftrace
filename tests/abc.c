#include <unistd.h>

static int __attribute__((noinline)) a(void);
static int __attribute__((noinline)) b(void);
static int __attribute__((noinline)) c(void);

static int a(void)
{
	return b();
}

static int b(void)
{
	return c();
}

static int c(void)
{
	return getpid();
}

int main(void)
{
	return a();
}
