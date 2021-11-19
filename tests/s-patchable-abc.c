/*
 * This is a basic test to verify whether uftrace works on the system.
 */
#include <stdlib.h>
#include <unistd.h>

#if __x86_64__
#define NR_NOPS 5
#elif __aarch64__
#define NR_NOPS 2
#else
#define NR_NOPS 0
#endif

#define __patchable __attribute__((patchable_function_entry(NR_NOPS)))

static int a(void);
static int b(void);
static int c(void);

__patchable static int a(void)
{
	return b() - 1;
}

static int b(void)
{
	return c() + 1;
}

__patchable static int c(void)
{
	return getpid() % 100000;
}

__patchable int main(int argc, char *argv[])
{
	int ret = 0;

	if (argc > 1)
		ret = atoi(argv[1]);

	ret += a();
	return ret ? 0 : 1;
}
