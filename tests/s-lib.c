/*
 * This is test to trace function in a library.
 */
#include <unistd.h>

int lib_a(void);
int lib_b(void);
int lib_c(void);

int lib_a(void)
{
	return lib_b() - 1;
}

int lib_b(void)
{
	return lib_c() + 1;
}

int lib_c(void)
{
	return getpid() % 100000;
}

