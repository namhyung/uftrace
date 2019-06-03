/*
 * This is test to trace function in a library.
 */
#include <unistd.h>

int lib_d(int i);
static int lib_e(int i);
static int lib_f(int i);

int lib_d(int i)
{
	return lib_e(i + 1) - 1;
}

static int lib_e(int i)
{
	return lib_f(i - 1) + 1;
}

static int lib_f(int mask)
{
	return getpid() % mask;
}

