#include <stdio.h>

static int static_var = 1;
int global_var = 2;
int __attribute__((weak)) weak_var = 3;

int foo(int *p, int n)
{
	*p = n;
	return n + 1;
}

int filecmp(FILE *a, FILE *b)
{
	return a == b;
}

int main(void)
{
	foo(&static_var, static_var);
	foo(&global_var, global_var);
	foo(&weak_var, weak_var);
	return filecmp(stdout, stderr);
}
