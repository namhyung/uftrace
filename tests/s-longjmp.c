#include <setjmp.h>

jmp_buf env;

int foo(void)
{
	longjmp(env, 1);
	return 0;
}

int bar(void)
{
	return -1;
}

int main(int argc, char *argv[])
{
	int ret;

	if (!setjmp(env))
		ret = foo();
	else
		ret = bar();
	return !(ret == -1);
}
