#include <setjmp.h>

jmp_buf env;

int foo(void)
{
	longjmp(env, 1);
	return 0;
}

int bar(int a)
{
	return a - 2;
}

int main(int argc, char *argv[])
{
	int ret;

	if (!setjmp(env))
		ret = foo();
	else
		ret = bar(argc);
	return !(ret == -1);
}
