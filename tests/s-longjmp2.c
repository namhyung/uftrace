#include <setjmp.h>

jmp_buf env;

int foo(void)
{
	longjmp(env, 1);
	return 1;
}

int baz(void)
{
	longjmp(env, 2);
	return 2;
}

int bar(void)
{
	return baz();
}

int main(int argc, char *argv[])
{
	int ret;

	switch (setjmp(env)) {
	case 0:
		ret = foo();
		break;
	case 1:
		ret = bar();
		break;
	case 2:
		ret = 0;
		break;
	default:
		ret = -1;
		break;
	}
	return ret;
}
