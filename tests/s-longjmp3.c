#include <setjmp.h>
#include <unistd.h>

jmp_buf env1;
jmp_buf env2;

int foo(int i)
{
	if (i == 1)
		longjmp(env1, 1);
	else
		longjmp(env2, 3);
	return 0;
}

int baz(int i)
{
	if (i == 1)
		longjmp(env1, 2);
	else
		longjmp(env2, 4);
	return 0;
}

int bar(int i)
{
	return baz(i);
}

int main(int argc, char *argv[])
{
	int ret;

	ret = setjmp(env1);
	getpid();
	if (ret == 0)
		ret = setjmp(env2);

	if (ret == 0)
		foo(1);
	else if (ret == 1)
		bar(1);
	else if (ret == 2)
		foo(2);
	else if (ret == 3)
		bar(2);

	return 0;
}
