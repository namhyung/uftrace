#include <stdio.h>

void __attribute__((noinline)) foo(void)
{
	printf("%s\n", __func__);
}

void __attribute__((noinline)) bar(void)
{
	foo();
	printf("%s\n", __func__);
}

void __attribute__((noinline)) baz(void)
{
	bar();
	printf("%s\n", __func__);
}

int main(void)
{
	printf("%s\n", __func__);
	baz();
	return 0;
}
