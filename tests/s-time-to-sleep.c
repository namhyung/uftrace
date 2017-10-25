#include <stdlib.h>
#include <unistd.h>

void *mem_alloc(void)
{
	return malloc(0);
}

void mem_free(void *ptr)
{
	free(ptr);
}

void bar(int msec)
{
	usleep(msec);
}

void foo(void)
{
	void *p = mem_alloc();
	bar(2000);
	mem_free(p);
}

int main(void)
{
	foo();
	bar(1000);
	return 0;
}
