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

void bar(void)
{
	usleep(2000);
}

void foo(void)
{
	void *p = mem_alloc();
	bar();
	mem_free(p);
}

int main(void)
{
	foo();
	return 0;
}
