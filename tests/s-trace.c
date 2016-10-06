#include <stdlib.h>
#include <unistd.h>

void bar(void)
{
	usleep(2000);
}

void foo(void)
{
	bar();
}

int main(void)
{
	foo();
	return 0;
}
