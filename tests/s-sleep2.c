#include <stdlib.h>
#include <unistd.h>

void bar(void)
{
	usleep(30000);
}

void foo(void)
{
	usleep(50000);
	bar();
}

int main(void)
{
	usleep(10000);

	foo();
	return 0;
}
