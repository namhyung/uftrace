#include <stdlib.h>
#include <unistd.h>

void bar(void)
{
	usleep(3000);
}

void foo(void)
{
	usleep(5000);
	bar();
}

int main(void)
{
	usleep(1000);

	foo();
	return 0;
}
