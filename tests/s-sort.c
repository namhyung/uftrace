#include <unistd.h>

void __attribute__((noinline)) foo(void);
void __attribute__((noinline)) bar(void);
void __attribute__((noinline)) loop(void);

void loop(void)
{
	int i;
	for (i = 0; i < 1000; i++)
		asm volatile("" ::: "memory");
}

void foo(void)
{
	loop();
	loop();
	loop();
}

void bar(void)
{
	int i;
	for (i = 0; i < 1000; i++)
		asm volatile("" ::: "memory");
	usleep(1000);
}

int main(int argc, char *argv[])
{
	int i;

	for (i = 0; i < 10000; i++)
		asm volatile("" ::: "memory");
	foo();

	for (i = 0; i < 10000; i++)
		asm volatile("" ::: "memory");
	foo();

	for (i = 0; i < 10000; i++)
		asm volatile("" ::: "memory");
	bar();
	return 0;
}
