#include <stdio.h>

volatile int n;

void __attribute__((noinline)) arg(char *str)
{
	printf("%s ", str);
	n++;
}

int main(int argc, char *argv[])
{
	int i;
	for (i = 1; i < argc; i++)
		arg(argv[i]);
	fputc('\n', stdout);
	return n;
}
