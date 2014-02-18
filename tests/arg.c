#include <stdio.h>

void __attribute__((noinline)) arg(char *str)
{
	printf("%s ", str);
}

int main(int argc, char *argv[])
{
	int i;
	for (i = 1; i < argc; i++)
		arg(argv[i]);
	putchar('\n');
	return 0;
}
