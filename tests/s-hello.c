#include <stdio.h>

int main(int argc, char *argv[])
{
	const char *whom = "world";

	if (argc > 1)
		whom = argv[1];

	printf("Hello %s\n", whom);
	return 0;
}
