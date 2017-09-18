#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *hello = "hello";
char *msg = "autoargs test";

int main(int argc, char *argv[])
{
	char buf[1024];
	size_t len = strlen(msg);

	char *ptr = (char*)calloc(1, len + 1);
	free(ptr);

	if (!strcmp(hello, argv[1]))
		puts(hello);
	else
		puts(msg);

	return 0;
}
