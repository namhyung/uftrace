#include <stdlib.h>

int main(int argc, char *argv[])
{
	int num = 3;
	char *path = getenv("HOME");
	void *ptr;

	if (argc > 1)
		num = atoi(argv[1]);

	ptr = malloc(num);
	free(ptr);

	return 0;
}
