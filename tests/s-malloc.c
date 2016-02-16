#include <stdio.h>

#define MALLOC_BUFSIZE  (1024 * 1024 * 1024)

void *malloc(unsigned size)
{
	static char buf[MALLOC_BUFSIZE];
	static unsigned count;
	void *ptr;

	if (count + size > sizeof(buf))
		return NULL;

	ptr = buf + count;
	count += size;

	return ptr;
}

void free(void *ptr)
{
	/* do nothing */
}

int main(void)
{
	free(malloc(16));
	return 0;
}
