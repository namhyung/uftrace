#include <stdio.h>

#define MALLOC_BUFSIZE  (1024 * 1024 * 1024)


__attribute__((noinline)) void *malloc(unsigned size);
__attribute__((noinline)) void free(void *ptr);

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
