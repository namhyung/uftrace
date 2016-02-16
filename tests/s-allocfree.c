#include <stdlib.h>

static void * alloc1(void);
static void * alloc2(void);
static void * alloc3(void);
static void * alloc4(void);
static void * alloc5(void);

static void free1(void *ptr);
static void free2(void *ptr);
static void free3(void *ptr);
static void free4(void *ptr);
static void free5(void *ptr);

static void * alloc1(void)
{
	return alloc2();
}

static void * alloc2(void)
{
	return alloc3();
}

static void * alloc3(void)
{
	return alloc4();
}

static void * alloc4(void)
{
	return alloc5();
}

static void * alloc5(void)
{
	return malloc(1);
}

static void free1(void *ptr)
{
	free2(ptr);
}

static void free2(void *ptr)
{
	free3(ptr);
}

static void free3(void *ptr)
{
	free4(ptr);
}

static void free4(void *ptr)
{
	free5(ptr);
}

static void free5(void *ptr)
{
	free(ptr);
}

int main(int argc, char *argv[])
{
	free1(alloc1());
	return 0;
}
