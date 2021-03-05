#include <stdlib.h>

// block compiler optimizing.
static void * alloc1(volatile int);
static void * alloc2(volatile int);
static void * alloc3(volatile int);
static void * alloc4(volatile int);
static void * alloc5(volatile int);

static void free1(void *ptr);
static void free2(void *ptr);
static void free3(void *ptr);
static void free4(void *ptr);
static void free5(void *ptr);

static void * alloc1(volatile int one)
{
	return alloc2(one);
}

static void * alloc2(volatile int one)
{
	return alloc3(one);
}

static void * alloc3(volatile int one)
{
	return alloc4(one);
}

static void * alloc4(volatile int one)
{
	return alloc5(one);
}

static void * alloc5(volatile int one)
{
	return malloc(one);
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
	volatile int one = 1;
	free1(alloc1(one));
	return 0;
}
