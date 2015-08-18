#include <stdlib.h>

static void * __attribute__((noinline)) alloc1(void);
static void * __attribute__((noinline)) alloc2(void);
static void * __attribute__((noinline)) alloc3(void);
static void * __attribute__((noinline)) alloc4(void);
static void * __attribute__((noinline)) alloc5(void);

static void __attribute__((noinline)) free1(void *ptr);
static void __attribute__((noinline)) free2(void *ptr);
static void __attribute__((noinline)) free3(void *ptr);
static void __attribute__((noinline)) free4(void *ptr);
static void __attribute__((noinline)) free5(void *ptr);

static void * __attribute__((noinline)) alloc1(void)
{
	return alloc2();
}

static void * __attribute__((noinline)) alloc2(void)
{
	return alloc3();
}

static void * __attribute__((noinline)) alloc3(void)
{
	return alloc4();
}

static void * __attribute__((noinline)) alloc4(void)
{
	return alloc5();
}

static void * __attribute__((noinline)) alloc5(void)
{
	return malloc(1);
}

static void __attribute__((noinline)) free1(void *ptr)
{
	free2(ptr);
}

static void __attribute__((noinline)) free2(void *ptr)
{
	free3(ptr);
}

static void __attribute__((noinline)) free3(void *ptr)
{
	free4(ptr);
}

static void __attribute__((noinline)) free4(void *ptr)
{
	free5(ptr);
}

static void __attribute__((noinline)) free5(void *ptr)
{
	free(ptr);
}

int main(int argc, char *argv[])
{
	free1(alloc1());
	return 0;
}
