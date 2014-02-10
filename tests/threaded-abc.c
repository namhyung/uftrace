#include <pthread.h>

int abc;

static int __attribute__((noinline)) a(void);
static int __attribute__((noinline)) b(void);
static int __attribute__((noinline)) c(void);

static int a(void)
{
	return b();
}

static int b(void)
{
	return c();
}

static int c(void)
{
	return 0;
}

static void *foo(void *arg)
{
	abc += a();
	return NULL;
}

int main(void)
{
	int i;
	pthread_t t[4];

	for (i = 0; i < 4; i++)
		pthread_create(&t[i], NULL, foo, NULL);
	abc += a();
	for (i = 0; i < 4; i++)
		pthread_join(t[i], NULL);
	return 0;
}
