#include <pthread.h>

void foo(void)
{
	int i;
	for (i = 0; i < 1000; i++)
		asm volatile("" ::: "memory");
}

void *bar(void *arg)
{
	if (arg)
		arg = NULL;
	return arg;
}

static void *thread_first(void *arg)
{
	foo();
	return bar(arg);
}

static void *thread_second(void *arg)
{
	foo();
	return bar(arg);
}

static void *thread_third(void *arg)
{
	foo();
	return bar(arg);
}

static void *thread_fourth(void *arg)
{
	foo();
	return bar(arg);
}

int main(void)
{
	int i;
	pthread_t thrd_id[4];

	pthread_create(&thrd_id[0], NULL, thread_first, NULL);
	pthread_create(&thrd_id[1], NULL, thread_second, NULL);
	pthread_create(&thrd_id[2], NULL, thread_third, NULL);
	pthread_create(&thrd_id[3], NULL, thread_fourth, NULL);

	for (i = 0; i < 4; i++)
		pthread_join(thrd_id[i], NULL);

	return 0;
}
