#include <pthread.h>
#include <stdio.h>

#define NUM_THREAD 2

pthread_t threads[NUM_THREAD];

void *thread_main(void *arg)
{
	double result = 1.0;

	printf("%f\n", result);
	pthread_exit(NULL);
	return NULL;
}

int main(void)
{
	int i;

	for (i = 0; i < NUM_THREAD; i++)
		pthread_create(&threads[i], NULL, &thread_main, NULL);

	for (i = 0; i < NUM_THREAD; i++)
		pthread_join(threads[i], NULL);

	return 0;
}
