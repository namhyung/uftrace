#include <pthread.h>

#define NUM_THREAD 4

pthread_t threads[NUM_THREAD];
void *thread_main(void *arg)
{
	double result;
	result = 1.0;
	printf("%f\n",result);
	pthread_exit((void *) 0);
}

int main(void)
{
	for (int i = 0; i < NUM_THREAD; i++){	
		pthread_create(&threads[i], NULL, &thread_main, (void *)i);
	}
	for (int i = 0; i < NUM_THREAD; i++){
		int status;	
		pthread_join(threads[i], (void **)&status);
	}
	return 0;
}



