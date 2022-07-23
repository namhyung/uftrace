#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_key_t key;

void tsd_dtor(void *data)
{
	free(data);
}

void *thread(void *arg)
{
	pthread_setspecific(key, malloc(2));
	return NULL;
}

int main(void)
{
	pthread_t t;

	pthread_key_create(&key, tsd_dtor);
	pthread_setspecific(key, malloc(1));

	pthread_create(&t, NULL, thread, NULL);
	pthread_join(t, NULL);

	tsd_dtor(pthread_getspecific(key));
	pthread_key_delete(key);
	return 0;
}
