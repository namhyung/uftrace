#include <pthread.h>
#include <unistd.h>

void *thread_func(void *arg)
{
	char *exename = arg;

	execl(exename, exename, NULL);
	return NULL;
}

int main(void)
{
	pthread_t thrd_id;

	pthread_create(&thrd_id, NULL, thread_func, "t-abc");
	pthread_join(thrd_id, NULL);

	return 0;
}
