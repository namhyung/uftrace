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
	pthread_t thid;

	pthread_create(&thid, NULL, thread_func, "t-abc");
	pthread_join(thid, NULL);

	return 0;
}
