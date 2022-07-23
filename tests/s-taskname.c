#define _GNU_SOURCE
#include <pthread.h>
#include <sys/prctl.h>

void task_name1(const char *name)
{
	prctl(PR_SET_NAME, name, 0, 0, 0);
}

void task_name2(const char *name)
{
	pthread_setname_np(pthread_self(), name);
}

int main(int argc, char *argv[])
{
	task_name1("foo");
	task_name2("bar");
	return 0;
}
