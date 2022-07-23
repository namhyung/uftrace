#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_PROG "t-abc"

int main(int argc, char *argv[])
{
	int pid;

	pid = vfork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		execl(TEST_PROG, TEST_PROG, NULL);
		return -1;
	}

	wait(NULL);
	return 0;
}
