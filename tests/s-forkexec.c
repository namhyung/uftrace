/*
 * This test calls fork() and then exec() to run the t-abc executable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define TEST_PROG  "t-abc"

int main(int argc, char *argv[])
{
	int pid;

	pid = fork();
	if (pid == 0) {
		execl(TEST_PROG, TEST_PROG, NULL);
		exit(2);
	}
	waitpid(pid, NULL, 0);
	return 0;
}
