/*
 * This test calls fork() and then exec() to run the t-abc executable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_PROG1 "t-abc"
#define TEST_PROG2 "t-openclose"

int main(int argc, char *argv[])
{
	int pid;

	pid = fork();
	if (pid == 0) {
		if (argc == 1)
			execl(TEST_PROG1, TEST_PROG1, NULL);
		else
			execl(TEST_PROG2, TEST_PROG2, NULL);
		exit(2);
	}
	waitpid(pid, NULL, 0);
	return 0;
}
