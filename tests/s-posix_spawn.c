/*
 * This test calls posix_spawn() to run the t-abc and t-openclose executables.
 */
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_PROG1 "t-abc"
#define TEST_PROG2 "t-openclose"

int main(int argc, char *argv[])
{
	int pid;
	char *args1[] = { TEST_PROG1, NULL };
	char *args2[] = { TEST_PROG2, NULL };
	char *envp[] = { "PATH=.", "HOME=/home/user", NULL };

	posix_spawn(&pid, TEST_PROG1, NULL, NULL, args1, envp);
	waitpid(pid, NULL, 0);

	posix_spawn(&pid, TEST_PROG2, NULL, NULL, args2, envp);
	waitpid(pid, NULL, 0);

	return 0;
}
