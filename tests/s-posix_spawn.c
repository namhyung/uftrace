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
	char *args[] = {
		NULL,
		NULL,
	};
	char *envp[] = { "PATH=.", "HOME=/home/user", NULL };

	args[0] = TEST_PROG1;
	posix_spawn(&pid, TEST_PROG1, NULL, NULL, args, envp);
	waitpid(pid, NULL, 0);

	args[0] = TEST_PROG2;
	posix_spawn(&pid, TEST_PROG2, NULL, NULL, args, envp);
	waitpid(pid, NULL, 0);

	return 0;
}
