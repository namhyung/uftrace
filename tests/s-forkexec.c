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
	char *ch;
	char buf[4096] = {};

	if (readlink("/proc/self/exe", buf, sizeof(buf)) < 0)
		strcpy(buf, argv[0]);

	ch = strrchr(buf, '/');
	if (ch)
		ch++;
	else
		ch = buf;

	strcpy(ch, TEST_PROG);

	pid = fork();
	if (pid == 0) {
		execl(buf, TEST_PROG, "1", NULL);
		exit(2);
	}
	waitpid(pid, NULL, 0);
	return 0;
}
