/*
 * This code is based on Linux perf tools (so in turn git) project
 * which is released under GPL v2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>

static int pager_pid;
static int pager_fd;

static int start_command(const char *argv[])
{
	int fds[2];

	if (pipe(fds) < 0)
		return -1;

	fflush(NULL);
	pager_pid = fork();
	if (pager_pid < 0) {
		close(fds[0]);
		close(fds[1]);
		return -1;
	}

	if (!pager_pid) {
		fd_set in_set;
		fd_set ex_set;

		/* child process */
		dup2(fds[0], STDIN_FILENO);
		close(fds[0]);
		close(fds[1]);

		FD_ZERO(&in_set);
		FD_ZERO(&ex_set);
		FD_SET(STDIN_FILENO, &in_set);
		FD_SET(STDIN_FILENO, &ex_set);

		/*
		 * Work around bug in "less" by not starting it
		 * until we have real input
		 */
		select(1, &in_set, NULL, &ex_set, NULL);

		setenv("LESS", "FRSX", 0);

		execvp(argv[0], (char *const *)argv);
		exit(127);
	}

	close(fds[0]);
	pager_fd = fds[1];

	return 0;
}

void wait_for_pager(void)
{
	int status;

	if (!pager_pid)
		return;

	/* signal EOF to pager */
	fclose(stdout);
	fclose(stderr);

	waitpid(pager_pid, &status, 0);
	pager_pid = 0;
}

char *setup_pager(void)
{
	char *pager = getenv("PAGER");

	if (!isatty(STDOUT_FILENO))
		return NULL;
	if (!(pager || access("/usr/bin/pager", X_OK)))
		pager = "/usr/bin/pager";
	if (!(pager || access("/usr/bin/less", X_OK)))
		pager = "/usr/bin/less";
	if (!pager)
		pager = "cat";
	if (!*pager || !strcmp(pager, "cat"))
		return NULL;

	return pager;
}

void start_pager(char *pager)
{
	const char *pager_argv[] = { "sh", "-c", NULL, NULL };

	if (pager == NULL)
		return;

	/* spawn the pager */
	pager_argv[2] = pager;

	if (start_command(pager_argv))
		return;

	/* original process continues, but writes to the pipe */
	dup2(pager_fd, STDOUT_FILENO);
	if (isatty(STDERR_FILENO))
		dup2(pager_fd, STDERR_FILENO);
	close(pager_fd);

	atexit(wait_for_pager);
}
