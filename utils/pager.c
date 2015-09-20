/*
 * This code is based on Linux perf tools (so in turn git) project
 * which is released under GPL v2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

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
		/* child process */
		dup2(fds[0], 0);
		close(fds[0]);
		close(fds[1]);

		setenv("LESS", "FRSX", 0);

		execvp(argv[0], (char *const*) argv);
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

void start_pager(void)
{
	const char *pager = getenv("PAGER");
	const char *pager_argv[] = { "sh", "-c", NULL, NULL };

	if (!isatty(1))
		return;
	if (!(pager || access("/usr/bin/pager", X_OK)))
		pager = "/usr/bin/pager";
	if (!(pager || access("/usr/bin/less", X_OK)))
		pager = "/usr/bin/less";
	if (!pager)
		pager = "cat";
	if (!*pager || !strcmp(pager, "cat"))
		return;

	/* spawn the pager */
	pager_argv[2] = pager;

	if (start_command(pager_argv))
		return;

	/* original process continues, but writes to the pipe */
	dup2(pager_fd, 1);
	if (isatty(2))
		dup2(pager_fd, 2);
	close(pager_fd);

	atexit(wait_for_pager);
}
