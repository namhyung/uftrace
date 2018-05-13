#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <signal.h>

#define PR_FMT     "mcount-dynamic"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/script.h"
#include "utils/env-file.h"

/*
 * previous mcount_startup() the contructor.
 */
void pre_startup()
{
	int fd_envfile;
	fd_envfile = open_env_file();
	set_env_from_file(fd_envfile);

	/*
	 * the Process output is delayed for unknown reasons when using
	 * dynamic tracing. cannot found the reason of delay but below code
	 * can mitigation the symptom.
	 */
	setvbuf(stdout, NULL, _IONBF, 1024);
	setvbuf(stderr, NULL, _IONBF, 1024);
}

/*
 * configuration for dynamic tracing.
 */
void config_for_dynamic() {
	char *pipefd_str;
	char *uftrace_pid_str;
	int uftrace_pid;

	struct stat statbuf;

	uftrace_pid_str = getenv("UFTRACE_PID");
	if (uftrace_pid_str) {
		pr_dbg("uftrace process PID : %s\n", uftrace_pid_str);
		uftrace_pid = strtol(uftrace_pid_str, NULL, 0);
		if (uftrace_pid == 0) {
			pr_err_ns("Cannot parse UFTRACE_PID from environment. \n");
		}
	} else {
		pr_err_ns("Cannot found UFTRACE_PID from environment. \n");
	}

	pipefd_str = getenv("UFTRACE_PIPE");
	if (pipefd_str) {
		pfd = strtol(pipefd_str, NULL, 0);

		char fd_path[64];
		snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", uftrace_pid, pfd);
		pr_dbg("open uftrace process : %s\n", fd_path);
		pfd = open(fd_path, O_RDWR);
		/* minimal sanity check */
		if (fstat(pfd, &statbuf) < 0 || !S_ISFIFO(statbuf.st_mode)) {
			pr_dbg("ignore invalid pipe fd: %d\n", pfd);
			pfd = -1;
		}
	}
}

/*
 * post mcount_startup() the constructor.
 */
void post_startup()
{
	config_for_dynamic();
}


// TODO : make test and get the grade A+.

