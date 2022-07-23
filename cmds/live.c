#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libmcount/mcount.h"
#include "uftrace.h"
#include "utils/fstack.h"
#include "utils/kernel.h"
#include "utils/utils.h"

static char *tmp_dirname;
static void cleanup_tempdir(void)
{
	if (!tmp_dirname)
		return;

	remove_directory(tmp_dirname);
	tmp_dirname = NULL;
}

static void reset_live_opts(struct uftrace_opts *opts)
{
	/* this is needed to set display_depth at replay */
	live_disabled = opts->disabled;

	/*
	 * These options are handled in record and no need to do it in
	 * replay again.
	 */
	free(opts->filter);
	opts->filter = NULL;
	free(opts->caller);
	opts->caller = NULL;

	opts->depth = MCOUNT_DEFAULT_DEPTH;
	opts->disabled = false;
	opts->no_event = false;
	opts->no_sched = false;
}

static void sigsegv_handler(int sig)
{
	pr_warn("Segmentation fault\n");
	cleanup_tempdir();
	raise(sig);
}

static bool can_skip_replay(struct uftrace_opts *opts, int record_result)
{
	if (opts->nop)
		return true;

	return false;
}

static void setup_child_environ(struct uftrace_opts *opts)
{
	char *old_preload, *libpath;

#ifdef INSTALL_LIB_PATH
	if (!opts->lib_path) {
		char *envbuf = getenv("LD_LIBRARY_PATH");

		if (envbuf) {
			envbuf = xstrdup(envbuf);
			libpath = strjoin(envbuf, INSTALL_LIB_PATH, ":");
			setenv("LD_LIBRARY_PATH", libpath, 1);
			free(libpath);
		}
		else {
			setenv("LD_LIBRARY_PATH", INSTALL_LIB_PATH, 1);
		}
	}
#endif

	libpath = get_libmcount_path(opts);
	if (libpath == NULL)
		pr_err_ns("uftrace could not find libmcount.so for live-tracing\n");

	old_preload = getenv("LD_PRELOAD");
	if (old_preload) {
		size_t len = strlen(libpath) + strlen(old_preload) + 2;
		char *preload = xmalloc(len);

		snprintf(preload, len, "%s:%s", libpath, old_preload);
		setenv("LD_PRELOAD", preload, 1);
		free(preload);
	}
	else
		setenv("LD_PRELOAD", libpath, 1);

	free(libpath);
}

int command_live(int argc, char *argv[], struct uftrace_opts *opts)
{
	char template[32] = "/tmp/uftrace-live-XXXXXX";
	int fd;
	struct sigaction sa = {
		.sa_flags = SA_RESETHAND,
	};
	int ret;

	if (!opts->record) {
		tmp_dirname = template;
		umask(022);
		fd = mkstemp(template);
		if (fd < 0) {
			if (errno != EPERM)
				pr_err("cannot access to /tmp");

			fd = mkstemp(template + sizeof("/tmp/") - 1);

			if (fd < 0)
				pr_err("cannot create temp name");
			tmp_dirname += sizeof("/tmp/") - 1;
		}

		close(fd);
		unlink(tmp_dirname);

		atexit(cleanup_tempdir);

		sa.sa_handler = sigsegv_handler;
		sigfillset(&sa.sa_mask);
		sigaction(SIGSEGV, &sa, NULL);

		opts->dirname = tmp_dirname;
	}

	if (opts->list_event) {
		if (geteuid() == 0)
			list_kernel_events();

		if (fork() == 0) {
			setup_child_environ(opts);
			setenv("UFTRACE_LIST_EVENT", "1", 1);

			execv(opts->exename, argv);
			abort();
		}
		return 0;
	}

	ret = command_record(argc, argv, opts);
	if (!can_skip_replay(opts, ret)) {
		int ret2;

		reset_live_opts(opts);

		if (opts->use_pager)
			start_pager(setup_pager());

		pr_dbg("live-record finished.. \n");
		if (opts->report) {
			pr_out("#\n# uftrace report\n#\n");
			ret2 = command_report(argc, argv, opts);
			if (ret == UFTRACE_EXIT_SUCCESS)
				ret = ret2;

			pr_out("\n#\n# uftrace replay\n#\n");
		}

		pr_dbg("start live-replaying...\n");
		ret2 = command_replay(argc, argv, opts);
		if (ret == UFTRACE_EXIT_SUCCESS)
			ret = ret2;
	}

	cleanup_tempdir();

	return ret;
}
