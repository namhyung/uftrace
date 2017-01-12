#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "libmcount/mcount.h"


static char *tmp_dirname;
static void cleanup_tempdir(void)
{
	DIR *dp;
	struct dirent *ent;
	char path[PATH_MAX];

	if (!tmp_dirname)
		return;

	dp = opendir(tmp_dirname);
	if (dp == NULL) {
		if (errno == ENOENT)
			return;
		pr_err("cannot open temp dir");
	}

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", tmp_dirname, ent->d_name);
		if (unlink(path) < 0)
			pr_err("unlink failed: %s: %m\n", path);
	}

	closedir(dp);

	if (rmdir(tmp_dirname) < 0)
		pr_err("rmdir failed: %s: %m\n", tmp_dirname);
	tmp_dirname = NULL;
}

static void reset_live_opts(struct opts *opts)
{
	/* this is needed to set display_depth at replay */
	live_disabled = opts->disabled;

	/*
	 * These options are handled in record and no need to do it in
	 * replay again.
	 */
	opts->filter	= NULL;
	opts->depth	= MCOUNT_DEFAULT_DEPTH;
	opts->disabled	= false;
	opts->threshold = 0;
}

static void sigsegv_handler(int sig)
{
	pr_log("Segmentation fault\n");
	cleanup_tempdir();
	raise(sig);
}

int command_live(int argc, char *argv[], struct opts *opts)
{
	char template[32] = "/tmp/uftrace-live-XXXXXX";
	int fd = mkstemp(template);
	struct sigaction sa = {
		.sa_flags = SA_RESETHAND,
	};
	int ret;

	if (fd < 0)
		pr_err("cannot create temp name");

	close(fd);
	unlink(template);

	tmp_dirname = template;
	atexit(cleanup_tempdir);

	sa.sa_handler = sigsegv_handler;
	sigfillset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, NULL);

	opts->dirname = template;

	ret = command_record(argc, argv, opts);
	if (!opts->nop) {
		int ret2;

		reset_live_opts(opts);

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
