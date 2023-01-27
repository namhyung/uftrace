#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "libmcount/mcount.h"
#include "uftrace.h"
#include "utils/fstack.h"
#include "utils/kernel.h"
#include "utils/socket.h"
#include "utils/utils.h"

static char *tmp_dirname;
static void cleanup_tempdir(void)
{
	if (!tmp_dirname)
		return;

	remove_directory(tmp_dirname);
	tmp_dirname = NULL;
}

/* trigger actions that need to be done in replay */
static const struct {
	const char *action;
	int len;
} replay_triggers[] = {
	{ "backtrace", 9 }, { "color=", 6 }, { "hide", 4 }, { "time=", 5 }, { "trace", 5 },
};

static bool has_replay_triggers(const char *trigger)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(replay_triggers); i++) {
		if (strstr(trigger, replay_triggers[i].action))
			return true;
	}
	return false;
}

static bool match_replay_triggers(const char *trigger)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(replay_triggers); i++) {
		if (!strncmp(trigger, replay_triggers[i].action, replay_triggers[i].len))
			return true;
	}
	return false;
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
	opts->size_filter = 0;

	/*
	 * Likewise, most trigger options are ignored, but color settings and
	 * backtrace are effective only in replay.
	 */
	if (opts->trigger) {
		char *new_triggers = NULL;
		struct strv trs = STRV_INIT;
		char *s;
		int i;

		/* fastpath: these are not used frequently */
		if (!has_replay_triggers(opts->trigger)) {
			free(opts->trigger);
			opts->trigger = NULL;
			goto others;
		}

		/*
		 * Split trigger options for each function.
		 * Example trigger option string like this:
		 *
		 *  a@depth=1;b@backtrace,read=pmu-cycle;c@color=red,time=1us
		 */
		strv_split(&trs, opts->trigger, ";");

		strv_for_each(&trs, s, i) {
			struct strv sv = STRV_INIT;
			char *name, *tmp, *o;
			bool found = false;
			int k;

			/* skip this function if it doesn't have these triggers */
			if (!has_replay_triggers(s))
				continue;

			name = xstrdup(s);
			tmp = strchr(name, '@');
			if (tmp == NULL) {
				pr_dbg("invalid trigger option: %s\n", s);
				free(name);
				continue;
			}
			*tmp = '\0';

			/* split trigger option into actions */
			strv_split(&sv, tmp + 1, ",");

			strv_for_each(&sv, o, k) {
				if (!match_replay_triggers(o))
					continue;

				if (!found) {
					/* first action: needs func name first */
					tmp = strjoin(name, o, "@");
					found = true;
					continue;
				}

				/* second or later actions: just append */
				tmp = strjoin(tmp, o, ",");
			}
			strv_free(&sv);

			if (found) {
				new_triggers = strjoin(new_triggers, tmp, ";");
				free(tmp);
			}
		}
		strv_free(&trs);

		free(opts->trigger);
		opts->trigger = new_triggers;
	}

others:
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

/* Forward all client options to the agent */
static int forward_options(struct uftrace_opts *opts)
{
	int sfd;
	struct sockaddr_un addr;
	int ret = 0;

	sfd = socket_create(&addr, opts->pid);
	if (sfd == -1)
		return -1;

	if (socket_connect(sfd, &addr) == -1) {
		ret = -1;
		goto socket_error;
	}

	if (socket_send_option(sfd, UFTRACE_DOPT_CLOSE, NULL, 0) == -1) {
		pr_warn("cannot terminate agent connection\n");
		ret = -1;
	}
	else {
		enum uftrace_dopt ack;
		if (read(sfd, &ack, sizeof(enum uftrace_dopt)) < 0 || ack != UFTRACE_DOPT_CLOSE)
			ret = -1;
	}

socket_error:
	close(sfd);
	return ret;
}

int command_live(int argc, char *argv[], struct uftrace_opts *opts)
{
#define LIVE_NAME "uftrace-live-XXXXXX"
	char template[32] = "/tmp/" LIVE_NAME;
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
			/* can't reuse first template because it was trashed by mkstemp */
			strcpy(template, LIVE_NAME);

			if (errno != EPERM && errno != ENOENT)
				pr_err("cannot access to /tmp");

			fd = mkstemp(template);

			if (fd < 0)
				pr_err("cannot create temp name");
			tmp_dirname = template;
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

	if (opts->pid)
		return forward_options(opts);

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

#ifdef UNIT_TEST

TEST_CASE(live_reset_options)
{
	struct uftrace_opts o = {
		.depth = 3,
		.disabled = true,
		.no_event = true,
		.no_sched = true,
	};

	pr_dbg("setup live options\n");
	o.filter = strjoin(o.filter, "foo", ";");
	o.caller = strjoin(o.caller, "bar", ";");
	/* add different types of triggers */
	o.trigger = strjoin(o.trigger, "foo@filter,depth=1", ";");
	o.trigger = strjoin(o.trigger, "bar@time=1us,filter,color=red", ";");
	o.trigger = strjoin(o.trigger, "baz@backtrace,trace,read=pmu-cycle", ";");

	pr_dbg("reset live options (filter, triggers, ...)\n");
	reset_live_opts(&o);

	TEST_EQ(o.depth, MCOUNT_DEFAULT_DEPTH);
	TEST_EQ(o.filter, NULL);
	TEST_EQ(o.caller, NULL);
	/* it should only have the color trigger */
	TEST_STREQ(o.trigger, "bar@time=1us,color=red;baz@backtrace,trace");
	TEST_EQ(o.disabled, false);
	TEST_EQ(o.no_event, false);
	TEST_EQ(o.no_sched, false);

	free(o.trigger);
	return TEST_OK;
}

#endif /* UNIT_TEST */
