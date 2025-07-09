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

#define LIVE_NAME "uftrace-live-XXXXXX"
#define TMP_LIVE_NAME "/tmp/" LIVE_NAME

#define TMP_DIR_NAME_SIZE 32

static char tmp_dirname[TMP_DIR_NAME_SIZE];
static void cleanup_tempdir(void)
{
	if (tmp_dirname[0] == '\0')
		return;

	remove_directory(tmp_dirname);

	memset(tmp_dirname, '\0', sizeof(tmp_dirname));
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
	live_disabled = (opts->trace == TRACE_STATE_OFF);

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
	opts->trace = TRACE_STATE_ON;
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

/**
 * query_agent_capabilities - query agent for its supported features
 * @fd - agent socket fd
 * @return - agent capabilities
 */
static int query_agent_capabilities(int fd)
{
	struct uftrace_msg msg;
	int status;

	pr_dbg3("query agent capabilities\n");
	if (agent_message_send(fd, UFTRACE_MSG_AGENT_QUERY, NULL, 0) < 0)
		return -1;

	status = agent_message_read_response(fd, &msg);
	if (status < 0)
		return -1;

	switch (msg.type) {
	case UFTRACE_MSG_AGENT_OK:
		pr_dbg2("agent capabilities: %#x\n", status);
		break;

	case UFTRACE_MSG_AGENT_ERR:
		pr_dbg3("agent query error: %s\n", strerror(status));
		status = -1;
		break;

	default:
		pr_dbg3("invalid agent response\n");
	}

	return status;
}

/**
 * forward_option - forward a given option and its data to the agent
 * @fd           - agent socket file descriptor
 * @capabilities - features supported by the agent
 * @opt          - option type to send
 * @value        - option data load
 * @value_size   - size of @value
 * @return       - status: -1 on error, 0 on success
 */
static int forward_option(int fd, int capabilities, int opt, void *value, size_t value_size)
{
	void *data;
	size_t data_size;
	struct uftrace_msg ack;
	int ret = -1;

	if (!(opt & capabilities)) {
		pr_warn("option not unsupported by the agent: %#x\n", opt);
		return 0;
	}

	/* The agent needs to know which option to apply, and its associated value.
	 * We pack both information into the data load of a single message, with
	 * type UFTRACE_MSG_AGENT_SET_OPT.
	 *
	 * We use the following data structure:
	 *
	 * PACKED_DATA = OPTION_TYPE |   VALUE
	 *               -----------   ----------
	 *               sizeof(opt)   value_size
	 *
	 * Example:
	 * PACKED_DATA = UFTRACE_AGENT_OPT_FILTER |  'func1,!func2'
	 *               ------------------------   ---------------
	 *                     sizeof(opt)          value_size = 12
	 */
	pr_dbg2("send option to agent: %#x\n", opt);
	data_size = value_size + sizeof(opt);
	data = malloc(data_size);
	if (!data)
		goto cleanup;
	memcpy(data, &opt, sizeof(opt));
	memcpy(data + sizeof(opt), value, value_size);

	ret = agent_message_send(fd, UFTRACE_MSG_AGENT_SET_OPT, data, data_size);
	if (ret < 0) {
		pr_dbg("error sending option to agent\n");
		goto cleanup;
	}

	ret = agent_message_read_response(fd, &ack);
	if (ret < 0) {
		pr_dbg3("error reading agent response\n");
		goto cleanup;
	}

	switch (ack.type) {
	case UFTRACE_MSG_AGENT_OK:
		ret = 0;
		pr_dbg4("option applied by agent: %#x\n", opt);
		break;

	case UFTRACE_MSG_AGENT_ERR:
		if (ret == ENOTSUP)
			pr_warn("option not unsupported by the agent: %#x\n", opt);
		else
			pr_warn("agent error: %s\n", strerror(ret));
		ret = -1;
		break;

	default:
		pr_dbg3("bad agent message type (expected ack)\n");
		ret = -1;
	}

cleanup:
	free(data);
	return ret;
}

/* Forward all client options to the agent */
static int forward_options(struct uftrace_opts *opts)
{
	int sfd;
	struct sockaddr_un addr;
	struct uftrace_msg ack;
	int status = 0;
	int status_close = 0;
	int capabilities;

	sfd = agent_socket_create(&addr, opts->pid);
	if (sfd == -1)
		return UFTRACE_EXIT_FAILURE;

	if (agent_connect(sfd, &addr) == -1)
		goto socket_error;
	pr_dbg2("connected to agent %d\n", opts->pid);

	capabilities = query_agent_capabilities(sfd);
	if (capabilities < 0)
		goto close;

	if (opts->trace != TRACE_STATE_NONE) {
		int trace = (opts->trace == TRACE_STATE_ON);
		status = forward_option(sfd, capabilities, UFTRACE_AGENT_OPT_TRACE, &trace,
					sizeof(trace));
	}

	if (opts->depth) {
		status = forward_option(sfd, capabilities, UFTRACE_AGENT_OPT_DEPTH, &opts->depth,
					sizeof(opts->depth));
		if (status < 0)
			goto close;
	}

	if (opts->threshold) {
		status = forward_option(sfd, capabilities, UFTRACE_AGENT_OPT_THRESHOLD,
					&opts->threshold, sizeof(opts->threshold));
		if (status < 0)
			goto close;
	}

	/* provide a pattern type for options that need it */
	if (opts->filter || opts->caller || opts->trigger) {
		status = forward_option(sfd, capabilities, UFTRACE_AGENT_OPT_PATTERN,
					&opts->patt_type, sizeof(opts->patt_type));
		if (status < 0)
			goto close;
	}

	if (opts->filter) {
		status = forward_option(sfd, capabilities, UFTRACE_AGENT_OPT_FILTER, opts->filter,
					strlen(opts->filter) + 1);
		if (status < 0)
			goto close;
	}

	if (opts->caller) {
		status = forward_option(sfd, capabilities, UFTRACE_AGENT_OPT_CALLER, opts->caller,
					strlen(opts->caller) + 1);
		if (status < 0)
			goto close;
	}

	if (opts->trigger) {
		status = forward_option(sfd, capabilities, UFTRACE_AGENT_OPT_TRIGGER, opts->trigger,
					strlen(opts->trigger) + 1);
		if (status < 0)
			goto close;
	}

close:
	status_close = agent_message_send(sfd, UFTRACE_MSG_AGENT_CLOSE, NULL, 0);
	if (status_close == 0) {
		status_close = agent_message_read_response(sfd, &ack);
		if (status_close == 0) {
			if (ack.type == UFTRACE_MSG_AGENT_OK)
				pr_dbg("disconnected from agent\n");
			else
				status_close = -1;
		}
	}
	if (status_close < 0)
		pr_dbg("agent connection not closed properly\n");

socket_error:
	if (close(sfd) == -1)
		pr_dbg2("error closing agent socket\n");

	if (status < 0 || status_close < 0)
		return UFTRACE_EXIT_FAILURE;
	else
		return UFTRACE_EXIT_SUCCESS;
}

int command_live(int argc, char *argv[], struct uftrace_opts *opts)
{
	int fd;
	struct sigaction sa = {
		.sa_flags = SA_RESETHAND,
	};
	int ret;

	if (!opts->record) {
		snprintf(tmp_dirname, sizeof(tmp_dirname), "%s", TMP_LIVE_NAME);
		umask(022);
		fd = mkstemp(tmp_dirname);
		if (fd < 0) {
			if (errno != EPERM && errno != ENOENT)
				pr_err("cannot access to %s", tmp_dirname);

			/* can't reuse first template because it was trashed by mkstemp */
			snprintf(tmp_dirname, sizeof(tmp_dirname), "%s", LIVE_NAME);
			fd = mkstemp(tmp_dirname);

			if (fd < 0)
				pr_err("cannot create %s", tmp_dirname);
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

		if (opts->exename && fork() == 0) {
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
		.trace = TRACE_STATE_OFF,
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
	TEST_EQ(o.trace, TRACE_STATE_ON);
	TEST_EQ(o.no_event, false);
	TEST_EQ(o.no_sched, false);

	free(o.trigger);
	return TEST_OK;
}

#endif /* UNIT_TEST */
