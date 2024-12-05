#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "mcount"
#define PR_DOMAIN DBG_MCOUNT

#include "libmcount/internal.h"
#include "libmcount/mcount.h"
#include "utils/socket.h"
#include "utils/utils.h"

/* agent thread */
static pthread_t agent;

/* state flag for the agent */
static volatile bool agent_run = false;

#define MCOUNT_AGENT_CAPABILITIES                                                                  \
	(UFTRACE_AGENT_OPT_TRACE | UFTRACE_AGENT_OPT_DEPTH | UFTRACE_AGENT_OPT_THRESHOLD |         \
	 UFTRACE_AGENT_OPT_PATTERN | UFTRACE_AGENT_OPT_FILTER | UFTRACE_AGENT_OPT_CALLER |         \
	 UFTRACE_AGENT_OPT_TRIGGER)

/**
 * swap_triggers - atomically swap the pointer to a filter rbtree and free the
 * old one
 * @old - pointer to the tree to deprecate
 * @new - new version of the tree to use
 */
void swap_triggers(struct uftrace_triggers_info **old, struct uftrace_triggers_info *new)
{
	struct uftrace_triggers_info *tmp;
	tmp = __sync_val_compare_and_swap(old, *old, new);
	sleep(1); /* RCU-like grace period */
	uftrace_cleanup_triggers(tmp);
	free(tmp);
}

/**
 * agent_setup_filter - update the registered filters from the agent
 * @filter_str - filters to add or remove
 * @triggers   - rbtree of tracing filters
 */
static void agent_setup_filter(char *filter_str, struct uftrace_triggers_info *triggers)
{
	uftrace_setup_filter(filter_str, &mcount_sym_info, triggers, &mcount_filter_setting);
}

/**
 * agent_setup_caller_filter - update the registered caller filters from the agent
 * @caller_str - caller filters to add or remove
 * @triggers   - rbtree where the filters are stored
 */
static void agent_setup_caller_filter(char *caller_str, struct uftrace_triggers_info *triggers)
{
	uftrace_setup_caller_filter(caller_str, &mcount_sym_info, triggers, &mcount_filter_setting);
}

/**
 * agent_setup_trigger - update the registered triggers from the agent
 * @trigger_str - trigger to add or remove
 * @triggers    - rbtree of tracing filters
 */
static void agent_setup_trigger(char *trigger_str, struct uftrace_triggers_info *triggers)
{
	uftrace_setup_trigger(trigger_str, &mcount_sym_info, triggers, &mcount_filter_setting);
}

/**
 * agent_init - initialize the agent
 * @addr - client socket
 * @return - socket file descriptor (-1 on error)
 */
static int agent_init(struct sockaddr_un *addr)
{
	int sfd;

	if (mkdir(MCOUNT_AGENT_SOCKET_DIR, 0775) == -1) {
		if (errno != EEXIST) {
			pr_dbg("error creating run directory %s\n", MCOUNT_AGENT_SOCKET_DIR);
			return -1;
		}
	}

	sfd = agent_socket_create(addr, getpid());
	if (sfd == -1)
		return sfd;

	if (access(addr->sun_path, F_OK) == 0) {
		pr_dbg("agent socket file already exists\n");
		goto error;
	}

	if (agent_listen(sfd, addr) == -1)
		goto error;

	return sfd;

error:
	close(sfd);
	return -1;
}

/**
 * agent_fini - finalize the agent thread execution
 * @addr - client socket
 * @sfd - client socket file descriptor
 */
static void agent_fini(struct sockaddr_un *addr, int sfd)
{
	if (sfd != -1)
		close(sfd);

	socket_unlink(addr);

	pr_dbg("agent terminated\n");
}

/**
 * agent_read_option - fetch option type and value from agent socket
 * @fd - socket file descriptor
 * @opt - option type
 * @value - option value
 * @read_size - size of data to read
 * @return - size of data read into @value
 */
static int agent_read_option(int fd, int *opt, void **value, size_t read_size)
{
	size_t opt_size = sizeof(*opt);
	size_t value_size = read_size - opt_size;

	if (read_all(fd, opt, opt_size) < 0)
		return -1;

	*value = realloc(*value, value_size);
	if (!value)
		return -1;

	if (read_all(fd, *value, value_size) < 0)
		return -1;

	pr_dbg4("read agent option (size=%d)\n", read_size);
	return value_size;
}

/**
 * agent_apply_option - change libmcount parameters at runtime
 * @opt      - option to apply
 * @value    - value for the given option
 * @size     - size of @value
 * @triggers - triggers definition and counters
 * @return   - 0 on success, -1 on failure
 */
static int agent_apply_option(int opt, void *value, size_t size,
			      struct uftrace_triggers_info *triggers)
{
	struct uftrace_opts opts;
	int ret = 0;
	int trace;

	switch (opt) {
	case UFTRACE_AGENT_OPT_TRACE:
		trace = *((int *)value);
		if (mcount_enabled != trace) {
			mcount_enabled = trace;
			pr_dbg("turn trace %s\n", mcount_enabled ? "on" : "off");
		}
		break;

	case UFTRACE_AGENT_OPT_DEPTH:
		opts.depth = *((int *)value);
		if (opts.depth != mcount_depth) {
			mcount_depth = opts.depth;
			pr_dbg3("dynamic depth: %d\n", mcount_depth);
		}
		else
			pr_dbg3("dynamic depth unchanged\n");
		break;

	case UFTRACE_AGENT_OPT_THRESHOLD:
		opts.threshold = *((uint64_t *)value);
		if (opts.threshold != mcount_threshold) {
			mcount_threshold = opts.threshold;
			pr_dbg3("dynamic time threshold: %lu\n", mcount_threshold);
		}
		else
			pr_dbg3("dynamic time threshold unchanged\n");
		break;

	case UFTRACE_AGENT_OPT_PATTERN:
		opts.patt_type = *((int *)value);
		if (opts.patt_type != mcount_filter_setting.ptype) {
			mcount_filter_setting.ptype = opts.patt_type;
			pr_dbg3("use pattern type %#x\n", opts.patt_type);
		}
		break;

	case UFTRACE_AGENT_OPT_FILTER:
		pr_dbg3("apply filter '%s' (size=%d)\n", value, size);
		agent_setup_filter(value, triggers);
		break;

	case UFTRACE_AGENT_OPT_CALLER:
		pr_dbg3("apply caller filter '%s' (size=%d)\n", value, size);
		agent_setup_caller_filter(value, triggers);
		break;

	case UFTRACE_AGENT_OPT_TRIGGER:
		pr_dbg3("apply trigger '%s' (size=%d)\n", value, size);
		agent_setup_trigger(value, triggers);
		break;

	default:
		ret = -1;
	}

	return ret;
}

static bool triggers_needs_copy(int opt)
{
	bool ret;
#define MATCHING_OPTIONS                                                                           \
	(UFTRACE_AGENT_OPT_FILTER | UFTRACE_AGENT_OPT_CALLER | UFTRACE_AGENT_OPT_TRIGGER)
	ret = opt & MATCHING_OPTIONS;
#undef MATCHING_OPTIONS
	return ret;
}

/* Agent routine, applying instructions from the CLI. */
static void *agent_apply_commands(void *arg)
{
	int sfd, cfd; /* socket fd, connection fd */
	bool close_connection;
	struct uftrace_msg msg;
	struct sockaddr_un addr;
	void *value = NULL;
	size_t size;
	struct uftrace_triggers_info *triggers_copy = NULL;

	/* initialize agent */
	sfd = agent_init(&addr);
	if (sfd == -1) {
		pr_warn("agent cannot start\n");
		return NULL;
	}
	agent_run = true;
	pr_dbg("agent started on socket '%s'\n", addr.sun_path);

	/* handle incoming connections consecutively */
	while (agent_run) {
		cfd = agent_accept(sfd);
		if (cfd == -1) {
			pr_dbg2("error accepting socket connection\n");
			continue;
		}
		pr_dbg3("client connected\n");

		/* read client messages */
		close_connection = false;
		while (!close_connection) {
			int status = 0;
			int opt;

			/* read message header to get type */
			if (agent_message_read_head(cfd, &msg) == -1) {
				status = EINVAL;
				pr_dbg3("error reading client message\n");
				agent_message_send(cfd, UFTRACE_MSG_AGENT_ERR, &status,
						   sizeof(status));
				continue;
			}

			/* parse message body */
			switch (msg.type) {
			case UFTRACE_MSG_AGENT_QUERY:
				status = MCOUNT_AGENT_CAPABILITIES;
				pr_dbg3("send capabilities to client\n");
				agent_message_send(cfd, UFTRACE_MSG_AGENT_OK, &status,
						   sizeof(status));
				break;

			case UFTRACE_MSG_AGENT_SET_OPT:
				size = agent_read_option(cfd, &opt, &value, msg.len);
				if (status < 0) {
					status = EINVAL;
					agent_message_send(cfd, UFTRACE_MSG_AGENT_ERR, &status,
							   sizeof(status));
					break;
				}

				/* deep copy mcount_triggers for each connection (if needed) */
				if (triggers_needs_copy(opt) && !triggers_copy) {
					triggers_copy = xmalloc(sizeof(*triggers_copy));
					*triggers_copy =
						uftrace_deep_copy_triggers(mcount_triggers);
				}
				status = agent_apply_option(opt, value, size, triggers_copy);
				if (status == 0)
					agent_message_send(cfd, UFTRACE_MSG_AGENT_OK, NULL, 0);
				else
					agent_message_send(cfd, UFTRACE_MSG_AGENT_ERR, &status,
							   sizeof(status));
				break;

			case UFTRACE_MSG_AGENT_GET_OPT:
				/* TODO send data */
				agent_message_send(cfd, UFTRACE_MSG_AGENT_OK, NULL, 0);
				break;

			case UFTRACE_MSG_AGENT_CLOSE:
				close_connection = true;
				agent_message_send(cfd, UFTRACE_MSG_AGENT_OK, NULL, 0);
				break;

			default:
				close_connection = true;
				pr_dbg3("agent message not recognized\n");
			}
		}

		if (triggers_copy) {
			swap_triggers(&mcount_triggers, triggers_copy);
			triggers_copy = NULL;
		}

		if (close(cfd) == -1)
			pr_dbg3("error closing client socket\n");
		else
			pr_dbg3("client disconnected\n");
	}

	free(value);
	agent_fini(&addr, sfd);
	return 0;
}

int agent_spawn(void)
{
	errno = pthread_create(&agent, NULL, &agent_apply_commands, NULL);
	if (errno != 0) {
		pr_warn("cannot start agent: %s\n", strerror((errno)));
		return -1;
	}
	return 0;
}

/* Check if the agent is up. If so, set its run flag to false, open and close
 * connection . */
int agent_kill(void)
{
	int sfd;
	int status;
	struct sockaddr_un addr;
	struct uftrace_msg ack;

	if (!agent_run)
		return 0;
	agent_run = false;

	sfd = agent_socket_create(&addr, getpid());
	if (sfd == -1)
		goto error;

	if (agent_connect(sfd, &addr) == -1) {
		if (errno != ENOENT) /* The agent may have ended and deleted the socket */
			goto error;
	}

	status = agent_message_send(sfd, UFTRACE_MSG_AGENT_CLOSE, NULL, 0);
	if (status < 0)
		goto error;
	status = agent_message_read_response(sfd, &ack);
	if (status < 0 || ack.type != UFTRACE_MSG_AGENT_OK)
		goto error;

	close(sfd);

	if (pthread_join(agent, NULL) != 0)
		pr_dbg("agent left in unknown state\n");

	return 0;

error:
	pr_dbg2("error terminating agent routine\n");
	close(sfd);
	socket_unlink(&addr);
	return -1;
}

#ifdef UNIT_TEST
TEST_CASE(mcount_agent)
{
	pr_dbg("starting the agent\n");
	TEST_EQ(agent_spawn(), 0);
	do {
		usleep(1000);
	} while (!agent_run);
	pr_dbg("killing the agent\n");
	TEST_EQ(agent_kill(), 0);
	return TEST_OK;
}
#endif /* UNIT_TEST */
