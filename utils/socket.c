#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "uftrace.h"
#include "utils/socket.h"
#include "utils/utils.h"

/* Unlink socket file if it exists */
void socket_unlink(struct sockaddr_un *addr)
{
	if (unlink(addr->sun_path) == -1) {
		if (errno != ENOENT)
			pr_dbg("cannot unlink socket '%s'\n", addr->sun_path);
	}
}

/* Create socket for communication between the client and the agent */
int agent_socket_create(struct sockaddr_un *addr, pid_t pid)
{
	int fd;
	char *channel = NULL;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		pr_warn("socket creation failed: %s\n", strerror(errno));
		return fd;
	}
	memset(addr, 0, sizeof(struct sockaddr_un));
	xasprintf(&channel, "%s/%d.socket", MCOUNT_AGENT_SOCKET_DIR, pid);
	addr->sun_family = AF_UNIX;
	strncpy(addr->sun_path, channel, sizeof(addr->sun_path) - 1);
	free(channel);
	return fd;
}

/* Setup socket on agent side so it can accept client connection */
int agent_listen(int fd, struct sockaddr_un *addr)
{
	if (bind(fd, (struct sockaddr *)addr, sizeof(struct sockaddr_un)) == -1) {
		pr_warn("cannot bind to socket '%s': %s\n", addr->sun_path, strerror(errno));
		return -1;
	}

	if (listen(fd, 1) == -1) {
		pr_warn("cannot listen to socket '%s': %s\n", addr->sun_path, strerror(errno));
		return -1;
	}

	return 0;
}

/* Client side: connect to an agent socket */
int agent_connect(int fd, struct sockaddr_un *addr)
{
	if (connect(fd, (struct sockaddr *)addr, sizeof(struct sockaddr_un)) == -1) {
		pr_warn("cannot connect to socket '%s': %s\n", addr->sun_path, strerror(errno));
		return -1;
	}

	return 0;
}

/* Agent side: accept incoming client connection */
int agent_accept(int fd)
{
	return accept(fd, NULL, NULL);
}

/**
 * agent_message_send - send a message through the agent socket
 * @fd     - socket file descriptor
 * @type   - type of message to send
 * @data   - data load
 * @size   - size of @data
 * @return - status code, negative for error
 */
int agent_message_send(int fd, int type, void *data, size_t size)
{
	struct uftrace_msg msg = {
		.magic = UFTRACE_MSG_MAGIC,
		.type = type,
		.len = size,
	};
	struct iovec iov[2] = {
		{
			.iov_base = &msg,
			.iov_len = sizeof(msg),
		},
		{
			.iov_base = data,
			.iov_len = size,
		},
	};

	pr_dbg4("send agent message [%d] (size=%d)\n", type, size);
	if (writev_all(fd, iov, ARRAY_SIZE(iov)) < 0) {
		pr_dbg3("error writing message to agent socket\n");
		return -1;
	}

	return 0;
}

/**
 * agent_message_read_head - read message header from the agent socket
 *
 * Fetch the message type and size so the data load can be read somewhere else.
 *
 * @fd     - socket file descriptor
 * @msg    - received message head
 * @return - status code, negative for error
 */
int agent_message_read_head(int fd, struct uftrace_msg *msg)
{
	if (read_all(fd, msg, sizeof(*msg)) < 0) {
		pr_dbg4("error reading agent message header\n");
		return -1;
	}

	if (msg->magic != UFTRACE_MSG_MAGIC) {
		pr_dbg4("invalid agent message received\n");
		return -1;
	}

	return 0;
}
