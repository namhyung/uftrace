#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "uftrace.h"
#include "utils/socket.h"
#include "utils/utils.h"

/* unlink socket file if it exists */
void socket_unlink(struct sockaddr_un *addr)
{
	if (unlink(addr->sun_path) == -1) {
		if (errno != ENOENT) {
			pr_dbg("cannot unlink %s\n", addr->sun_path);
		}
	}
}

/* Create socket for communication between the client and the agent */
int socket_create(struct sockaddr_un *addr, pid_t pid)
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
int socket_listen(int fd, struct sockaddr_un *addr)
{
	if (bind(fd, (struct sockaddr *)addr, sizeof(struct sockaddr_un)) == -1) {
		pr_warn("cannot bind to socket %s: %s\n", addr->sun_path, strerror(errno));
		close(fd);
		return -1;
	}
	if (listen(fd, 1) == -1) {
		pr_warn("cannot listen to socket %s\n", addr->sun_path);
		close(fd);
		return -1;
	}
	return 0;
}

/* Send a single option to the agent through its socket */
int socket_send_option(int fd, enum uftrace_dopt opt, void *value, size_t size)
{
	if (!write(fd, &opt, sizeof(enum uftrace_dopt)))
		return -1;
	if (value)
		return write(fd, value, size);
	return 0;
}

int socket_connect(int fd, struct sockaddr_un *addr)
{
	if (connect(fd, (struct sockaddr *)addr, sizeof(struct sockaddr_un)) == -1) {
		pr_warn("cannot connect to socket '%s': %s\n", addr->sun_path, strerror(errno));
		return -1;
	}
	return 0;
}

int socket_accept(int fd)
{
	return accept(fd, NULL, NULL);
}
