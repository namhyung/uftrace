#ifndef UFTRACE_SOCKET_H
#define UFTRACE_SOCKET_H

#include <sys/socket.h>

#define MCOUNT_AGENT_SOCKET_DIR "/tmp/uftrace"

struct uftrace_msg;

void socket_unlink(struct sockaddr_un *addr);
int agent_socket_create(struct sockaddr_un *addr, pid_t pid);
int agent_listen(int fd, struct sockaddr_un *addr);
int agent_connect(int fd, struct sockaddr_un *addr);
int agent_accept(int fd);
int agent_message_send(int fd, int type, void *data, size_t size);
int agent_message_read_head(int fd, struct uftrace_msg *msg);
int agent_message_read_response(int fd, struct uftrace_msg *response);

#endif // UFTRACE_SOCKET_H
