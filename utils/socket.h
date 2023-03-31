#ifndef UFTRACE_SOCKET_H
#define UFTRACE_SOCKET_H

#include <sys/socket.h>

#define MCOUNT_AGENT_SOCKET_DIR "/tmp/uftrace"

void socket_unlink(struct sockaddr_un *addr);
int agent_socket_create(struct sockaddr_un *addr, pid_t pid);
int agent_listen(int fd, struct sockaddr_un *addr);
int agent_connect(int fd, struct sockaddr_un *addr);
int agent_accept(int fd);
int agent_message_send(int fd, int opt, void *value, size_t size);

#endif // UFTRACE_SOCKET_H
