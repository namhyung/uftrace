#ifndef UFTRACE_SOCKET_H
#define UFTRACE_SOCKET_H

#include <sys/socket.h>

#define MCOUNT_AGENT_SOCKET_DIR "/tmp/uftrace"

enum uftrace_dopt;

void socket_unlink(struct sockaddr_un *addr);
int socket_create(struct sockaddr_un *addr, pid_t pid);
int socket_listen(int fd, struct sockaddr_un *addr);
int socket_connect(int fd, struct sockaddr_un *addr);
int socket_accept(int fd);
int socket_send_option(int fd, enum uftrace_dopt opt, void *value, size_t size);

#endif // UFTRACE_SOCKET_H
