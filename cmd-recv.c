#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>

#include "ftrace.h"
#include "utils/utils.h"

static int server_socket(struct opts *opts)
{
	int sock;
	int on = 1;
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_addr	= {
			.s_addr	= htonl(INADDR_ANY),
		},
		.sin_port	= htons(opts->port),
	};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		pr_err("socket creation failed");

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		pr_err("socket bind failed");

	if (listen(sock, 5) < 0)
		pr_err("socket listen failed");

	return sock;
}

static int signal_fd(struct opts *opts)
{
	int fd;
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
		pr_err("signal block failed");

	fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	if (fd < 0)
		pr_err("signalfd failed");

	return fd;
}

int setup_client_socket(struct opts *opts)
{
	struct sockaddr_in addr = {
		.sin_family	= AF_INET,
		.sin_port	= htons(opts->port),
	};
	struct hostent *hostinfo;
	int sock;
	int one = 1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		pr_err("socket create failed");

	setsockopt(sock, SOL_TCP, TCP_NODELAY, &one, sizeof(one));

	hostinfo = gethostbyname(opts->host);
	if (hostinfo == NULL)
		pr_err("cannot find host: %s", opts->host);

	addr.sin_addr = *(struct in_addr *) hostinfo->h_addr;

	if (connect(sock, &addr, sizeof(addr)) < 0)
		pr_err("socket connect failed");

	return sock;
}

static void epoll_add(int efd, int fd, unsigned event)
{
	struct epoll_event ev = {
		.events	= event,
		.data	= {
			.fd = fd,
		},
	};

	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0)
		pr_err("epoll add failed");
}

static void handle_server_sock(struct epoll_event *ev, int efd)
{
	int client;
	int sock = ev->data.fd;
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	client = accept(sock, &addr, &len);
	if (client < 0)
		pr_err("socket accept failed");

	epoll_add(efd, client, EPOLLIN);
	pr_dbg("new connection added\n");
}

static void handle_client_sock(struct epoll_event *ev, int efd)
{
}

int command_recv(int argc, char *argv[], struct opts *opts)
{
	int sock;
	int sigfd;
	int efd;

	sock = server_socket(opts);
	sigfd = signal_fd(opts);

	efd = epoll_create1(EPOLL_CLOEXEC);
	if (efd < 0)
		pr_err("epoll create failed");

	epoll_add(efd, sock,  EPOLLIN);
	epoll_add(efd, sigfd, EPOLLIN);

	while (!ftrace_done) {
		struct epoll_event ev[10];
		int i, len;

		len = epoll_wait(efd, ev, 10, -1);
		if (len < 0)
			pr_err("epoll wait failed");

		for (i = 0; i < len; i++) {
			if (ev[i].data.fd == sigfd)
				ftrace_done = true;
			else if (ev[i].data.fd == sock)
				handle_server_sock(&ev[i], efd);
			else
				handle_client_sock(&ev[i], efd);
		}
	}

	close(efd);
	close(sigfd);
	close(sock);
	return 0;
}
