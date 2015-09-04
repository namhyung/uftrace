#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>

#include "ftrace.h"
#include "utils/utils.h"
#include "utils/list.h"

struct client_data {
	struct list_head	list;
	int			sock;
	char			*dirname;
	int			dir_fd;
};

static LIST_HEAD(client_list);

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

/* client (record) side API */
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

void send_trace_header(int sock, char *name)
{
	ssize_t len = strlen(name);
	struct ftrace_msg msg = {
		.magic = htons(FTRACE_MSG_MAGIC),
		.type  = htons(FTRACE_MSG_SEND_HDR),
		.len   = htonl(len),
	};
	struct iovec iov[] = {
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = name, .iov_len = len, },
	};

	pr_dbg("send FTRACE_MSG_SEND_HDR\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send header failed");
}

void send_trace_data(int sock, int tid, void *data, size_t len)
{
	int32_t msg_tid = htonl(tid);
	struct ftrace_msg msg = {
		.magic = htons(FTRACE_MSG_MAGIC),
		.type  = htons(FTRACE_MSG_SEND_DATA),
		.len   = htonl(sizeof(msg_tid) + len),
	};
	struct iovec iov[] = {
		{ .iov_base = &msg,     .iov_len = sizeof(msg), },
		{ .iov_base = &msg_tid, .iov_len = sizeof(msg_tid), },
		{ .iov_base = data,     .iov_len = len, },
	};

	pr_dbg("send FTRACE_MSG_SEND_DATA\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send data failed");
}

void send_trace_task(int sock, struct ftrace_msg *hmsg,
		     struct ftrace_msg_task *tmsg)
{
	struct ftrace_msg msg = {
		.magic = htons(FTRACE_MSG_MAGIC),
		.type  = htons(FTRACE_MSG_SEND_TASK),
		.len   = htonl(sizeof(*hmsg) + sizeof(*tmsg)),
	};
	struct iovec iov[] = {
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = hmsg, .iov_len = sizeof(*hmsg), },
		{ .iov_base = tmsg, .iov_len = sizeof(*tmsg), },
	};

	hmsg->magic = htons(hmsg->magic);
	hmsg->type  = htons(hmsg->type);
	hmsg->len   = htonl(hmsg->len);

	tmsg->time = htonq(tmsg->time);
	tmsg->pid  = htonl(tmsg->pid);
	tmsg->tid  = htonl(tmsg->tid);

	pr_dbg("send FTRACE_MSG_SEND_TASK\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send task data failed");
}

/* namelen is 8-byte aligned length of smsg->namelen */
void send_trace_session(int sock, struct ftrace_msg *hmsg,
			struct ftrace_msg_sess *smsg,
			char *exename, int namelen)
{
	struct ftrace_msg msg = {
		.magic = htons(FTRACE_MSG_MAGIC),
		.type  = htons(FTRACE_MSG_SEND_SESSION),
		.len   = htonl(sizeof(*hmsg) + sizeof(*smsg)),
	};
	struct iovec iov[] = {
		{ .iov_base = &msg,    .iov_len = sizeof(msg), },
		{ .iov_base = hmsg,    .iov_len = sizeof(*hmsg), },
		{ .iov_base = smsg,    .iov_len = sizeof(*smsg), },
		{ .iov_base = exename, .iov_len = namelen, },
	};
	uint64_t sid;
	char sidbuf[sizeof(smsg->sid) + 1];

	hmsg->magic = htons(hmsg->magic);
	hmsg->type  = htons(hmsg->type);
	hmsg->len   = htonl(hmsg->len);

	smsg->task.time = htonq(smsg->task.time);
	smsg->task.pid  = htonl(smsg->task.pid);
	smsg->task.tid  = htonl(smsg->task.tid);
	smsg->namelen   = htonl(smsg->namelen);

	sscanf(smsg->sid, "%016"SCNx64, &sid);
	snprintf(sidbuf, sizeof(sidbuf), "%016"PRIx64, htonq(sid));
	memcpy(smsg->sid, sidbuf, sizeof(smsg->sid));

	pr_dbg("send FTRACE_MSG_SEND_SESSION\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send session data failed");
}

void send_trace_map(int sock, uint64_t sid, void *map, int len)
{
	struct ftrace_msg msg = {
		.magic = htons(FTRACE_MSG_MAGIC),
		.type  = htons(FTRACE_MSG_SEND_MAP),
		.len   = htonl(sizeof(sid) + len),
	};
	uint64_t msg_sid = htonq(sid);
	struct iovec iov[] = {
		{ .iov_base = &msg,     .iov_len = sizeof(msg), },
		{ .iov_base = &msg_sid, .iov_len = sizeof(msg_sid), },
		{ .iov_base = map,      .iov_len = len, },
	};

	pr_dbg("send FTRACE_MSG_SEND_MAP\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send map failed");
}

void send_trace_info(int sock, struct ftrace_file_header *hdr,
		     void *info, int len)
{
	struct ftrace_msg msg = {
		.magic = htons(FTRACE_MSG_MAGIC),
		.type  = htons(FTRACE_MSG_SEND_INFO),
		.len   = htonl(sizeof(*hdr) + len),
	};
	struct iovec iov[] = {
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = hdr,  .iov_len = sizeof(*hdr), },
		{ .iov_base = info, .iov_len = len, },
	};

	hdr->version     = htonl(hdr->version);
	hdr->header_size = htons(hdr->header_size);
	hdr->feat_mask   = htonq(hdr->feat_mask);
	hdr->info_mask   = htonq(hdr->info_mask);

	pr_dbg("send FTRACE_MSG_SEND_INFO\n");
	if (writev_all(sock, iov, ARRAY_SIZE(iov)) < 0)
		pr_err("send info failed");
}


/* server (recv) side API */
static struct client_data *find_client(int sock)
{
	struct client_data *c;

	list_for_each_entry(c, &client_list, list) {
		if (c->sock == sock)
			return c;
	}
	return NULL;
}

#define O_CLIENT_FLAGS  (O_WRONLY | O_APPEND | O_CREAT)

static void write_client_file(struct client_data *c, char *filename, int nr, ...)
{
	int i, fd;
	va_list ap;
	struct iovec iov[nr];

	fd = openat(c->dir_fd, filename, O_CLIENT_FLAGS, 0644);
	if (fd < 0)
		pr_err("file open failed: %s", filename);

	va_start(ap, nr);
	for (i = 0; i < nr; i++) {
		iov[i].iov_base = va_arg(ap, void *);
		iov[i].iov_len  = va_arg(ap, int);
	}
	va_end(ap);

	if (writev_all(fd, iov, nr) < 0)
		pr_err("write client data failed on %s", filename);

	close(fd);
}

static void recv_trace_header(int sock, int len)
{
	char dirname[len + 1];
	struct client_data *client;

	if (read_all(sock, dirname, len) < 0)
		pr_err("recv header failed");
	dirname[len] = '\0';

	client = xmalloc(sizeof(*client));

	client->sock = sock;
	client->dirname = xstrdup(dirname);
	INIT_LIST_HEAD(&client->list);

	create_directory(dirname);
	pr_dbg("create directory: %s\n", dirname);

	client->dir_fd = open(dirname, O_PATH | O_DIRECTORY);
	if (client->dir_fd < 0)
		pr_err("open dir failed");

	list_add(&client->list, &client_list);
}

static void recv_trace_data(int sock, int len)
{
	struct client_data *client;
	int32_t tid;
	char *filename = NULL;
	void *buffer;

	client = find_client(sock);
	if (client == NULL)
		pr_err("no client on this socket\n");

	if (read_all(sock, &tid, sizeof(tid)) < 0)
		pr_err("recv tid failed");
	tid = ntohl(tid);

	xasprintf(&filename, "%d.dat", tid);

	len -= sizeof(tid);
	buffer = xmalloc(len);

	if (read_all(sock, buffer, len) < 0)
		pr_err("recv buffer failed");

	write_client_file(client, filename, 1, buffer, len);

	free(buffer);
	free(filename);
}

static void recv_trace_task(int sock, int len)
{
	struct client_data *client;
	struct ftrace_msg msg;
	struct ftrace_msg_task tmsg;

	client = find_client(sock);
	if (client == NULL)
		pr_err("no client on this socket\n");

	if (read_all(sock, &msg, sizeof(msg)) < 0)
		pr_err("recv task message failed");

	msg.magic = htons(msg.magic);
	msg.type  = htons(msg.type);
	msg.len   = htonl(msg.len);

	if (msg.type != FTRACE_MSG_TID && msg.type != FTRACE_MSG_FORK_END)
		pr_err("invalid task message type: %u\n", msg.type);

	if (read_all(sock, &tmsg, sizeof(tmsg)) < 0)
		pr_err("recv task message failed");

	tmsg.time = htonq(tmsg.time);
	tmsg.pid  = htonl(tmsg.pid);
	tmsg.tid  = htonl(tmsg.tid);

	write_client_file(client, "task", 2, &msg, sizeof(msg),
			  &tmsg, sizeof(tmsg));
}

static void recv_trace_session(int sock, int len)
{
	struct client_data *client;
	struct ftrace_msg msg;
	struct ftrace_msg_sess smsg;
	uint64_t sid;
	char sidbuf[sizeof(smsg.sid) + 1];
	char *exename;
	int namelen;

	client = find_client(sock);
	if (client == NULL)
		pr_err("no client on this socket\n");

	if (read_all(sock, &msg, sizeof(msg)) < 0)
		pr_err("recv session message failed");

	msg.magic = htons(msg.magic);
	msg.type  = htons(msg.type);
	msg.len   = htonl(msg.len);

	if (msg.type != FTRACE_MSG_SESSION)
		pr_err("invalid session message type: %u\n", msg.type);

	if (read_all(sock, &smsg, sizeof(smsg)) < 0)
		pr_err("recv session message failed");

	smsg.task.time = htonq(smsg.task.time);
	smsg.task.pid  = htonl(smsg.task.pid);
	smsg.task.tid  = htonl(smsg.task.tid);
	smsg.namelen   = htonl(smsg.namelen);

	sscanf(smsg.sid, "%016"SCNx64, &sid);
	snprintf(sidbuf, sizeof(sidbuf), "%016"PRIx64, htonq(sid));
	memcpy(smsg.sid, sidbuf, sizeof(smsg.sid));

	namelen = ALIGN(smsg.namelen, 8);
	exename = xmalloc(namelen);

	if (read_all(sock, exename, namelen) < 0)
		pr_err("recv exename failed");

	write_client_file(client, "task", 3, &msg, sizeof(msg),
			  &smsg, sizeof(smsg), exename, namelen);

	free(exename);
}

static void recv_trace_map(int sock, int len)
{
	struct client_data *client;
	uint64_t sid;
	char *mapname = NULL;
	void *mapdata;

	client = find_client(sock);
	if (client == NULL)
		pr_err("no client on this socket\n");

	if (read_all(sock, &sid, sizeof(sid)) < 0)
		pr_err("recv map session id failed");

	sid = ntohq(sid);
	xasprintf(&mapname, "sid-%016"PRIx64".map", sid);

	len -= sizeof(sid);
	mapdata = xmalloc(len);

	if (read_all(sock, mapdata, len) < 0)
		pr_err("recv map file failed");

	write_client_file(client, mapname, 1, mapdata, len);

	free(mapdata);
	free(mapname);
}

static void recv_trace_info(int sock, int len)
{
	struct client_data *client;
	struct ftrace_file_header hdr;
	void *info;

	client = find_client(sock);
	if (client == NULL)
		pr_err("no client on this socket\n");

	if (read_all(sock, &hdr, sizeof(hdr)) < 0)
		pr_err("recv file header failed");

	hdr.version     = ntohl(hdr.version);
	hdr.header_size = ntohs(hdr.header_size);
	hdr.feat_mask   = ntohq(hdr.feat_mask);
	hdr.info_mask   = ntohq(hdr.info_mask);

	len -= sizeof(hdr);
	info = xmalloc(len);

	if (read_all(sock, info, len) < 0)
		pr_err("recv info file failed");

	write_client_file(client, "info", 2, &hdr, sizeof(hdr), info, len);

	free(info);
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
	int sock = ev->data.fd;
	struct ftrace_msg msg;

	if (ev->events & (EPOLLERR | EPOLLHUP)) {
		struct client_data *c;

		pr_log("client socket closed\n");

		if (epoll_ctl(efd, EPOLL_CTL_DEL, sock, NULL) < 0)
			pr_log("epoll del failed");

		c = find_client(sock);
		if (c) {
			free(c->dirname);
			close(c->dir_fd);
			close(c->sock);
			free(c);
		}

		return;
	}

	if (read_all(sock, &msg, sizeof(msg)) < 0)
		pr_err("message recv failed");

	msg.magic = ntohs(msg.magic);
	msg.type  = ntohs(msg.type);
	msg.len   = ntohl(msg.len);

	if (msg.magic != FTRACE_MSG_MAGIC)
		pr_err_ns("invalid message\n");

	switch (msg.type) {
	case FTRACE_MSG_SEND_HDR:
		pr_dbg("receive FTRACE_MSG_SEND_HDR\n");
		recv_trace_header(sock, msg.len);
		break;
	case FTRACE_MSG_SEND_DATA:
		pr_dbg("receive FTRACE_MSG_SEND_DATA\n");
		recv_trace_data(sock, msg.len);
		break;
	case FTRACE_MSG_SEND_TASK:
		pr_dbg("receive FTRACE_MSG_SEND_TASK\n");
		recv_trace_task(sock, msg.len);
		break;
	case FTRACE_MSG_SEND_SESSION:
		pr_dbg("receive FTRACE_MSG_SEND_SESSION\n");
		recv_trace_session(sock, msg.len);
		break;
	case FTRACE_MSG_SEND_MAP:
		pr_dbg("receive FTRACE_MSG_SEND_MAP\n");
		recv_trace_map(sock, msg.len);
		break;
	case FTRACE_MSG_SEND_INFO:
		pr_dbg("receive FTRACE_MSG_SEND_INFO\n");
		recv_trace_info(sock, msg.len);
		break;
	default:
		pr_log("unknown message: %d\n", msg.type);
		break;
	}
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
