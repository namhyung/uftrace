#ifndef __FTRACE_H__
#define __FTRACE_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <libelf.h>
#include <fcntl.h>

#include "utils/rbtree.h"
#include "utils/list.h"
#include "utils/symbol.h"


#ifndef  O_PATH
# define O_PATH  0
#endif

#define FTRACE_MAGIC_LEN  8
#define FTRACE_MAGIC_STR  "Ftrace!"
#define FTRACE_FILE_VERSION  3
#define FTRACE_FILE_VERSION_MIN  2
#define FTRACE_FILE_NAME  "ftrace.data"
#define FTRACE_DIR_NAME   "ftrace.dir"

#define FTRACE_RECV_PORT  8090


struct ftrace_file_header {
	char magic[FTRACE_MAGIC_LEN];
	uint32_t version;
	uint16_t header_size;
	uint8_t  endian;
	uint8_t  class;
	uint64_t feat_mask;
	uint64_t info_mask;
	uint64_t unused;
};

enum ftrace_feat_bits {
	/* bit index */
	PLTHOOK_BIT,
	TASK_SESSION_BIT,
	KERNEL_BIT,

	/* bit mask */
	PLTHOOK			= (1U << PLTHOOK_BIT),
	TASK_SESSION		= (1U << TASK_SESSION_BIT),
	KERNEL			= (1U << KERNEL_BIT),
};

enum ftrace_info_bits {
	EXE_NAME,
	EXE_BUILD_ID,
	EXIT_STATUS,
	CMDLINE,
	CPUINFO,
	MEMINFO,
	OSINFO,
	TASKINFO,
	USAGEINFO,
	LOADINFO,
};

struct ftrace_info {
	char *exename;
	unsigned char build_id[20];
	int exit_status;
	char *cmdline;
	int nr_cpus_online;
	int nr_cpus_possible;
	char *cpudesc;
	char *meminfo;
	char *kernel;
	char *hostname;
	char *distro;
	int nr_tid;
	int *tids;
	double stime;
	double utime;
	long vctxsw;
	long ictxsw;
	long maxrss;
	long major_fault;
	long minor_fault;
	long rblock;
	long wblock;
	float load1;
	float load5;
	float load15;
};

struct ftrace_kernel;

struct ftrace_file_handle {
	FILE *fp;
	int sock;
	const char *dirname;
	struct ftrace_file_header hdr;
	struct ftrace_info info;
	struct ftrace_kernel *kern;
	int depth;
};

#define FTRACE_MODE_INVALID 0
#define FTRACE_MODE_RECORD  1
#define FTRACE_MODE_REPLAY  2
#define FTRACE_MODE_LIVE    3
#define FTRACE_MODE_REPORT  4
#define FTRACE_MODE_INFO    5
#define FTRACE_MODE_RECV    6
#define FTRACE_MODE_DUMP    7

#define FTRACE_MODE_DEFAULT  FTRACE_MODE_LIVE

struct opts {
	char *lib_path;
	char *filter;
	char *trigger;
	char *tid;
	char *exename;
	char *dirname;
	char *logfile;
	char *host;
	char *sort_keys;
	int mode;
	int idx;
	int depth;
	int max_stack;
	int kernel;
	int port;
	int color;
	unsigned long bsize;
	bool flat;
	bool want_plthook;
	bool print_symtab;
	bool force;
	bool report_thread;
	bool no_merge;
	bool nop;
	bool time;
	bool backtrace;
	bool use_pager;
	bool avg_total;
	bool avg_self;
};

int command_record(int argc, char *argv[], struct opts *opts);
int command_replay(int argc, char *argv[], struct opts *opts);
int command_live(int argc, char *argv[], struct opts *opts);
int command_report(int argc, char *argv[], struct opts *opts);
int command_info(int argc, char *argv[], struct opts *opts);
int command_recv(int argc, char *argv[], struct opts *opts);

extern volatile bool ftrace_done;
extern struct ftrace_proc_maps *proc_maps;

int open_data_file(struct opts *opts, struct ftrace_file_handle *handle);
void close_data_file(struct opts *opts, struct ftrace_file_handle *handle);
int read_task_file(char *dirname);

void sighandler(int sig);

struct ftrace_session {
	struct rb_node		 node;
	char			 sid[16];
	uint64_t		 start_time;
	int			 pid, tid;
	struct ftrace_proc_maps *maps;
	struct symtabs		 symtabs;
	int 			 namelen;
	char 			 exename[];
};

struct ftrace_sess_ref {
	struct ftrace_sess_ref	*next;
	struct ftrace_session	*sess;
	uint64_t		 start, end;
};

struct ftrace_task {
	int			 pid, tid;
	struct rb_node		 node;
	struct ftrace_sess_ref	 sess;
	struct ftrace_sess_ref	*sess_last;
};

#define FTRACE_MSG_MAGIC 0xface

#define FTRACE_MSG_REC_START      1U
#define FTRACE_MSG_REC_END        2U
#define FTRACE_MSG_TID            3U
#define FTRACE_MSG_FORK_START     4U
#define FTRACE_MSG_FORK_END       5U
#define FTRACE_MSG_SESSION        6U
#define FTRACE_MSG_LOST           7U
#define FTRACE_MSG_SEND_HDR       8U
#define FTRACE_MSG_SEND_DATA      9U
#define FTRACE_MSG_SEND_TASK     10U
#define FTRACE_MSG_SEND_SESSION  11U
#define FTRACE_MSG_SEND_MAP      12U
#define FTRACE_MSG_SEND_SYM      13U
#define FTRACE_MSG_SEND_INFO     14U
#define FTRACE_MSG_SEND_END      15U

/* msg format for communicating by pipe */
struct ftrace_msg {
	unsigned short magic; /* FTRACE_MSG_MAGIC */
	unsigned short type;  /* FTRACE_MSG_REC_* */
	unsigned int len;
	unsigned char data[];
};

struct ftrace_msg_task {
	uint64_t time;
	int32_t  pid;
	int32_t  tid;
};

struct ftrace_msg_sess {
	struct ftrace_msg_task task;
	char sid[16];
	int  unused;
	int  namelen;
	char exename[];
};

extern struct ftrace_session *first_session;

void create_session(struct ftrace_msg_sess *msg, char *dirname, char *exename);
struct ftrace_session *find_session(int pid, uint64_t timestamp);
struct ftrace_session *find_task_session(int pid, uint64_t timestamp);
void create_task(struct ftrace_msg_task *msg, bool fork);
struct ftrace_task *find_task(int tid);

typedef int (*walk_tasks_cb_t)(struct ftrace_task *task, void *arg);
void walk_tasks(walk_tasks_cb_t callback, void *arg);

int setup_client_socket(struct opts *opts);
void send_trace_header(int sock, char *name);
void send_trace_data(int sock, int tid, void *data, size_t len);
void send_trace_task(int sock, struct ftrace_msg *hmsg,
		     struct ftrace_msg_task *tmsg);
void send_trace_session(int sock, struct ftrace_msg *hmsg,
			struct ftrace_msg_sess *smsg,
			char *exename, int namelen);
void send_trace_map(int sock, uint64_t sid, void *map, int len);
void send_trace_sym(int sock, char *symfile, void *map, int len);
void send_trace_info(int sock, struct ftrace_file_header *hdr,
		     void *info, int len);
void send_trace_end(int sock);

enum ftrace_ret_stack_type {
	FTRACE_ENTRY,
	FTRACE_EXIT,
	FTRACE_LOST,
};

#define FTRACE_UNUSED  0xa

/* reduced version of mcount_ret_stack */
struct ftrace_ret_stack {
	uint64_t time;
	uint64_t type:   2;
	uint64_t unused: 4;
	uint64_t depth:  10;
	uint64_t addr:   48;
};

struct kbuffer;
struct pevent;

struct ftrace_kernel {
	int pid;
	int nr_cpus;
	int depth;
	int *traces;
	int *fds;
	int64_t *offsets;
	int64_t *sizes;
	void **mmaps;
	struct kbuffer **kbufs;
	struct pevent *pevent;
	struct mcount_ret_stack *rstacks;
	bool *rstack_valid;
	bool *rstack_done;
	char *output_dir;
	struct list_head filters;
	struct list_head notrace;
};

int setup_kernel_filters(struct ftrace_kernel *kernel, char *filters);
int start_kernel_tracing(struct ftrace_kernel *kernel);
int record_kernel_tracing(struct ftrace_kernel *kernel);
int stop_kernel_tracing(struct ftrace_kernel *kernel);
int finish_kernel_tracing(struct ftrace_kernel *kernel);

int setup_kernel_data(struct ftrace_kernel *kernel);
int read_kernel_stack(struct ftrace_kernel *kernel, struct mcount_ret_stack *rstack);
int finish_kernel_data(struct ftrace_kernel *kernel);

struct rusage;

void fill_ftrace_info(uint64_t *info_mask, int fd, struct opts *opts, int status,
		      struct rusage *rusage);
int read_ftrace_info(uint64_t info_mask, struct ftrace_file_handle *handle);
void clear_ftrace_info(struct ftrace_info *info);

int arch_fill_cpuinfo_model(int fd);

#endif /* __FTRACE_H__ */
