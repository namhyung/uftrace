#ifndef __UFTRACE_H__
#define __UFTRACE_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <libelf.h>
#include <fcntl.h>

#include "utils/rbtree.h"
#include "utils/list.h"
#include "utils/symbol.h"


#define UFTRACE_MAGIC_LEN  8
#define UFTRACE_MAGIC_STR  "Ftrace!"
#define UFTRACE_FILE_VERSION  4
#define UFTRACE_FILE_VERSION_MIN  3
#define UFTRACE_DIR_NAME     "uftrace.data"
#define UFTRACE_DIR_OLD_NAME  "ftrace.dir"

#define UFTRACE_RECV_PORT  8090

#define OPT_RSTACK_MAX  65535

struct ftrace_file_header {
	char magic[UFTRACE_MAGIC_LEN];
	uint32_t version;
	uint16_t header_size;
	uint8_t  endian;
	uint8_t  class;
	uint64_t feat_mask;
	uint64_t info_mask;
	uint16_t max_stack;
	uint16_t unused1;
	uint32_t unused2;
};

enum ftrace_feat_bits {
	/* bit index */
	PLTHOOK_BIT,
	TASK_SESSION_BIT,
	KERNEL_BIT,
	ARGUMENT_BIT,
	RETVAL_BIT,
	SYM_REL_ADDR_BIT,
	MAX_STACK_BIT,

	/* bit mask */
	PLTHOOK			= (1U << PLTHOOK_BIT),
	TASK_SESSION		= (1U << TASK_SESSION_BIT),
	KERNEL			= (1U << KERNEL_BIT),
	ARGUMENT		= (1U << ARGUMENT_BIT),
	RETVAL			= (1U << RETVAL_BIT),
	SYM_REL_ADDR		= (1U << SYM_REL_ADDR_BIT),
	MAX_STACK		= (1U << MAX_STACK_BIT),
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
	ARG_SPEC,
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
	char *argspec;
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
	struct ftrace_task_handle *tasks;
	int nr_tasks;
	int depth;
	uint64_t time_filter;
};

#define UFTRACE_MODE_INVALID 0
#define UFTRACE_MODE_RECORD  1
#define UFTRACE_MODE_REPLAY  2
#define UFTRACE_MODE_LIVE    3
#define UFTRACE_MODE_REPORT  4
#define UFTRACE_MODE_INFO    5
#define UFTRACE_MODE_RECV    6
#define UFTRACE_MODE_DUMP    7
#define UFTRACE_MODE_GRAPH   8

#define UFTRACE_MODE_DEFAULT  UFTRACE_MODE_LIVE

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
	char *args;
	char *retval;
	char *diff;
	int mode;
	int idx;
	int depth;
	int kernel_depth;
	int max_stack;
	int port;
	int color;
	int column_offset;
	int sort_column;
	int nr_thread;
	int rt_prio;
	unsigned long bufsize;
	unsigned long kernel_bufsize;
	uint64_t threshold;
	uint64_t sample_time;
	bool flat;
	bool libcall;
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
	bool disabled;
	bool report;
	bool column_view;
	bool want_bind_not;
	bool task_newline;
	bool chrome_trace;
	bool comment;
	bool flame_graph;
	bool libmcount_single;
	bool kernel;
	bool kernel_skip_out;
	bool kernel_only;
};

int command_record(int argc, char *argv[], struct opts *opts);
int command_replay(int argc, char *argv[], struct opts *opts);
int command_live(int argc, char *argv[], struct opts *opts);
int command_report(int argc, char *argv[], struct opts *opts);
int command_info(int argc, char *argv[], struct opts *opts);
int command_recv(int argc, char *argv[], struct opts *opts);
int command_dump(int argc, char *argv[], struct opts *opts);
int command_graph(int argc, char *argv[], struct opts *opts);

extern volatile bool ftrace_done;
extern struct ftrace_proc_maps *proc_maps;

int open_data_file(struct opts *opts, struct ftrace_file_handle *handle);
void close_data_file(struct opts *opts, struct ftrace_file_handle *handle);
int read_task_file(char *dirname, bool needs_session, bool sym_rel_addr);
int read_task_txt_file(char *dirname, bool needs_session, bool sym_rel_addr);

struct ftrace_session {
	struct rb_node		 node;
	char			 sid[16];
	uint64_t		 start_time;
	int			 pid, tid;
	struct symtabs		 symtabs;
	struct rb_root		 filters;
	struct rb_root		 fixups;
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

void create_session(struct ftrace_msg_sess *msg, char *dirname, char *exename,
		    bool sym_rel_addr);
struct ftrace_session *find_session(int pid, uint64_t timestamp);
struct ftrace_session *find_task_session(int pid, uint64_t timestamp);
void create_task(struct ftrace_msg_task *msg, bool fork, bool needs_session);
struct ftrace_task *find_task(int tid);
void read_session_map(char *dirname, struct symtabs *symtabs, char *sid);

typedef int (*walk_sessions_cb_t)(struct ftrace_session *session, void *arg);
void walk_sessions(walk_sessions_cb_t callback, void *arg);
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

void write_task_info(const char *dirname, struct ftrace_msg_task *tmsg);
void write_fork_info(const char *dirname, struct ftrace_msg_task *tmsg);
void write_session_info(const char *dirname, struct ftrace_msg_sess *smsg,
			const char *exename);

enum ftrace_ret_stack_type {
	FTRACE_ENTRY,
	FTRACE_EXIT,
	FTRACE_LOST,
};

#define FTRACE_UNUSED_V3  0xa
#define FTRACE_UNUSED_V4  0x5
#define FTRACE_UNUSED     FTRACE_UNUSED_V4

/* reduced version of mcount_ret_stack */
struct ftrace_ret_stack {
	uint64_t time;
	uint64_t type:   2;
	uint64_t more:   1;
	uint64_t unused: 3;
	uint64_t depth:  10;
	uint64_t addr:   48;
};

static inline bool is_v3_compat(struct ftrace_ret_stack *stack)
{
	/* (FTRACE_UNUSED_V4 << 1 | more) == FTRACE_UNUSED_V3 */
	return stack->unused == FTRACE_UNUSED && stack->more == 0;
}

struct fstack_arguments {
	struct list_head	*args;
	unsigned		len;
	void			*data;
};

struct uftrace_rstack_list {
	struct list_head read;
	struct list_head unused;
	int count;
};

struct uftrace_rstack_list_node {
	struct list_head list;
	struct ftrace_ret_stack rstack;
	struct fstack_arguments args;
};

void setup_rstack_list(struct uftrace_rstack_list *list);
void add_to_rstack_list(struct uftrace_rstack_list *list,
			struct ftrace_ret_stack *rstack,
			struct fstack_arguments *args);
struct ftrace_ret_stack * get_first_rstack_list(struct uftrace_rstack_list *);
void consume_first_rstack_list(struct uftrace_rstack_list *list);
void delete_last_rstack_list(struct uftrace_rstack_list *list);
void reset_rstack_list(struct uftrace_rstack_list *list);

enum ftrace_ext_type {
	FTRACE_ARGUMENT		= 1,
};

struct kbuffer;
struct pevent;

struct ftrace_kernel {
	int pid;
	int nr_cpus;
	int depth;
	bool skip_out;
	unsigned long bufsize;
	int *traces;
	int *fds;
	int64_t *offsets;
	int64_t *sizes;
	void **mmaps;
	struct kbuffer **kbufs;
	struct pevent *pevent;
	struct ftrace_ret_stack *rstacks;
	struct uftrace_rstack_list *rstack_list;
	bool *rstack_valid;
	bool *rstack_done;
	int *missed_events;
	int *tids;
	char *output_dir;
	struct list_head filters;
	struct list_head notrace;
};

/* these functions will be used at record time */
int setup_kernel_tracing(struct ftrace_kernel *kernel, char *filters);
int start_kernel_tracing(struct ftrace_kernel *kernel);
int record_kernel_tracing(struct ftrace_kernel *kernel);
int record_kernel_trace_pipe(struct ftrace_kernel *kernel, int cpu);
int stop_kernel_tracing(struct ftrace_kernel *kernel);
int finish_kernel_tracing(struct ftrace_kernel *kernel);

/* these functions will be used at replay time */
int setup_kernel_data(struct ftrace_kernel *kernel);
int read_kernel_stack(struct ftrace_file_handle *handle,
		      struct ftrace_task_handle **taskp);
int read_kernel_cpu_data(struct ftrace_kernel *kernel, int cpu);
int finish_kernel_data(struct ftrace_kernel *kernel);

struct rusage;

void fill_ftrace_info(uint64_t *info_mask, int fd, struct opts *opts, int status,
		      struct rusage *rusage);
int read_ftrace_info(uint64_t info_mask, struct ftrace_file_handle *handle);
void clear_ftrace_info(struct ftrace_info *info);

int arch_fill_cpuinfo_model(int fd);
int arch_register_index(char *reg_name);

#endif /* __UFTRACE_H__ */
