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

#define OPT_RSTACK_MAX      65535
#define OPT_RSTACK_DEFAULT  1024
#define OPT_DEPTH_MAX       OPT_RSTACK_MAX
#define OPT_DEPTH_DEFAULT   OPT_RSTACK_DEFAULT

#define KB 1024
#define MB (KB * 1024)

struct uftrace_file_header {
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

enum uftrace_feat_bits {
	/* bit index */
	PLTHOOK_BIT,
	TASK_SESSION_BIT,
	KERNEL_BIT,
	ARGUMENT_BIT,
	RETVAL_BIT,
	SYM_REL_ADDR_BIT,
	MAX_STACK_BIT,
	EVENT_BIT,

	FEAT_BIT_MAX,

	/* bit mask */
	PLTHOOK			= (1U << PLTHOOK_BIT),
	TASK_SESSION		= (1U << TASK_SESSION_BIT),
	KERNEL			= (1U << KERNEL_BIT),
	ARGUMENT		= (1U << ARGUMENT_BIT),
	RETVAL			= (1U << RETVAL_BIT),
	SYM_REL_ADDR		= (1U << SYM_REL_ADDR_BIT),
	MAX_STACK		= (1U << MAX_STACK_BIT),
	EVENT			= (1U << EVENT_BIT),
};

enum uftrace_info_bits {
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

struct uftrace_info {
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

enum {
	UFTRACE_EXIT_SUCCESS	= 0,
	UFTRACE_EXIT_FAILURE,
	UFTRACE_EXIT_SIGNALED,
	UFTRACE_EXIT_UNKNOWN,
};

struct kbuffer;
struct pevent;
struct uftrace_record;
struct uftrace_rstack_list;
struct uftrace_session;
struct uftrace_kernel_reader;

struct uftrace_session_link {
	struct rb_root		root;
	struct rb_root		tasks;
	struct uftrace_session *first;
};

struct ftrace_file_handle {
	FILE *fp;
	int sock;
	const char *dirname;
	struct uftrace_file_header hdr;
	struct uftrace_info info;
	struct uftrace_kernel_reader *kernel;
	struct ftrace_task_handle *tasks;
	struct uftrace_session_link sessions;
	int nr_tasks;
	int depth;
	bool needs_byte_swap;
	bool needs_bit_swap;
	uint64_t time_filter;
	struct uftrace_time_range time_range;
	struct list_head events;
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
#define UFTRACE_MODE_SCRIPT  9

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
	char *fields;
	char *patch;
	char *event;
	char **run_cmd;
	char *opt_file;
	char *script_file;
	char *diff_policy;
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
	bool kernel_skip_out;  /* also affects VDSO filter */
	bool kernel_only;
	bool list_event;
	bool keep_pid;
	struct uftrace_time_range range;
};

static inline bool opts_has_filter(struct opts *opts)
{
	return opts->filter || opts->trigger || opts->threshold ||
		opts->depth != OPT_DEPTH_DEFAULT;
}

int command_record(int argc, char *argv[], struct opts *opts);
int command_replay(int argc, char *argv[], struct opts *opts);
int command_live(int argc, char *argv[], struct opts *opts);
int command_report(int argc, char *argv[], struct opts *opts);
int command_info(int argc, char *argv[], struct opts *opts);
int command_recv(int argc, char *argv[], struct opts *opts);
int command_dump(int argc, char *argv[], struct opts *opts);
int command_graph(int argc, char *argv[], struct opts *opts);
int command_script(int argc, char *argv[], struct opts *opts);

extern volatile bool uftrace_done;
extern struct ftrace_proc_maps *proc_maps;

int open_data_file(struct opts *opts, struct ftrace_file_handle *handle);
void close_data_file(struct opts *opts, struct ftrace_file_handle *handle);
int read_task_file(struct uftrace_session_link *sess, char *dirname,
		   bool needs_session, bool sym_rel_addr);
int read_task_txt_file(struct uftrace_session_link *sess, char *dirname,
		       bool needs_session, bool sym_rel_addr);

#define SESSION_ID_LEN  16

struct uftrace_session {
	struct rb_node		 node;
	char			 sid[SESSION_ID_LEN];
	uint64_t		 start_time;
	int			 pid, tid;
	struct symtabs		 symtabs;
	struct rb_root		 filters;
	struct rb_root		 fixups;
	struct list_head	 dlopen_libs;
	int 			 namelen;
	char 			 exename[];
};

struct uftrace_sess_ref {
	struct uftrace_sess_ref	*next;
	struct uftrace_session	*sess;
	uint64_t		 start, end;
};

struct uftrace_dlopen_list {
	struct list_head	list;
	uint64_t		time;
	unsigned long		base;
	struct symtabs		symtabs;
	char			name[];
};

struct uftrace_task {
	int			 pid, tid, ppid;
	struct rb_node		 node;
	struct uftrace_sess_ref	 sref;
	struct uftrace_sess_ref	*sref_last;
};

#define UFTRACE_MSG_MAGIC 0xface

enum uftrace_msg_type {
	UFTRACE_MSG_REC_START		= 1,
	UFTRACE_MSG_REC_END,
	UFTRACE_MSG_TASK_START,
	UFTRACE_MSG_TASK_END,
	UFTRACE_MSG_FORK_START,
	UFTRACE_MSG_FORK_END,
	UFTRACE_MSG_SESSION,
	UFTRACE_MSG_LOST,
	UFTRACE_MSG_DLOPEN,
	UFTRACE_MSG_FINISH,

	UFTRACE_MSG_SEND_START		= 100,
	UFTRACE_MSG_SEND_DIR_NAME,
	UFTRACE_MSG_SEND_DATA,
	UFTRACE_MSG_SEND_KERNEL_DATA,
	UFTRACE_MSG_SEND_INFO,
	UFTRACE_MSG_SEND_META_DATA,
	UFTRACE_MSG_SEND_END,
};

/* msg format for communicating by pipe */
struct uftrace_msg {
	unsigned short magic; /* UFTRACE_MSG_MAGIC */
	unsigned short type;  /* UFTRACE_MSG_REC_* */
	unsigned int len;
	unsigned char data[];
};

struct uftrace_msg_task {
	uint64_t time;
	int32_t  pid;
	int32_t  tid;
};

struct uftrace_msg_sess {
	struct uftrace_msg_task task;
	char sid[16];
	int  unused;
	int  namelen;
	char exename[];
};

struct uftrace_msg_dlopen {
	struct uftrace_msg_task task;
	uint64_t base_addr;
	char sid[16];
	int  unused;
	int  namelen;
	char exename[];
};

extern struct uftrace_session *first_session;

void create_session(struct uftrace_session_link *sess, struct uftrace_msg_sess *msg,
		    char *dirname, char *exename, bool sym_rel_addr);
struct uftrace_session *find_session(struct uftrace_session_link *sess,
				     int pid, uint64_t timestamp);
struct uftrace_session *find_task_session(struct uftrace_session_link *sess,
					  int pid, uint64_t timestamp);
void create_task(struct uftrace_session_link *sess, struct uftrace_msg_task *msg,
		 bool fork, bool needs_session);
struct uftrace_task *find_task(struct uftrace_session_link *sess, int tid);
void read_session_map(char *dirname, struct symtabs *symtabs, char *sid);
struct uftrace_session * get_session_from_sid(struct uftrace_session_link *sess,
					      char sid[]);
void session_add_dlopen(struct uftrace_session *sess, uint64_t timestamp,
			unsigned long base_addr, const char *libname);
struct sym * session_find_dlsym(struct uftrace_session *sess, uint64_t timestamp,
				unsigned long addr);
void delete_sessions(struct uftrace_session_link *sess);

struct uftrace_record;
struct sym * task_find_sym(struct uftrace_session_link *sess,
			   struct ftrace_task_handle *task,
			   struct uftrace_record *rec);
struct sym * task_find_sym_addr(struct uftrace_session_link *sess,
				struct ftrace_task_handle *task,
				uint64_t time, uint64_t addr);

typedef int (*walk_sessions_cb_t)(struct uftrace_session *session, void *arg);
void walk_sessions(struct uftrace_session_link *sess,
		   walk_sessions_cb_t callback, void *arg);
typedef int (*walk_tasks_cb_t)(struct uftrace_task *task, void *arg);
void walk_tasks(struct uftrace_session_link *sess,
		walk_tasks_cb_t callback, void *arg);

int setup_client_socket(struct opts *opts);
void send_trace_dir_name(int sock, char *name);
void send_trace_data(int sock, int tid, void *data, size_t len);
void send_trace_kernel_data(int sock, int cpu, void *data, size_t len);
void send_trace_metadata(int sock, const char *dirname, char *filename);
void send_trace_info(int sock, struct uftrace_file_header *hdr,
		     void *info, int len);
void send_trace_end(int sock);

void write_task_info(const char *dirname, struct uftrace_msg_task *tmsg);
void write_fork_info(const char *dirname, struct uftrace_msg_task *tmsg);
void write_session_info(const char *dirname, struct uftrace_msg_sess *smsg,
			const char *exename);
void write_dlopen_info(const char *dirname, struct uftrace_msg_dlopen *dmsg,
		       const char *libname);

enum uftrace_record_type {
	UFTRACE_ENTRY,
	UFTRACE_EXIT,
	UFTRACE_LOST,
	UFTRACE_EVENT,
};

#define RECORD_MAGIC_V3  0xa
#define RECORD_MAGIC_V4  0x5
#define RECORD_MAGIC     RECORD_MAGIC_V4

/* reduced version of mcount_ret_stack */
struct uftrace_record {
	uint64_t time;
	uint64_t type:   2;
	uint64_t more:   1;
	uint64_t magic:  3;
	uint64_t depth:  10;
	uint64_t addr:   48;
};

static inline bool is_v3_compat(struct uftrace_record *urec)
{
	/* (RECORD_MAGIC_V4 << 1 | more) == RECORD_MAGIC_V3 */
	return urec->magic == RECORD_MAGIC && urec->more == 0;
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
	struct uftrace_record rstack;
	struct fstack_arguments args;
};

void setup_rstack_list(struct uftrace_rstack_list *list);
void add_to_rstack_list(struct uftrace_rstack_list *list,
			struct uftrace_record *rstack,
			struct fstack_arguments *args);
struct uftrace_record * get_first_rstack_list(struct uftrace_rstack_list *);
void consume_first_rstack_list(struct uftrace_rstack_list *list);
void delete_last_rstack_list(struct uftrace_rstack_list *list);
void reset_rstack_list(struct uftrace_rstack_list *list);

enum ftrace_ext_type {
	FTRACE_ARGUMENT		= 1,
};

struct rusage;

void fill_ftrace_info(uint64_t *info_mask, int fd, struct opts *opts, int status,
		      struct rusage *rusage);
int read_ftrace_info(uint64_t info_mask, struct ftrace_file_handle *handle);
void clear_ftrace_info(struct uftrace_info *info);

int arch_fill_cpuinfo_model(int fd);
int arch_register_index(char *reg_name);

enum ufrace_event_id {
	EVENT_ID_KERNEL	= 0U,
	/* kernel IDs are read from tracefs */

	EVENT_ID_BUILTIN = 100000U,
	EVENT_ID_PROC_STATM,
	EVENT_ID_PAGE_FAULT,

	EVENT_ID_USER	= 1000000U,
};

struct uftrace_event {
	struct list_head list;
	unsigned id;
	char *provider;
	char *event;
};

#endif /* __UFTRACE_H__ */
