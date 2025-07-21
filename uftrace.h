#ifndef UFTRACE_H
#define UFTRACE_H

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "utils/arch.h"
#include "utils/filter.h"
#include "utils/list.h"
#include "utils/perf.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"

#define UFTRACE_MAGIC_LEN 8
#define UFTRACE_MAGIC_STR "Ftrace!"
#define UFTRACE_FILE_VERSION 4
#define UFTRACE_FILE_VERSION_MIN 3
#define UFTRACE_DIR_NAME "uftrace.data"
#define UFTRACE_DIR_OLD_NAME "ftrace.dir"

#define UFTRACE_RECV_PORT 8090

/* default option values */
#define OPT_RSTACK_MAX 65535
#define OPT_RSTACK_DEFAULT 1024
#define OPT_DEPTH_MAX OPT_RSTACK_MAX
#define OPT_THRESHOLD_MAX 0xFFFFFFFFFFFFFFFF /* max uint64 = 2^64-1 */
#define OPT_DEPTH_DEFAULT OPT_RSTACK_DEFAULT
#define OPT_COLUMN_OFFSET 8
#define OPT_SORT_COLUMN 2
#define OPT_SORT_KEYS "total"

#define KB 1024
#define MB (KB * 1024)

struct uftrace_file_header {
	char magic[UFTRACE_MAGIC_LEN];
	uint32_t version;
	uint16_t header_size;
	uint8_t endian;
	uint8_t elf_class;
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
	PERF_EVENT_BIT,
	AUTO_ARGS_BIT,
	DEBUG_INFO_BIT,
	ESTIMATE_RETURN_BIT,
	SYM_SIZE_BIT,

	FEAT_BIT_MAX,

	/* bit mask */
	PLTHOOK = (1U << PLTHOOK_BIT),
	TASK_SESSION = (1U << TASK_SESSION_BIT),
	KERNEL = (1U << KERNEL_BIT),
	ARGUMENT = (1U << ARGUMENT_BIT),
	RETVAL = (1U << RETVAL_BIT),
	SYM_REL_ADDR = (1U << SYM_REL_ADDR_BIT),
	MAX_STACK = (1U << MAX_STACK_BIT),
	EVENT = (1U << EVENT_BIT),
	PERF_EVENT = (1U << PERF_EVENT_BIT),
	AUTO_ARGS = (1U << AUTO_ARGS_BIT),
	DEBUG_INFO = (1U << DEBUG_INFO_BIT),
	ESTIMATE_RETURN = (1U << ESTIMATE_RETURN_BIT),
	SYM_SIZE = (1U << SYM_SIZE_BIT),
};

enum uftrace_info_bits {
	/* bit index */
	EXE_NAME_BIT,
	EXE_BUILD_ID_BIT,
	EXIT_STATUS_BIT,
	CMDLINE_BIT,
	CPUINFO_BIT,
	MEMINFO_BIT,
	OSINFO_BIT,
	TASKINFO_BIT,
	USAGEINFO_BIT,
	LOADINFO_BIT,
	ARG_SPEC_BIT,
	RECORD_DATE_BIT,
	PATTERN_TYPE_BIT,
	VERSION_BIT,
	UTC_OFFSET_BIT,

	INFO_BIT_MAX,

	/* bit mask */
	EXE_NAME = (1U << EXE_NAME_BIT),
	EXE_BUILD_ID = (1U << EXE_BUILD_ID_BIT),
	EXIT_STATUS = (1U << EXIT_STATUS_BIT),
	CMDLINE = (1U << CMDLINE_BIT),
	CPUINFO = (1U << CPUINFO_BIT),
	MEMINFO = (1U << MEMINFO_BIT),
	OSINFO = (1U << OSINFO_BIT),
	TASKINFO = (1U << TASKINFO_BIT),
	USAGEINFO = (1U << USAGEINFO_BIT),
	LOADINFO = (1U << LOADINFO_BIT),
	ARG_SPEC = (1U << ARG_SPEC_BIT),
	RECORD_DATE = (1U << RECORD_DATE_BIT),
	PATTERN_TYPE = (1U << PATTERN_TYPE_BIT),
	VERSION = (1U << VERSION_BIT),
	UTC_OFFSET = (1U << UTC_OFFSET_BIT),
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
	char *retspec;
	char *autoarg;
	char *autoret;
	char *autoenum;
	bool auto_args_enabled;
	int nr_tid;
	int *tids;
	double stime;
	double utime;
	char *record_date;
	char *elapsed_time;
	char *utc_offset;
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
	enum uftrace_pattern_type patt_type;
	char *uftrace_version;
};

enum {
	UFTRACE_EXIT_SUCCESS = 0,
	UFTRACE_EXIT_FAILURE,
	UFTRACE_EXIT_SIGNALED,
	UFTRACE_EXIT_UNKNOWN,
	UFTRACE_EXIT_FINISHED = 1 << 16,
};

struct kbuffer;
struct pevent;
struct uftrace_record;
struct uftrace_rstack_list;
struct uftrace_session;
struct uftrace_kernel_reader;
struct uftrace_perf_reader;
struct uftrace_extern_reader;
struct uftrace_module;

struct uftrace_session_link {
	struct rb_root root;
	struct rb_root tasks;
	struct uftrace_session *first;
	struct uftrace_task *first_task;
};

struct uftrace_data {
	FILE *fp;
	int sock;
	const char *dirname;
	enum uftrace_cpu_arch arch;
	struct uftrace_file_header hdr;
	struct uftrace_info info;
	struct uftrace_kernel_reader *kernel;
	struct uftrace_perf_reader *perf;
	struct uftrace_extern_reader *extn;
	struct uftrace_task_reader *tasks;
	struct uftrace_session_link sessions;
	int nr_tasks;
	int nr_perf;
	int last_perf_idx;
	int depth;
	bool needs_byte_swap;
	bool needs_bit_swap;
	bool perf_event_processed;
	bool caller_filter;
	uint64_t time_filter;
	unsigned size_filter;
	struct uftrace_time_range time_range;
	struct list_head events;
};

bool data_is_lp64(struct uftrace_data *handle);

#define UFTRACE_MODE_INVALID 0
#define UFTRACE_MODE_RECORD 1
#define UFTRACE_MODE_REPLAY 2
#define UFTRACE_MODE_LIVE 3
#define UFTRACE_MODE_REPORT 4
#define UFTRACE_MODE_INFO 5
#define UFTRACE_MODE_RECV 6
#define UFTRACE_MODE_DUMP 7
#define UFTRACE_MODE_GRAPH 8
#define UFTRACE_MODE_SCRIPT 9
#define UFTRACE_MODE_TUI 10

#define UFTRACE_MODE_DEFAULT UFTRACE_MODE_LIVE

struct uftrace_opts {
	char *lib_path;
	char *filter;
	char *trigger;
	char *sig_trigger;
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
	char *watch;
	char **run_cmd;
	char *opt_file;
	char *script_file;
	char *diff_policy;
	char *caller;
	char *extern_data;
	char *hide;
	char *loc_filter;
	char *with_syms;
	char *clock;
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
	int size_filter;
	int pid;
	unsigned long bufsize;
	unsigned long kernel_bufsize;
	uint64_t threshold;
	uint64_t sample_time;
	bool flat;
	bool libcall;
	bool print_symtab;
	bool force;
	bool show_task;
	bool no_merge;
	bool nop;
	bool time;
	bool backtrace;
	bool use_pager;
	bool avg_total;
	bool avg_self;
	bool report;
	bool column_view;
	bool want_bind_not;
	bool task_newline;
	bool chrome_trace;
	bool comment;
	bool flame_graph;
	bool libmcount_single;
	bool kernel;
	bool kernel_skip_out; /* also affects VDSO filter */
	bool kernel_only;
	bool keep_pid;
	bool list_event;
	bool event_skip_out;
	bool no_event;
	bool no_sched;
	bool no_sched_preempt;
	bool nest_libcall;
	bool record;
	bool auto_args;
	bool show_args;
	bool libname;
	bool no_randomize_addr;
	bool graphviz;
	bool srcline;
	bool estimate_return;
	bool mermaid;
	bool agent;
	struct uftrace_time_range range;
	enum uftrace_pattern_type patt_type;
	enum uftrace_trace_state trace;
};

extern struct strv default_opts;

static inline bool opts_has_filter(struct uftrace_opts *opts)
{
	return opts->filter || opts->trigger || opts->threshold || opts->depth != OPT_DEPTH_DEFAULT;
}

void parse_script_opt(struct uftrace_opts *opts);

int command_record(int argc, char *argv[], struct uftrace_opts *opts);
int command_replay(int argc, char *argv[], struct uftrace_opts *opts);
int command_live(int argc, char *argv[], struct uftrace_opts *opts);
int command_report(int argc, char *argv[], struct uftrace_opts *opts);
int command_info(int argc, char *argv[], struct uftrace_opts *opts);
int command_recv(int argc, char *argv[], struct uftrace_opts *opts);
int command_dump(int argc, char *argv[], struct uftrace_opts *opts);
int command_graph(int argc, char *argv[], struct uftrace_opts *opts);
int command_script(int argc, char *argv[], struct uftrace_opts *opts);
int command_tui(int argc, char *argv[], struct uftrace_opts *opts);

extern volatile bool uftrace_done;

int open_data_file(struct uftrace_opts *opts, struct uftrace_data *handle);
int open_info_file(struct uftrace_opts *opts, struct uftrace_data *handle);
void __close_data_file(struct uftrace_opts *opts, struct uftrace_data *handle, bool unload_modules);
static inline void close_data_file(struct uftrace_opts *opts, struct uftrace_data *handle)
{
	__close_data_file(opts, handle, true);
}

int read_task_file(struct uftrace_session_link *sess, char *dirname, bool needs_symtab,
		   bool sym_rel_addr, bool needs_srcline);
int read_task_txt_file(struct uftrace_session_link *sess, char *dirname, char *symdir,
		       bool needs_symtab, bool sym_rel_addr, bool needs_srcline);

char *get_libmcount_path(struct uftrace_opts *opts);
void put_libmcount_path(char *libpath);

#define SESSION_ID_LEN 16
#define TASK_COMM_LEN 16
#define TASK_COMM_LAST (TASK_COMM_LEN - 1)
#define TASK_ID_LEN 7

struct uftrace_session {
	struct rb_node node;
	char sid[SESSION_ID_LEN];
	uint64_t start_time;
	int pid, tid;
	struct uftrace_sym_info sym_info;
	struct uftrace_triggers_info filter_info;
	struct uftrace_triggers_info fixups;
	struct list_head dlopen_libs;
	int namelen;
	char exename[];
};

struct uftrace_sess_ref {
	struct uftrace_sess_ref *next;
	struct uftrace_session *sess;
	uint64_t start, end;
};

struct uftrace_dlopen_list {
	struct list_head list;
	uint64_t time;
	unsigned long base;
	struct uftrace_module *mod;
	struct uftrace_triggers_info filter_info;
};

struct uftrace_task {
	int pid, tid, ppid;
	char comm[TASK_COMM_LEN];
	struct rb_node node;
	struct uftrace_sess_ref sref;
	struct uftrace_sess_ref *sref_last;
	struct list_head children;
	struct list_head siblings;
	struct {
		uint64_t run;
		uint64_t idle;
		uint64_t stamp;
	} time;
};

#define UFTRACE_MSG_MAGIC 0xface

enum uftrace_msg_type {
	UFTRACE_MSG_REC_START = 1,
	UFTRACE_MSG_REC_END,
	UFTRACE_MSG_TASK_START,
	UFTRACE_MSG_TASK_END,
	UFTRACE_MSG_FORK_START,
	UFTRACE_MSG_FORK_END,
	UFTRACE_MSG_SESSION,
	UFTRACE_MSG_LOST,
	UFTRACE_MSG_DLOPEN,
	UFTRACE_MSG_FINISH,

	UFTRACE_MSG_SEND_START = 100,
	UFTRACE_MSG_SEND_DIR_NAME,
	UFTRACE_MSG_SEND_DATA,
	UFTRACE_MSG_SEND_KERNEL_DATA,
	UFTRACE_MSG_SEND_PERF_DATA,
	UFTRACE_MSG_SEND_INFO,
	UFTRACE_MSG_SEND_META_DATA,
	UFTRACE_MSG_SEND_END,

	UFTRACE_MSG_AGENT_CLOSE = 200, /* close the connection */
	UFTRACE_MSG_AGENT_QUERY, /* perform connection handshake */
	UFTRACE_MSG_AGENT_GET_OPT, /* get current option value */
	UFTRACE_MSG_AGENT_SET_OPT, /* set new option value */
	UFTRACE_MSG_AGENT_OK, /* ack previous message */
	UFTRACE_MSG_AGENT_ERR, /* signal error on previous message */
};

/* msg format for communicating by pipe */
struct uftrace_msg {
	unsigned short magic; /* UFTRACE_MSG_MAGIC */
	unsigned short type; /* UFTRACE_MSG_* */
	unsigned int len;
	unsigned char data[];
};

struct uftrace_msg_task {
	uint64_t time;
	int32_t pid;
	int32_t tid;
};

struct uftrace_msg_sess {
	struct uftrace_msg_task task;
	char sid[16];
	int unused;
	int namelen;
	char exename[];
};

struct uftrace_msg_dlopen {
	struct uftrace_msg_task task;
	uint64_t base_addr;
	char sid[16];
	int unused;
	int namelen;
	char exename[];
};

enum uftrace_agent_opt {
	UFTRACE_AGENT_OPT_TRACE = (1U << 0), /* turn tracing on/off */
	UFTRACE_AGENT_OPT_DEPTH = (1U << 1), /* mcount depth filter */
	UFTRACE_AGENT_OPT_THRESHOLD = (1U << 2), /* mcount time filter */
	UFTRACE_AGENT_OPT_PATTERN = (1U << 3), /* pattern match type */
	UFTRACE_AGENT_OPT_FILTER = (1U << 4), /* tracing filters */
	UFTRACE_AGENT_OPT_CALLER = (1U << 5), /* tracing caller filters */
	UFTRACE_AGENT_OPT_TRIGGER = (1U << 6), /* tracing trigger actions */
};

extern struct uftrace_session *first_session;

void create_session(struct uftrace_session_link *sess, struct uftrace_msg_sess *msg, char *dirname,
		    char *symdir, char *exename, bool sym_rel_addr, bool needs_symtab,
		    bool needs_srcline);
struct uftrace_session *find_task_session(struct uftrace_session_link *sess,
					  struct uftrace_task *task, uint64_t timestamp);
void create_task(struct uftrace_session_link *sess, struct uftrace_msg_task *msg, bool fork);
struct uftrace_task *find_task(struct uftrace_session_link *sess, int tid);
void read_session_map(char *dirname, struct uftrace_sym_info *sinfo, char *sid);
void delete_session_map(struct uftrace_sym_info *sinfo);
void update_session_map(const char *filename);
struct uftrace_session *get_session_from_sid(struct uftrace_session_link *sess, char sid[]);
void session_add_dlopen(struct uftrace_session *sess, uint64_t timestamp, unsigned long base_addr,
			const char *libname, bool needs_srcline);
void session_setup_dlopen_argspec(struct uftrace_session *sess,
				  struct uftrace_filter_setting *setting, bool is_retval);
struct uftrace_dlopen_list *session_find_dlopen(struct uftrace_session *sess, uint64_t timestamp,
						unsigned long addr);
struct uftrace_symbol *session_find_dlsym(struct uftrace_session *sess, uint64_t timestamp,
					  unsigned long addr);
const struct uftrace_filter *session_find_filter(struct uftrace_session *sess,
						 struct uftrace_record *rec);
void delete_sessions(struct uftrace_session_link *sess);

struct uftrace_record;
struct uftrace_symbol *task_find_sym(struct uftrace_session_link *sess,
				     struct uftrace_task_reader *task, struct uftrace_record *rec);
struct uftrace_symbol *task_find_sym_addr(struct uftrace_session_link *sess,
					  struct uftrace_task_reader *task, uint64_t time,
					  uint64_t addr);
struct uftrace_dbg_loc *task_find_loc_addr(struct uftrace_session_link *sess,
					   struct uftrace_task_reader *task, uint64_t time,
					   uint64_t addr);

typedef int (*walk_sessions_cb_t)(struct uftrace_session *session, void *arg);
void walk_sessions(struct uftrace_session_link *sess, walk_sessions_cb_t callback, void *arg);
typedef int (*walk_tasks_cb_t)(struct uftrace_task *task, void *arg);
void walk_tasks(struct uftrace_session_link *sess, walk_tasks_cb_t callback, void *arg);

int setup_client_socket(struct uftrace_opts *opts);
void send_trace_dir_name(int sock, char *name);
void send_trace_data(int sock, int tid, void *data, size_t len);
void send_trace_kernel_data(int sock, int cpu, void *data, size_t len);
void send_trace_perf_data(int sock, int cpu, void *data, size_t len);
void send_trace_metadata(int sock, const char *dirname, char *filename);
void send_trace_info(int sock, struct uftrace_file_header *hdr, void *info, int len);
void send_trace_end(int sock);

void write_task_info(const char *dirname, struct uftrace_msg_task *tmsg);
void write_fork_info(const char *dirname, struct uftrace_msg_task *tmsg);
void write_session_info(const char *dirname, struct uftrace_msg_sess *smsg, const char *exename);
void write_dlopen_info(const char *dirname, struct uftrace_msg_dlopen *dmsg, const char *libname);

enum uftrace_record_type {
	UFTRACE_ENTRY,
	UFTRACE_EXIT,
	UFTRACE_LOST,
	UFTRACE_EVENT,
};

#define RECORD_MAGIC_V3 0xa
#define RECORD_MAGIC_V4 0x5
#define RECORD_MAGIC RECORD_MAGIC_V4

/* reduced version of mcount_ret_stack */
struct uftrace_record {
	uint64_t time;
	uint64_t type : 2;
	uint64_t more : 1;
	uint64_t magic : 3;
	uint64_t depth : 10;
	uint64_t addr : 48; /* child ip or uftrace_event_id */
};

static inline bool is_v3_compat(struct uftrace_record *urec)
{
	/* (RECORD_MAGIC_V4 << 1 | more) == RECORD_MAGIC_V3 */
	return urec->magic == RECORD_MAGIC && urec->more == 0;
}

struct uftrace_fstack_args {
	struct list_head *args;
	unsigned len;
	void *data;
};

struct uftrace_rstack_list {
	struct list_head read;
	struct list_head unused;
	int count;
};

struct uftrace_rstack_list_node {
	struct list_head list;
	struct uftrace_record rstack;
	struct uftrace_fstack_args args;
};

void setup_rstack_list(struct uftrace_rstack_list *list);
void add_to_rstack_list(struct uftrace_rstack_list *list, struct uftrace_record *rstack,
			struct uftrace_fstack_args *args);
struct uftrace_record *get_first_rstack_list(struct uftrace_rstack_list *);
void consume_first_rstack_list(struct uftrace_rstack_list *list);
void delete_last_rstack_list(struct uftrace_rstack_list *list);
void reset_rstack_list(struct uftrace_rstack_list *list);

enum uftrace_ext_type {
	FTRACE_ARGUMENT = 1,
};

static inline bool has_perf_data(struct uftrace_data *handle)
{
	return handle->perf != NULL;
}

static inline bool has_event_data(struct uftrace_data *handle)
{
	return handle->perf_event_processed;
}

struct rusage;

int fill_file_header(struct uftrace_opts *opts, int status, struct rusage *rusage,
		     char *elapsed_time);
void fill_uftrace_info(uint64_t *info_mask, int fd, struct uftrace_opts *opts, int status,
		       struct rusage *rusage, char *elapsed_time);
int read_uftrace_info(uint64_t info_mask, struct uftrace_data *handle);
void process_uftrace_info(struct uftrace_data *handle, struct uftrace_opts *opts,
			  void (*process)(void *data, const char *fmt, ...), void *data);
void clear_uftrace_info(struct uftrace_info *info);

int arch_fill_cpuinfo_model(int fd);

enum uftrace_event_id {
	EVENT_ID_KERNEL = 0U,
	/* kernel IDs are read from tracefs */

	EVENT_ID_BUILTIN = 100000U,
	EVENT_ID_READ_PROC_STATM,
	EVENT_ID_READ_PAGE_FAULT,
	EVENT_ID_DIFF_PROC_STATM,
	EVENT_ID_DIFF_PAGE_FAULT,
	EVENT_ID_READ_PMU_CYCLE,
	EVENT_ID_DIFF_PMU_CYCLE,
	EVENT_ID_READ_PMU_CACHE,
	EVENT_ID_DIFF_PMU_CACHE,
	EVENT_ID_READ_PMU_BRANCH,
	EVENT_ID_DIFF_PMU_BRANCH,
	EVENT_ID_WATCH_CPU,
	EVENT_ID_WATCH_VAR,

	/* supported perf events */
	EVENT_ID_PERF = 200000U,
	EVENT_ID_PERF_SCHED_IN,
	EVENT_ID_PERF_SCHED_OUT,
	EVENT_ID_PERF_SCHED_BOTH,
	EVENT_ID_PERF_TASK,
	EVENT_ID_PERF_EXIT,
	EVENT_ID_PERF_COMM,
	EVENT_ID_PERF_SCHED_OUT_PREEMPT,
	EVENT_ID_PERF_SCHED_BOTH_PREEMPT,

	EVENT_ID_USER = 1000000U,

	EVENT_ID_EXTERN_DATA = 2000000U,
};

struct uftrace_event {
	struct list_head list;
	enum uftrace_event_id id;
	char *provider;
	char *event;
};

struct uftrace_watch_event {
	union {
		int cpu;
		struct {
			uint64_t addr;
			uint64_t data;
		} var;
	};
};

#define HTML_HEADER                                                                                \
	"<html>\n"                                                                                 \
	"<head></head>\n"                                                                          \
	"<body style='background-color:black;color:white;'>\n"                                     \
	"<pre>\n"

#define HTML_FOOTER                                                                                \
	"</pre>\n"                                                                                 \
	"</body>\n"                                                                                \
	"</html>\n"

/* for unit tests */
int prepare_test_data(struct uftrace_opts *opts, struct uftrace_data *handle);
int release_test_data(struct uftrace_opts *opts, struct uftrace_data *handle);

#endif /* UFTRACE_H */
