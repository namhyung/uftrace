#ifndef __FTRACE_H__
#define __FTRACE_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <libelf.h>

#include "utils/rbtree.h"
#include "utils/symbol.h"


#define FTRACE_MAGIC_LEN  8
#define FTRACE_MAGIC_STR  "Ftrace!"
#define FTRACE_FILE_VERSION  3
#define FTRACE_FILE_VERSION_MIN  2
#define FTRACE_FILE_NAME  "ftrace.data"
#define FTRACE_DIR_NAME   "ftrace.dir"

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
};

struct ftrace_kernel;

struct ftrace_file_handle {
	FILE *fp;
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
#define FTRACE_MODE_DUMP    6

#define FTRACE_MODE_DEFAULT  FTRACE_MODE_LIVE

struct opts {
	char *lib_path;
	char *filter;
	char *notrace;
	char *tid;
	char *exename;
	char *dirname;
	char *logfile;
	int mode;
	int idx;
	int depth;
	int max_stack;
	int kernel;
	unsigned long bsize;
	bool flat;
	bool want_plthook;
	bool print_symtab;
	bool force;
	bool report_thread;
	bool no_merge;
	bool nop;
	bool time;
};

int command_record(int argc, char *argv[], struct opts *opts);

extern volatile bool ftrace_done;

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

struct ftrace_msg_task;
struct ftrace_msg_sess;

extern struct ftrace_session *first_session;

void create_session(struct ftrace_msg_sess *msg, char *exename);
struct ftrace_session *find_session(int pid, uint64_t timestamp);
struct ftrace_session *find_task_session(int pid, uint64_t timestamp);
void create_task(struct ftrace_msg_task *msg, bool fork);
struct ftrace_task *find_task(int tid);

int read_tid_list(int *tids, bool skip_unknown);
void free_tid_list(void);

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
	char *filters;
	char *notrace;
};

int start_kernel_tracing(struct ftrace_kernel *kernel);
int record_kernel_tracing(struct ftrace_kernel *kernel);
int stop_kernel_tracing(struct ftrace_kernel *kernel);
int finish_kernel_tracing(struct ftrace_kernel *kernel);

int setup_kernel_data(struct ftrace_kernel *kernel);
int read_kernel_stack(struct ftrace_kernel *kernel, struct mcount_ret_stack *rstack);
int finish_kernel_data(struct ftrace_kernel *kernel);

void fill_ftrace_info(uint64_t *info_mask, int fd, char *exename, Elf *elf,
		      int status);
int read_ftrace_info(uint64_t info_mask, struct ftrace_file_handle *handle);
void clear_ftrace_info(struct ftrace_info *info);

int arch_fill_cpuinfo_model(int fd);

#endif /* __FTRACE_H__ */
