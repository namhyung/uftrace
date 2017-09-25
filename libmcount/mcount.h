/*
 * data structures for handling mcount records
 *
 * Copyright (C) 2014-2017, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef FTRACE_MCOUNT_H
#define FTRACE_MCOUNT_H

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>

#include "uftrace.h"
#include "mcount-arch.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"
#include "utils/filter.h"

#define FTRACE_DIR_NAME   "uftrace.data"

#define MCOUNT_RSTACK_MAX      OPT_RSTACK_DEFAULT
#define MCOUNT_DEFAULT_DEPTH   OPT_DEPTH_DEFAULT

#define MCOUNT_NOTRACE_IDX     0x10000
#define MCOUNT_INVALID_DYNIDX  0xffff

enum mcount_rstack_flag {
	MCOUNT_FL_SETJMP	= (1U << 0),
	MCOUNT_FL_LONGJMP	= (1U << 1),
	MCOUNT_FL_NORECORD	= (1U << 2),
	MCOUNT_FL_NOTRACE	= (1U << 3),
	MCOUNT_FL_FILTERED	= (1U << 4),
	MCOUNT_FL_VFORK		= (1U << 5),
	MCOUNT_FL_WRITTEN	= (1U << 6),
	MCOUNT_FL_DISABLED	= (1U << 7),
	MCOUNT_FL_RECOVER	= (1U << 8),
	MCOUNT_FL_RETVAL	= (1U << 9),
	MCOUNT_FL_TRACE		= (1U << 10),
	MCOUNT_FL_ARGUMENT	= (1U << 11),
};

struct mcount_ret_stack {
	unsigned long *parent_loc;
	unsigned long parent_ip;
	unsigned long child_ip;
	enum mcount_rstack_flag flags;
	/* time in nsec (CLOCK_MONOTONIC) */
	uint64_t start_time;
	uint64_t end_time;
	int tid;
	int filter_depth;
	uint64_t filter_time;
	unsigned short depth;
	unsigned short dyn_idx;
	struct plthook_data *pd;
	/* set arg_spec at function entry and use it at exit */
	struct list_head *pargs;
};

void __monstartup(unsigned long low, unsigned long high);
void _mcleanup(void);
void mcount_restore(void);
void mcount_reset(void);

#define SHMEM_BUFFER_SIZE  (128 * 1024)

enum shmem_buffer_flags {
	SHMEM_FL_NEW		= (1U << 0),
	SHMEM_FL_WRITTEN	= (1U << 1),
	SHMEM_FL_RECORDING	= (1U << 2),
};

struct mcount_shmem_buffer {
	unsigned size;
	unsigned flag;
	unsigned unused[2];
	char data[];
};

/* must be in sync with enum debug_domain (bits) */
#define DBG_DOMAIN_STR  "TSDFfsKMPER"

enum filter_result {
	FILTER_RSTACK = -1,
	FILTER_OUT,
	FILTER_IN,
};

#ifndef DISABLE_MCOUNT_FILTER
struct filter_control {
	int in_count;
	int out_count;
	int depth;
	int saved_depth;
	uint64_t time;
	uint64_t saved_time;
};
#else
struct filter_control {};
#endif

struct mcount_shmem {
	unsigned			seqnum;
	int				losts;
	int				curr;
	int				nr_buf;
	int				max_buf;
	bool				done;
	struct mcount_shmem_buffer	**buffer;
};

/* first 4 byte saves the actual size of the argbuf */
#define ARGBUF_SIZE  1024
#define EVTBUF_SIZE  (ARGBUF_SIZE - 16)

struct mcount_event {
	uint64_t	time;
	uint32_t	id;
	uint16_t	dsize;
	uint16_t	pad;
	uint8_t		data[EVTBUF_SIZE];
};

#define MAX_EVENT  4

/*
 * The idx and record_idx are to save current index of the rstack.
 * In general, both will have same value but in case of cygprof
 * functions, it may differ if filters applied.
 *
 * This is because how cygprof handles filters - cygprof_exit() should
 * be called for filtered functions while mcount_exit() is not.  The
 * mcount_record_idx is only increased/decreased when the function is
 * not filtered out so that we can keep proper depth in the output.
 */
struct mcount_thread_data {
	int				tid;
	int				idx;
	int				record_idx;
	bool				recursion_guard;
	unsigned long			cygprof_dummy;
	struct mcount_ret_stack		*rstack;
	void				*argbuf;
	struct filter_control		filter;
	bool				enable_cached;
	struct mcount_shmem		shmem;
	struct mcount_event		event[MAX_EVENT];
	int				nr_events;
	struct mcount_arch_context	arch;
};

#ifdef HAVE_MCOUNT_ARCH_CONTEXT
extern void mcount_save_arch_context(struct mcount_arch_context *ctx);
extern void mcount_restore_arch_context(struct mcount_arch_context *ctx);
#else
static inline void mcount_save_arch_context(struct mcount_arch_context *ctx) {}
static inline  void mcount_restore_arch_context(struct mcount_arch_context *ctx) {}
#endif

#ifdef SINGLE_THREAD
# define TLS
# define get_thread_data()  &mtd
# define check_thread_data(mtdp)  (mtdp->rstack == NULL)
#else
# define TLS  __thread
# define get_thread_data()  pthread_getspecific(mtd_key)
# define check_thread_data(mtdp)  (mtdp == NULL)
#endif

extern TLS struct mcount_thread_data mtd;

extern uint64_t mcount_threshold;  /* nsec */
extern pthread_key_t mtd_key;
extern int shmem_bufsize;
extern unsigned long mcount_global_flags;

extern int page_size_in_kb;

enum mcount_global_flag {
	MCOUNT_GFL_SETUP	= (1U << 0),
	MCOUNT_GFL_FINISH	= (1U << 1),
};

extern unsigned long plthook_resolver_addr;

extern void __monstartup(unsigned long low, unsigned long high);
extern void mcount_return(void);
extern struct mcount_thread_data * mcount_prepare(void);
extern uint64_t mcount_gettime(void);
extern bool mcount_check_rstack(struct mcount_thread_data *mtdp);
extern void uftrace_send_message(int type, void *data, size_t len);
extern const char *session_name(void);
extern int gettid(struct mcount_thread_data *mtdp);

extern void mcount_rstack_restore(void);
extern void mcount_rstack_reset(void);

extern void prepare_shmem_buffer(struct mcount_thread_data *mtdp);
extern void get_new_shmem_buffer(struct mcount_thread_data *mtdp);
extern void finish_shmem_buffer(struct mcount_thread_data *mtdp, int idx);
extern void clear_shmem_buffer(struct mcount_thread_data *mtdp);
extern void shmem_finish(struct mcount_thread_data *mtdp);

enum plthook_special_action {
	PLT_FL_SKIP		= 1U << 0,
	PLT_FL_LONGJMP		= 1U << 1,
	PLT_FL_SETJMP		= 1U << 2,
	PLT_FL_VFORK		= 1U << 3,
	PLT_FL_FLUSH		= 1U << 4,
	PLT_FL_EXCEPT		= 1U << 5,
};

struct plthook_special_func {
	unsigned idx;
	unsigned flags;  /* enum plthook_special_action */
};

struct plthook_data {
	struct list_head		list;
	const char			*mod_name;
	unsigned long			module_id;
	unsigned long			base_addr;
	unsigned long			plt_addr;
	struct symtab			dsymtab;
	unsigned long			*pltgot_ptr;
	unsigned long			*resolved_addr;
	struct plthook_special_func	*special_funcs;
	int				nr_special;
};

unsigned long setup_pltgot(struct plthook_data *pd, int got_idx, int sym_idx,
			   void *data);
extern void mcount_setup_plthook(char *exename, bool nest_libcall);

extern unsigned long plthook_return(void);
extern void setup_dynsym_indexes(struct plthook_data *pd);
extern void destroy_dynsym_indexes(void);

extern unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx);

static inline bool mcount_should_stop(void)
{
	return mcount_global_flags != 0UL;
}

struct uftrace_trigger;
struct uftrace_arg_spec;
struct mcount_regs;

struct mcount_arg_context {
	struct mcount_regs	*regs;
	unsigned long		*stack_base;
	long			*retval;
	union {
		unsigned long	i;
		void		*p;
		double		f;
		struct {
			long	lo;
			long	hi;
		} ll;
		unsigned char	v[16];
	} val;
};

extern void mcount_arch_get_arg(struct mcount_arg_context *ctx,
				struct uftrace_arg_spec *spec);
extern void mcount_arch_get_retval(struct mcount_arg_context *ctx,
				   struct uftrace_arg_spec *spec);

extern enum filter_result mcount_entry_filter_check(struct mcount_thread_data *mtdp,
						    unsigned long child,
						    struct uftrace_trigger *tr);
extern void mcount_entry_filter_record(struct mcount_thread_data *mtdp,
				       struct mcount_ret_stack *rstack,
				       struct uftrace_trigger *tr,
				       struct mcount_regs *regs);
extern void mcount_exit_filter_record(struct mcount_thread_data *mtdp,
				      struct mcount_ret_stack *rstack,
				      long *retval);
extern int record_trace_data(struct mcount_thread_data *mtdp,
			     struct mcount_ret_stack *mrstack, long *retval);
extern void record_proc_maps(char *dirname, const char *sess_id,
			     struct symtabs *symtabs);

#ifndef DISABLE_MCOUNT_FILTER
extern void save_argument(struct mcount_thread_data *mtdp,
			  struct mcount_ret_stack *rstack,
			  struct list_head *args_spec,
			  struct mcount_regs *regs);
void save_retval(struct mcount_thread_data *mtdp,
		 struct mcount_ret_stack *rstack, long *retval);
void save_trigger_read(struct mcount_thread_data *mtdp,
		       struct mcount_ret_stack *rstack,
		       enum trigger_read_type type);
#endif  /* DISABLE_MCOUNT_FILTER */

struct mcount_dynamic_info {
	struct mcount_dynamic_info *next;
	char *mod_name;
	unsigned long addr;
	unsigned long size;
	unsigned long trampoline;
	void *arch;
};

int mcount_dynamic_update(struct symtabs *symtabs, char *patch_funcs);

/* these should be implemented for each architecture */
int mcount_setup_trampoline(struct mcount_dynamic_info *adi);
void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi);
int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym);

void update_kernel_tid(int tid);

struct mcount_event_info {
	char *module;
	char *provider;
	char *event;
	char *arguments;

	unsigned id;
	unsigned long addr;
	struct list_head list;
};

int mcount_setup_events(char *dirname, char *event_str);
struct mcount_event_info * mcount_lookup_event(unsigned long addr);
int mcount_save_event(struct mcount_event_info *mei);
void mcount_finish_events(void);
void mcount_list_events(void);

int mcount_arch_enable_event(struct mcount_event_info *mei);

#endif /* FTRACE_MCOUNT_H */
