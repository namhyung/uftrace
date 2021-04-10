/*
 * internal routines and data structures for handling mcount records
 *
 * Copyright (C) 2014-2018, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef UFTRACE_MCOUNT_INTERNAL_H
#define UFTRACE_MCOUNT_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <link.h>

#ifdef HAVE_LIBCAPSTONE
# include <capstone/capstone.h>
#endif

#include "uftrace.h"
#include "mcount-arch.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/compiler.h"

/* could be defined in mcount-arch.h */
#ifndef  ARCH_SUPPORT_AUTO_RECOVER
# define ARCH_SUPPORT_AUTO_RECOVER  0
#endif

/* plt_hooker has return address to hook */
#ifndef  ARCH_CAN_RESTORE_PLTHOOK
# define ARCH_CAN_RESTORE_PLTHOOK  0
#endif

enum filter_result {
	FILTER_RSTACK = -1,
	FILTER_OUT,
	FILTER_IN,
};

#ifndef DISABLE_MCOUNT_FILTER
struct filter_control {
	int in_count;
	int out_count;
	uint16_t depth;
	uint16_t saved_depth;
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
#define EVTBUF_HDR   (offsetof(struct mcount_event, data))

struct mcount_event {
	uint64_t	time;
	uint32_t	id;
	uint16_t	dsize;
	uint16_t	idx;
	uint8_t		data[EVTBUF_SIZE];
};

#define ASYNC_IDX 0xffff

#define MAX_EVENT  4

enum mcount_watch_item {
	MCOUNT_WATCH_NONE	= 0,
	MCOUNT_WATCH_CPU	= (1 << 0),
};

struct mcount_watchpoint {
	bool		inited;
	/* per-thread watch points */
	int		cpu;

	/* global watch points */
};

#ifndef DISABLE_MCOUNT_FILTER
struct mcount_mem_regions {
	struct rb_root root;
	unsigned long  heap;
	unsigned long  brk;
};
void finish_mem_region(struct mcount_mem_regions *regions);
#else
struct mcount_mem_regions {};
static inline void finish_mem_region(struct mcount_mem_regions *regions) {}
#endif

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
	bool				recursion_marker;
	bool				in_exception;
	bool				dead;
	bool				warned;
	unsigned long			cygprof_dummy;
	struct mcount_ret_stack		*rstack;
	void				*argbuf;
	struct filter_control		filter;
	bool				enable_cached;
	struct mcount_shmem		shmem;
	struct mcount_event		event[MAX_EVENT];
	int				nr_events;
	struct mcount_mem_regions	mem_regions;
	struct mcount_watchpoint	watch;
	struct mcount_arch_context	arch;
	struct list_head		pmu_fds;
};

#ifdef HAVE_MCOUNT_ARCH_CONTEXT
extern void mcount_save_arch_context(struct mcount_arch_context *ctx);
extern void mcount_restore_arch_context(struct mcount_arch_context *ctx);
#else
static inline void mcount_save_arch_context(struct mcount_arch_context *ctx) {}
static inline void mcount_restore_arch_context(struct mcount_arch_context *ctx) {}
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

void __mcount_guard_recursion(struct mcount_thread_data *mtdp);
void __mcount_unguard_recursion(struct mcount_thread_data *mtdp);
bool mcount_guard_recursion(struct mcount_thread_data *mtdp);
void mcount_unguard_recursion(struct mcount_thread_data *mtdp);

extern uint64_t mcount_threshold;  /* nsec */
extern pthread_key_t mtd_key;
extern int shmem_bufsize;
extern int pfd;
extern char *mcount_exename;
extern int page_size_in_kb;
extern bool kernel_pid_update;
extern bool mcount_auto_recover;
extern bool mcount_estimate_return;

enum mcount_global_flag {
	MCOUNT_GFL_SETUP	= (1U << 0),
	MCOUNT_GFL_FINISH	= (1U << 1),
};

extern unsigned long mcount_global_flags;

static inline bool mcount_should_stop(void)
{
	return mcount_global_flags != 0UL;
}

#ifdef DISABLE_MCOUNT_FILTER
static inline void mcount_filter_setup(struct mcount_thread_data *mtdp) {}
static inline void mcount_filter_release(struct mcount_thread_data *mtdp) {}
static inline void mcount_watch_init(void) {}
static inline void mcount_watch_setup(struct mcount_thread_data *mtdp) {}
static inline void mcount_watch_release(struct mcount_thread_data *mtdp) {}
#endif /* DISABLE_MCOUNT_FILTER */

static inline uint64_t mcount_gettime(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

static inline int mcount_gettid(struct mcount_thread_data *mtdp)
{
	if (!mtdp->tid)
		mtdp->tid = syscall(SYS_gettid);

	return mtdp->tid;
}

/*
 * calling memcpy or memset in libmcount might clobber some registers.
 */
static inline void mcount_memset1(void *dst, unsigned char d, int len)
{
	unsigned char *p = dst;

	while (len-- > 0)
		*p++ = d;
}

static inline void mcount_memcpy1(void * restrict dst,
				  const void * restrict src, int len)
{
	unsigned char * restrict p = dst;
	const unsigned char * restrict q = src;

	while (len-- > 0)
		*p++ = *q++;
}

static inline void mcount_memset4(void *dst, unsigned int d, int len)
{
	unsigned int *p = dst;
	int len4 = len / 4;

	while (len4-- > 0)
		*p++ = d;
}

static inline void mcount_memcpy4(void * restrict dst,
				  const void * restrict src, int len)
{
	unsigned int * restrict p = dst;
	const unsigned int * restrict q = src;
	int len4 = len / 4;

	while (len4-- > 0)
		*p++ = *q++;
}

extern void mcount_return(void);
extern void dynamic_return(void);
extern unsigned long plthook_return(void);

extern unsigned long mcount_return_fn;

extern struct mcount_thread_data * mcount_prepare(void);

extern void update_kernel_tid(int tid);
extern const char *mcount_session_name(void);
extern void uftrace_send_message(int type, void *data, size_t len);
extern void build_debug_domain(char *dbg_domain_str);

extern void mcount_rstack_restore(struct mcount_thread_data *mtdp);
extern void mcount_rstack_reset(struct mcount_thread_data *mtdp);
extern void mcount_rstack_reset_exception(struct mcount_thread_data *mtdp,
					  unsigned long frame_addr);
extern void mcount_auto_restore(struct mcount_thread_data *mtdp);
extern void mcount_auto_reset(struct mcount_thread_data *mtdp);
extern bool mcount_rstack_has_plthook(struct mcount_thread_data *mtdp);

extern void prepare_shmem_buffer(struct mcount_thread_data *mtdp);
extern void clear_shmem_buffer(struct mcount_thread_data *mtdp);
extern void shmem_finish(struct mcount_thread_data *mtdp);

enum plthook_special_action {
	PLT_FL_SKIP		= 1U << 0,
	PLT_FL_LONGJMP		= 1U << 1,
	PLT_FL_SETJMP		= 1U << 2,
	PLT_FL_VFORK		= 1U << 3,
	PLT_FL_FLUSH		= 1U << 4,
	PLT_FL_EXCEPT		= 1U << 5,
	PLT_FL_RESOLVE		= 1U << 6,
	PLT_FL_DLSYM		= 1U << 7,
};

struct plthook_special_func {
	unsigned idx;
	unsigned flags;  /* enum plthook_special_action */
};

struct plthook_skip_symbol {
	const char *name;
	void       *addr;
};

struct plthook_data {
	/* links to the 'plthook_modules' list */
	struct list_head		list;
	/* full path of this module */
	const char			*mod_name;
	/* used by dynamic linker (PLT resolver), saved in GOT[1] */
	unsigned long			module_id;
	/* base address where this module is loaded */
	unsigned long			base_addr;
	/* start address of PLT code (PLT0) */
	unsigned long			plt_addr;
	/* symbol table for PLT functions */
	struct symtab			dsymtab;
	/* address of global offset table (GOT) used for PLT */
	unsigned long			*pltgot_ptr;
	/* original address of each function (resolved by dynamic linker) */
	unsigned long			*resolved_addr;
	/* array of function that needs special care (see above) */
	struct plthook_special_func	*special_funcs;
	int				nr_special;
	/* architecture-specific info */
	void				*arch;
};

unsigned long setup_pltgot(struct plthook_data *pd, int got_idx, int sym_idx,
			   void *data);
extern void mcount_setup_plthook(char *exename, bool nest_libcall);

extern void setup_dynsym_indexes(struct plthook_data *pd);
extern void destroy_dynsym_indexes(void);

extern unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx);

extern unsigned long plthook_resolver_addr;
extern const struct plthook_skip_symbol plt_skip_syms[];
extern size_t plt_skip_nr;

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
	} __align(16) val;
	struct mcount_mem_regions *regions;
	struct mcount_arch_context *arch;
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
extern struct uftrace_mmap * new_map(const char *path, uint64_t start, uint64_t end,
				     const char *prot);
extern void record_proc_maps(char *dirname, const char *sess_id,
			     struct symtabs *symtabs);
extern void mcount_rstack_inject_return(struct mcount_thread_data *mtdp,
					unsigned long *frame_pointer,
					unsigned long addr);
extern const char *uftrace_basename(const char *pathname);

#ifndef DISABLE_MCOUNT_FILTER
extern void save_argument(struct mcount_thread_data *mtdp,
			  struct mcount_ret_stack *rstack,
			  struct list_head *args_spec,
			  struct mcount_regs *regs);
void save_retval(struct mcount_thread_data *mtdp,
		 struct mcount_ret_stack *rstack, long *retval);
void save_trigger_read(struct mcount_thread_data *mtdp,
		       struct mcount_ret_stack *rstack,
		       enum trigger_read_type type, bool diff);
#endif  /* DISABLE_MCOUNT_FILTER */

bool check_mem_region(struct mcount_arg_context *ctx,
		      unsigned long addr);

void save_watchpoint(struct mcount_thread_data *mtdp,
		     struct mcount_ret_stack *rstack,
		     unsigned long watchpoints);

struct mcount_dynamic_info {
	struct mcount_dynamic_info *next;
	struct uftrace_mmap *map;
	unsigned long base_addr;
	unsigned long text_addr;
	int text_size;
	unsigned long trampoline;
	struct list_head bad_syms;
	void *arch;
};

struct mcount_disasm_engine {
#ifdef HAVE_LIBCAPSTONE
	csh		engine;
#endif
};

#define INSTRUMENT_SUCCESS                       0
#define INSTRUMENT_FAILED                       -1
#define INSTRUMENT_SKIPPED                      -2

/* 
 * Supposing the size of smallest conditional branch is 2 byte.
 * We can replace, at most, 3 of them by the instrumentation
 * instruction.
 */
#define MAX_COND_BRANCH 3

int mcount_dynamic_update(struct symtabs *symtabs, char *patch_funcs,
			  enum uftrace_pattern_type ptype);
void mcount_dynamic_dlopen(struct symtabs *symtabs, struct dl_phdr_info *info,
			   char *path);
void mcount_dynamic_finish(void);

struct mcount_orig_insn {
	struct rb_node		node;
	unsigned long		addr;
	void			*orig;
	void			*insn;
	int			orig_size;
	int			insn_size;
};

struct cond_branch_info {
	/* where the insn starts in the out-of-line exec buffer*/
	unsigned long insn_index;
	/* the original target address of the branch */
	unsigned long branch_target;
	unsigned long insn_addr;
	unsigned long insn_size;
};

/*
 * mcount_disasm_info - information for dynamic patch
 * @sym : symbol for the function
 * @addr : currently targeted function address.
 * @insns : byte array to store instruction.
 * @orig_size : size of original instructions
 * @copy_size : size of copied instructions (may be modified)
 * @modified : whether instruction is changed
 * @has_jump : whether jump_target should be added
 */
struct mcount_disasm_info {
	struct sym		*sym;
	unsigned long		addr;
	unsigned char   	insns[64];
	int			orig_size;
	int			copy_size;
	bool			modified;
	bool			has_jump;
	bool			has_intel_cet;
	uint8_t			nr_branch;
	struct cond_branch_info branch_info[MAX_COND_BRANCH];
};

void mcount_save_code(struct mcount_disasm_info *info, unsigned call_size,
		      void *jmp_insn, unsigned jmp_size);
void *mcount_find_code(unsigned long addr);
struct mcount_orig_insn * mcount_find_insn(unsigned long addr);
void mcount_freeze_code(void);

/* these should be implemented for each architecture */
int mcount_setup_trampoline(struct mcount_dynamic_info *adi);
void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi);

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size);

void mcount_disasm_init(struct mcount_disasm_engine *disasm);
void mcount_disasm_finish(struct mcount_disasm_engine *disasm);

int mcount_arch_branch_table_size(struct mcount_disasm_info *info);
void mcount_arch_patch_branch(struct mcount_disasm_info *info, struct mcount_orig_insn *orig);

struct dynamic_bad_symbol {
	struct list_head	list;
	struct sym		*sym;
	bool			reverted;
};

struct dynamic_bad_symbol * mcount_find_badsym(struct mcount_dynamic_info *mdi,
					       unsigned long addr);
bool mcount_add_badsym(struct mcount_dynamic_info *mdi, unsigned long callsite,
		       unsigned long target);

struct mcount_event_info {
	char *module;
	char *provider;
	char *event;
	char *arguments;

	unsigned id;
	unsigned long addr;
	struct list_head list;
};

int mcount_setup_events(char *dirname, char *event_str,
			enum uftrace_pattern_type ptype);
struct mcount_event_info * mcount_lookup_event(unsigned long addr);
int mcount_save_event(struct mcount_event_info *mei);
void mcount_finish_events(void);
void mcount_list_events(void);

int mcount_arch_enable_event(struct mcount_event_info *mei);

void mcount_hook_functions(void);

int read_pmu_event(struct mcount_thread_data *mtdp, enum uftrace_event_id id,
		   void *buf);
void release_pmu_event(struct mcount_thread_data *mtdp, enum uftrace_event_id id);
void finish_pmu_event(struct mcount_thread_data *mtdp);

#endif /* UFTRACE_MCOUNT_INTERNAL_H */
