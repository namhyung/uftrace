#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <gelf.h>
#include <sys/mman.h>
#include <pthread.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "mcount-arch.h"
#include "utils/filter.h"
#include "utils/compiler.h"

#ifdef SINGLE_THREAD
# define TLS
#else
# define TLS  __thread
#endif

extern TLS int mcount_rstack_idx;
extern TLS int mcount_record_idx;
extern TLS struct mcount_ret_stack *mcount_rstack;

extern pthread_key_t shmem_key;
extern TLS int shmem_seqnum;
extern TLS struct mcount_shmem_buffer *shmem_buffer[2];
extern TLS struct mcount_shmem_buffer *shmem_curr;
extern TLS int shmem_losts;
extern int shmem_bufsize;

extern TLS int tid;
extern struct symtabs symtabs;
extern TLS bool mcount_recursion_guard;

extern uint64_t mcount_gettime(void);
extern void prepare_shmem_buffer(void);
extern void ftrace_send_message(int type, void *data, size_t len);
extern bool mcount_should_stop(void);
extern void mcount_prepare(void);
extern enum filter_result mcount_entry_filter_check(unsigned long child,
						    struct ftrace_trigger *tr);
extern void mcount_entry_filter_record(struct mcount_ret_stack *rstack,
				       struct ftrace_trigger *tr,
				       struct mcount_regs *regs);
extern void mcount_exit_filter_record(struct mcount_ret_stack *rstack);
extern int record_trace_data(struct mcount_ret_stack *mrstack,
				     struct list_head *args_spec,
				     struct mcount_regs *regs);

static TLS bool plthook_recursion_guard;
static unsigned long *plthook_got_ptr;
static unsigned long *plthook_dynsym_addr;
static bool *plthook_dynsym_resolved;
unsigned long plthook_resolver_addr;
static TLS unsigned long plthook_saved_addr;

static unsigned long got_addr;
static bool segv_handled;

void segv_handler(int sig, siginfo_t *si, void *ctx)
{
	if (si->si_code == SEGV_ACCERR) {
		mprotect((void *)(got_addr & ~0xFFF), sizeof(long)*3,
			 PROT_WRITE);
		segv_handled = true;
	} else {
		pr_err_ns("mcount: invalid memory access.. exiting.\n");
	}
}

extern void __weak plt_hooker(void);

static int find_got(Elf_Data *dyn_data, size_t nr_dyn)
{
	size_t i;
	struct sigaction sa, old_sa;

	for (i = 0; i < nr_dyn; i++) {
		GElf_Dyn dyn;

		if (gelf_getdyn(dyn_data, i, &dyn) == NULL)
			return -1;

		if (dyn.d_tag != DT_PLTGOT)
			continue;

		got_addr = (unsigned long)dyn.d_un.d_val;
		plthook_got_ptr = (void *)got_addr;
		plthook_resolver_addr = plthook_got_ptr[2];

		/*
		 * The GOT region is write-protected on some systems.
		 * In that case, we need to use mprotect() to overwrite
		 * the address of resolver function.  So install signal
		 * handler to catch such cases.
		 */
		sa.sa_sigaction = segv_handler;
		sa.sa_flags = SA_SIGINFO;
		sigfillset(&sa.sa_mask);
		if (sigaction(SIGSEGV, &sa, &old_sa) < 0) {
			pr_dbg("error during install sig handler\n");
			return -1;
		}

		plthook_got_ptr[2] = (unsigned long)plt_hooker;

		if (sigaction(SIGSEGV, &old_sa, NULL) < 0) {
			pr_dbg("error during recover sig handler\n");
			return -1;
		}

		if (segv_handled) {
			mprotect((void *)(got_addr & ~0xFFF), sizeof(long)*3,
				 PROT_READ);
			segv_handled = false;
		}

		pr_dbg2("found GOT at %p (PLT resolver: %#lx)\n",
			plthook_got_ptr, plthook_resolver_addr);

		break;
	}
	return 0;
}

int hook_pltgot(char *exename)
{
	int fd;
	int ret = -1;
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Scn *sec;
	GElf_Shdr shdr;
	Elf_Data *data;
	size_t shstr_idx;
	size_t i;

	pr_dbg2("opening executable image: %s\n", exename);

	fd = open(exename, O_RDONLY);
	if (fd < 0)
		return -1;

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);

	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto elf_error;

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto elf_error;

	for (i = 0; i < ehdr.e_phnum; i++) {
		GElf_Phdr phdr;

		if (gelf_getphdr(elf, i, &phdr) == NULL)
			goto elf_error;

		if (phdr.p_type != PT_DYNAMIC)
			continue;

		sec = gelf_offscn(elf, phdr.p_offset);

		if (!sec || gelf_getshdr(sec, &shdr) == NULL)
			continue;

		data = elf_getdata(sec, NULL);
		if (data == NULL)
			goto elf_error;

		if (find_got(data, shdr.sh_size / shdr.sh_entsize) < 0)
			goto elf_error;
	}
	ret = 0;

out:
	elf_end(elf);
	close(fd);

	return ret;

elf_error:
	pr_dbg("%s\n", elf_errmsg(elf_errno()));

	goto out;
}

/* functions should skip PLT hooking */
static const char *skip_syms[] = {
	"mcount",
	"__fentry__",
	"__gnu_mcount_nc",
	"__cyg_profile_func_enter",
	"__cyg_profile_func_exit",
	"_mcleanup",
	"mcount_restore",
	"mcount_reset",
	"__libc_start_main",
};

static struct dynsym_idxlist skip_idxlist;

static const char *setjmp_syms[] = {
	"setjmp",
	"_setjmp",
	"sigsetjmp",
	"__sigsetjmp",
};

static struct dynsym_idxlist setjmp_idxlist;

static const char *longjmp_syms[] = {
	"longjmp",
	"siglongjmp",
	"__longjmp_chk",
};

static struct dynsym_idxlist longjmp_idxlist;

static const char *vfork_syms[] = {
	"vfork",
};

static struct dynsym_idxlist vfork_idxlist;

static const char *flush_syms[] = {
	"fork", "vfork", "daemon", "exit",
	"longjmp", "siglongjmp", "__longjmp_chk",
	"execl", "execlp", "execle", "execv", "execve", "execvp", "execvpe",
};

static struct dynsym_idxlist flush_idxlist;

void setup_dynsym_indexes(struct symtabs *symtabs)
{
	build_dynsym_idxlist(symtabs, &skip_idxlist,
			     skip_syms, ARRAY_SIZE(skip_syms));
	build_dynsym_idxlist(symtabs, &setjmp_idxlist,
			     setjmp_syms, ARRAY_SIZE(setjmp_syms));
	build_dynsym_idxlist(symtabs, &longjmp_idxlist,
			     longjmp_syms, ARRAY_SIZE(longjmp_syms));
	build_dynsym_idxlist(symtabs, &vfork_idxlist,
			     vfork_syms, ARRAY_SIZE(vfork_syms));
	build_dynsym_idxlist(symtabs, &flush_idxlist,
			     flush_syms, ARRAY_SIZE(flush_syms));
}

void destroy_dynsym_indexes(void)
{
	destroy_dynsym_idxlist(&skip_idxlist);
	destroy_dynsym_idxlist(&setjmp_idxlist);
	destroy_dynsym_idxlist(&longjmp_idxlist);
	destroy_dynsym_idxlist(&vfork_idxlist);
	destroy_dynsym_idxlist(&flush_idxlist);
}

struct mcount_jmpbuf_rstack {
	int count;
	int record_idx;
	unsigned long parent[MCOUNT_RSTACK_MAX];
	unsigned long child[MCOUNT_RSTACK_MAX];
};

static struct mcount_jmpbuf_rstack setjmp_rstack;

static void setup_jmpbuf_rstack(struct mcount_ret_stack *rstack, int idx)
{
	int i;
	struct mcount_jmpbuf_rstack *jbstack = &setjmp_rstack;

	pr_dbg2("setup jmpbuf rstack: %d\n", idx);

	/* currently, only saves a single jmpbuf */
	jbstack->count = idx;
	jbstack->record_idx = mcount_record_idx;
	for (i = 0; i <= idx; i++) {
		jbstack->parent[i] = rstack[i].parent_ip;
		jbstack->child[i]  = rstack[i].child_ip;
	}

	rstack[idx].flags |= MCOUNT_FL_SETJMP;
}

static void restore_jmpbuf_rstack(struct mcount_ret_stack *rstack, int idx)
{
	int i, dyn_idx;
	struct mcount_jmpbuf_rstack *jbstack = &setjmp_rstack;

	dyn_idx = rstack[idx].dyn_idx;

	pr_dbg2("restore jmpbuf: %d\n", jbstack->count);

	mcount_rstack_idx = jbstack->count + 1;
	mcount_record_idx = jbstack->record_idx;

	for (i = 0; i < jbstack->count + 1; i++) {
		mcount_rstack[i].parent_ip = jbstack->parent[i];
		mcount_rstack[i].child_ip  = jbstack->child[i];
	}

	rstack[idx].flags &= ~MCOUNT_FL_LONGJMP;

	/* to avoid check in plthook_exit() */
	rstack[jbstack->count].dyn_idx = dyn_idx;
}

/* it's crazy to call vfork() concurrently */
static int vfork_parent;
static TLS int vfork_shmem_seqnum;
static TLS struct mcount_shmem_buffer *vfork_shmem_buffer[2];
static TLS struct mcount_shmem_buffer *vfork_shmem_curr;

static void prepare_vfork(void)
{
	/* save original parent pid */
	vfork_parent = getpid();
}

/* this function will be called in child */
static void setup_vfork(void)
{
	struct ftrace_msg_task tmsg = {
		.pid = getppid(),
		.tid = getpid(),
		.time = mcount_gettime(),
	};

	vfork_shmem_seqnum = shmem_seqnum;
	vfork_shmem_buffer[0] = shmem_buffer[0];
	vfork_shmem_buffer[1] = shmem_buffer[1];
	vfork_shmem_curr = shmem_curr;

	/* setup new shmem buffer for child */
	tid = 0;
	shmem_losts = 0;
	shmem_seqnum = 0;
	shmem_curr = NULL;
	prepare_shmem_buffer();

	ftrace_send_message(FTRACE_MSG_TID, &tmsg, sizeof(tmsg));
}

/* this function detects whether child finished */
static void restore_vfork(struct mcount_ret_stack *rstack)
{
	/*
	 * On vfork, parent sleeps until child exec'ed or exited.
	 * So if it sees parent pid, that means child was done.
	 */
	if (getpid() == vfork_parent) {
		struct sym *sym;

		shmem_seqnum = vfork_shmem_seqnum;
		shmem_buffer[0] = vfork_shmem_buffer[0];
		shmem_buffer[1] = vfork_shmem_buffer[1];
		shmem_curr = vfork_shmem_curr;

		tid = 0;
		vfork_parent = 0;

		/* make parent returning from vfork() */
		sym = find_dynsym(&symtabs, vfork_idxlist.idx[0]);
		if (sym)
			rstack->child_ip = sym->addr;
	}
}

extern unsigned long plthook_return(void);

unsigned long plthook_entry(unsigned long *ret_addr, unsigned long child_idx,
			    unsigned long module_id, struct mcount_regs *regs)
{
	struct sym *sym;
	unsigned long child_ip;
	struct mcount_ret_stack *rstack;
	struct ftrace_trigger tr = {
		.flags = 0,
	};
	bool skip = false;

	if (unlikely(mcount_should_stop()))
		return 0;

	mcount_recursion_guard = true;

	if (unlikely(mcount_rstack == NULL))
		mcount_prepare();

	/*
	 * There was a recursion like below:
	 *
	 * plthook_entry -> mcount_entry -> mcount_prepare -> xmalloc
	 *   -> plthook_entry
	 */
	if (plthook_recursion_guard)
		goto out;

	if (check_dynsym_idxlist(&skip_idxlist, child_idx))
		goto out;

	sym = find_dynsym(&symtabs, child_idx);
	pr_dbg3("[%d] enter %lx: %s\n", child_idx, sym->addr, sym->name);

	child_ip = sym ? sym->addr : 0;
	if (child_ip == 0) {
		pr_err_ns("invalid function idx found! (idx: %d, %#lx)\n",
			  (int) child_idx, child_idx);
	}

	if (mcount_entry_filter_check(sym->addr, &tr) == FILTER_OUT) {
		/*
		 * Skip recording but still hook the return address,
		 * otherwise it cannot trace further invocations due to
		 * the overwritten PLT entry by the resolver function.
		 */
		skip = true;
	}

	plthook_recursion_guard = true;

	rstack = &mcount_rstack[mcount_rstack_idx++];

	rstack->depth      = mcount_record_idx;
	rstack->dyn_idx    = child_idx;
	rstack->parent_loc = ret_addr;
	rstack->parent_ip  = *ret_addr;
	rstack->child_ip   = child_ip;
	rstack->start_time = skip ? 0 : mcount_gettime();
	rstack->end_time   = 0;
	rstack->flags      = skip ? MCOUNT_FL_NORECORD : 0;

	mcount_entry_filter_record(rstack, &tr, regs);

	*ret_addr = (unsigned long)plthook_return;

	if (check_dynsym_idxlist(&setjmp_idxlist, child_idx))
		setup_jmpbuf_rstack(mcount_rstack, mcount_rstack_idx-1);
	else if (check_dynsym_idxlist(&longjmp_idxlist, child_idx))
		rstack->flags |= MCOUNT_FL_LONGJMP;
	else if (check_dynsym_idxlist(&vfork_idxlist, child_idx)) {
		rstack->flags |= MCOUNT_FL_VFORK;
		prepare_vfork();
	}

	/* force flush rstack on some special functions */
	if (check_dynsym_idxlist(&flush_idxlist, child_idx))
		record_trace_data(rstack, NULL, regs);

	if (plthook_dynsym_resolved[child_idx]) {
		volatile unsigned long *resolved_addr = plthook_dynsym_addr + child_idx;

		/* ensure resolved address was set */
		while (!*resolved_addr)
			cpu_relax();

		mcount_recursion_guard = false;
		return *resolved_addr;
	}

	plthook_saved_addr = plthook_got_ptr[3 + child_idx];

out:
	mcount_recursion_guard = false;
	return 0;
}

unsigned long plthook_exit(void)
{
	int dyn_idx;
	unsigned long new_addr;
	struct mcount_ret_stack *rstack;

	mcount_recursion_guard = true;

again:
	rstack = &mcount_rstack[--mcount_rstack_idx];

	if (unlikely(rstack->flags & (MCOUNT_FL_LONGJMP | MCOUNT_FL_VFORK))) {
		if (rstack->flags & MCOUNT_FL_LONGJMP) {
			restore_jmpbuf_rstack(mcount_rstack, mcount_rstack_idx+1);
			goto again;
		}

		if (rstack->flags & MCOUNT_FL_VFORK)
			setup_vfork();
	}

	if (unlikely(vfork_parent))
		restore_vfork(rstack);

	dyn_idx = rstack->dyn_idx;
	if (dyn_idx == MCOUNT_INVALID_DYNIDX) {
		pr_err_ns("<%d> invalid dynsym idx: %d\n",
			  mcount_rstack_idx, dyn_idx);
	}

	pr_dbg3("[%d] exit  %lx: %s\n", dyn_idx,
		plthook_dynsym_addr[dyn_idx],
		find_dynsym(&symtabs, dyn_idx)->name);

	if (!(rstack->flags & MCOUNT_FL_NORECORD))
		rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(rstack);

	plthook_recursion_guard = false;

	if (!plthook_dynsym_resolved[dyn_idx]) {
#ifndef SINGLE_THREAD
		static pthread_mutex_t resolver_mutex = PTHREAD_MUTEX_INITIALIZER;

		pthread_mutex_lock(&resolver_mutex);
#endif
		if (!plthook_dynsym_resolved[dyn_idx]) {
			new_addr = plthook_got_ptr[3 + dyn_idx];
			/* restore GOT so plt_hooker keep called */
			plthook_got_ptr[3 + dyn_idx] = plthook_saved_addr;

			plthook_dynsym_addr[dyn_idx] = new_addr;
			plthook_dynsym_resolved[dyn_idx] = true;
		}
#ifndef SINGLE_THREAD
		pthread_mutex_unlock(&resolver_mutex);
#endif
	}

	mcount_recursion_guard = false;
	return rstack->parent_ip;
}

void plthook_setup(struct symtabs *symtabs)
{
	plthook_dynsym_resolved = xcalloc(sizeof(bool),
					  count_dynsym(symtabs));
	plthook_dynsym_addr = xcalloc(sizeof(unsigned long),
				      count_dynsym(symtabs));
}
