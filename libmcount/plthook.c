#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <gelf.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "mcount-arch.h"
#include "utils/filter.h"
#include "utils/compiler.h"

extern struct symtabs symtabs;

unsigned long plthook_resolver_addr;

static unsigned long *plthook_got_ptr;
static unsigned long *plthook_dynsym_addr;
static bool *plthook_dynsym_resolved;

static unsigned long got_addr;
static bool segv_handled;

int is_aligned(unsigned long sp)
{
	/* check the 16-byte stack alignment */
	return sp % 16;
}

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

static int find_got(Elf_Data *dyn_data, size_t nr_dyn, unsigned long offset)
{
	size_t i;
	struct sigaction sa, old_sa;

	for (i = 0; i < nr_dyn; i++) {
		GElf_Dyn dyn;

		if (gelf_getdyn(dyn_data, i, &dyn) == NULL)
			return -1;

		if (dyn.d_tag != DT_PLTGOT)
			continue;

		got_addr = (unsigned long)dyn.d_un.d_val + offset;
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

int hook_pltgot(char *exename, unsigned long offset)
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
	bool found = false;

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

		if (phdr.p_type == PT_LOAD && !found) {
			offset -= phdr.p_vaddr;
			found = true;
		}

		if (phdr.p_type != PT_DYNAMIC)
			continue;

		sec = gelf_offscn(elf, phdr.p_offset);

		if (!sec || gelf_getshdr(sec, &shdr) == NULL)
			continue;

		data = elf_getdata(sec, NULL);
		if (data == NULL)
			goto elf_error;

		if (find_got(data, shdr.sh_size / shdr.sh_entsize, offset) < 0)
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
	"__libc_start_main",
	"__cxa_throw",
	"__cxa_begin_catch",
	"__cxa_end_catch",
	"_Unwind_Resume",
};

static const char *setjmp_syms[] = {
	"setjmp",
	"_setjmp",
	"sigsetjmp",
	"__sigsetjmp",
};

static const char *longjmp_syms[] = {
	"longjmp",
	"siglongjmp",
	"__longjmp_chk",
};

static const char *vfork_syms[] = {
	"vfork",
};

static const char *flush_syms[] = {
	"fork", "vfork", "daemon", "exit",
	"longjmp", "siglongjmp", "__longjmp_chk",
	"execl", "execlp", "execle", "execv", "execve", "execvp", "execvpe",
};

enum plthook_action {
	PLT_FL_SKIP		= 1U << 0,
	PLT_FL_LONGJMP		= 1U << 1,
	PLT_FL_SETJMP		= 1U << 2,
	PLT_FL_VFORK		= 1U << 3,
	PLT_FL_FLUSH		= 1U << 4,
};

struct plthook_special_func {
	unsigned idx;
	unsigned flags;  /* enum plthook_action */
};

static struct plthook_special_func *special_funcs;
static int nr_special;

void add_special_func(unsigned idx, unsigned flags)
{
	int i;
	struct plthook_special_func *func;

	for (i = 0; i < nr_special; i++) {
		func = &special_funcs[i];

		if (func->idx == idx) {
			func->flags |= flags;
			return;
		}
	}

	special_funcs = xrealloc(special_funcs,
				 (nr_special + 1) * sizeof(*func));

	func = &special_funcs[nr_special++];

	func->idx     = idx;
	func->flags   = flags;
}

static void build_special_funcs(struct symtabs *symtabs, const char *syms[],
				unsigned nr_sym, unsigned flag)
{
	unsigned i;
	struct dynsym_idxlist idxlist;

	build_dynsym_idxlist(symtabs, &idxlist, syms, nr_sym);
	for (i = 0; i < idxlist.count; i++)
		add_special_func(idxlist.idx[i], flag);
	destroy_dynsym_idxlist(&idxlist);
}

static int idxsort(const void *a, const void *b)
{
	const struct plthook_special_func *func_a = a;
	const struct plthook_special_func *func_b = b;

	if (func_a->idx > func_b->idx)
		return 1;
	if (func_a->idx < func_b->idx)
		return -1;
	return 0;
}

static int idxfind(const void *a, const void *b)
{
	unsigned idx = (unsigned long) a;
	const struct plthook_special_func *func = b;

	if (func->idx == idx)
		return 0;

	return (idx > func->idx) ? 1 : -1;
}

void setup_dynsym_indexes(struct symtabs *symtabs)
{
	build_special_funcs(symtabs, skip_syms, ARRAY_SIZE(skip_syms),
			    PLT_FL_SKIP);
	build_special_funcs(symtabs, longjmp_syms, ARRAY_SIZE(longjmp_syms),
			    PLT_FL_LONGJMP);
	build_special_funcs(symtabs, setjmp_syms, ARRAY_SIZE(setjmp_syms),
			    PLT_FL_SETJMP);
	build_special_funcs(symtabs, vfork_syms, ARRAY_SIZE(vfork_syms),
			    PLT_FL_VFORK);
	build_special_funcs(symtabs, flush_syms, ARRAY_SIZE(flush_syms),
			    PLT_FL_FLUSH);

	/* built all table, now sorting */
	qsort(special_funcs, nr_special, sizeof(*special_funcs), idxsort);
}

void destroy_dynsym_indexes(void)
{
	free(special_funcs);
	special_funcs = NULL;

	nr_special = 0;
}

struct mcount_jmpbuf_rstack {
	int count;
	int record_idx;
	unsigned long parent[MCOUNT_RSTACK_MAX];
	unsigned long child[MCOUNT_RSTACK_MAX];
};

static struct mcount_jmpbuf_rstack setjmp_rstack;

static void setup_jmpbuf_rstack(struct mcount_thread_data *mtdp, int idx)
{
	int i;
	struct mcount_jmpbuf_rstack *jbstack = &setjmp_rstack;

	pr_dbg2("setup jmpbuf rstack: %d\n", idx);

	/* currently, only saves a single jmpbuf */
	jbstack->count = idx;
	jbstack->record_idx = mtdp->record_idx;

	for (i = 0; i <= idx; i++) {
		jbstack->parent[i] = mtdp->rstack[i].parent_ip;
		jbstack->child[i]  = mtdp->rstack[i].child_ip;
	}

	mtdp->rstack[idx].flags |= MCOUNT_FL_SETJMP;
}

static void restore_jmpbuf_rstack(struct mcount_thread_data *mtdp, int idx)
{
	int i, dyn_idx;
	struct mcount_jmpbuf_rstack *jbstack = &setjmp_rstack;

	dyn_idx = mtdp->rstack[idx].dyn_idx;

	pr_dbg2("restore jmpbuf: %d\n", jbstack->count);

	mtd.idx = jbstack->count + 1;
	mtd.record_idx = jbstack->record_idx;

	mtdp->idx = jbstack->count + 1;
	mtdp->record_idx = jbstack->record_idx;

	for (i = 0; i < jbstack->count + 1; i++) {
		mtdp->rstack[i].parent_ip = jbstack->parent[i];
		mtdp->rstack[i].child_ip  = jbstack->child[i];
	}

	/* to avoid check in plthook_exit() */
	mtdp->rstack[jbstack->count].dyn_idx = dyn_idx;
}

/* it's crazy to call vfork() concurrently */
static int vfork_parent;
static int vfork_rstack_idx;
static int vfork_record_idx;
static struct mcount_ret_stack vfork_rstack;
static struct mcount_shmem vfork_shmem;

static void prepare_vfork(struct mcount_thread_data *mtdp,
			  struct mcount_ret_stack *rstack)
{
	/* save original parent info */
	vfork_parent = getpid();
	vfork_rstack_idx = mtdp->idx;
	vfork_record_idx = mtdp->record_idx;

	memcpy(&vfork_rstack, rstack, sizeof(*rstack));
	/* it will be force flushed */
	vfork_rstack.flags |= MCOUNT_FL_WRITTEN;
}

/* this function will be called in child */
static void setup_vfork(struct mcount_thread_data *mtdp)
{
	struct ftrace_msg_task tmsg = {
		.pid = getppid(),
		.tid = getpid(),
		.time = mcount_gettime(),
	};

	/* flush tid cache */
	mtdp->tid = 0;

	memcpy(&vfork_shmem, &mtdp->shmem, sizeof(vfork_shmem));

	/* setup new shmem buffer for child */
	memset(&mtdp->shmem, 0, sizeof(mtdp->shmem));
	prepare_shmem_buffer(mtdp);

	ftrace_send_message(FTRACE_MSG_TID, &tmsg, sizeof(tmsg));
}

/* this function detects whether child finished */
static struct mcount_ret_stack * restore_vfork(struct mcount_thread_data *mtdp,
					       struct mcount_ret_stack *rstack)
{
	/*
	 * On vfork, parent sleeps until child exec'ed or exited.
	 * So if it sees parent pid, that means child was done.
	 */
	if (getpid() == vfork_parent) {
		/* flush tid cache */
		mtdp->tid = 0;

		mtdp->idx = vfork_rstack_idx;
		mtdp->record_idx = vfork_record_idx;
		rstack = &mtdp->rstack[mtdp->idx - 1];

		vfork_parent = 0;

		memcpy(&mtdp->shmem, &vfork_shmem, sizeof(vfork_shmem));

		memcpy(rstack, &vfork_rstack, sizeof(*rstack));
	}

	return rstack;
}

extern unsigned long plthook_return(void);

unsigned long plthook_entry(unsigned long *ret_addr, unsigned long child_idx,
			    unsigned long module_id, struct mcount_regs *regs)
{
	struct sym *sym;
	unsigned long child_ip;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	struct ftrace_trigger tr = {
		.flags = 0,
	};
	bool skip = false;
	enum filter_result filtered;
	struct plthook_special_func *func;
	unsigned long special_flag = 0;

	if (unlikely(mcount_should_stop()))
		return 0;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return 0;
	}
	else
		mtdp->recursion_guard = true;

	/* protect mtdp->plthook_addr until plthook_exit() */
	if (mtdp->plthook_guard)
		goto out;

	func = bsearch((void *)child_idx, special_funcs, nr_special,
		       sizeof(*func), idxfind);
	if (func)
		special_flag |= func->flags;

	if (unlikely(special_flag & PLT_FL_SKIP))
		goto out;

	sym = find_dynsym(&symtabs, child_idx);
	pr_dbg3("[%d] enter %lx: %s\n", child_idx, sym->addr, sym->name);

	child_ip = sym ? sym->addr : 0;
	if (child_ip == 0) {
		pr_err_ns("invalid function idx found! (idx: %d, %#lx)\n",
			  (int) child_idx, child_idx);
	}

	filtered = mcount_entry_filter_check(mtdp, sym->addr, &tr);
	if (filtered != FILTER_IN) {
		/*
		 * Skip recording but still hook the return address,
		 * otherwise it cannot trace further invocations due to
		 * the overwritten PLT entry by the resolver function.
		 */
		skip = true;

		/* but if we don't have rstack, just bail out */
		if (filtered == FILTER_RSTACK)
			goto out;
	}

	mtdp->plthook_guard = true;

	rstack = &mtdp->rstack[mtdp->idx++];

	rstack->depth      = mtdp->record_idx;
	rstack->dyn_idx    = child_idx;
	rstack->parent_loc = ret_addr;
	rstack->parent_ip  = *ret_addr;
	rstack->child_ip   = child_ip;
	rstack->start_time = skip ? 0 : mcount_gettime();
	rstack->end_time   = 0;
	rstack->flags      = skip ? MCOUNT_FL_NORECORD : 0;

	mcount_entry_filter_record(mtdp, rstack, &tr, regs);

	*ret_addr = (unsigned long)plthook_return;

	if (unlikely(special_flag)) {
		if (special_flag & PLT_FL_SETJMP) {
			setup_jmpbuf_rstack(mtdp, mtdp->idx - 1);
		}
		else if (special_flag & PLT_FL_LONGJMP) {
			rstack->flags |= MCOUNT_FL_LONGJMP;
		}
		else if (special_flag & PLT_FL_VFORK) {
			rstack->flags |= MCOUNT_FL_VFORK;
			prepare_vfork(mtdp, rstack);
		}

		/* force flush rstack on some special functions */
		if (special_flag & PLT_FL_FLUSH) {
			record_trace_data(mtdp, rstack, NULL);
		}
	}

	if (plthook_dynsym_resolved[child_idx]) {
		volatile unsigned long *resolved_addr;

		resolved_addr = plthook_dynsym_addr + child_idx;

		/* ensure resolved address was set */
		while (!*resolved_addr)
			cpu_relax();

		mtdp->recursion_guard = false;
		return *resolved_addr;
	}

	mtdp->plthook_addr = plthook_got_ptr[3 + child_idx];

out:
	mtdp->recursion_guard = false;
	return 0;
}

unsigned long plthook_exit(long *retval)
{
	int dyn_idx;
	unsigned long new_addr;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;

	mtdp = get_thread_data();
	assert(mtdp);

	mtdp->recursion_guard = true;

again:
	rstack = &mtdp->rstack[mtdp->idx - 1];

	if (unlikely(rstack->flags & (MCOUNT_FL_LONGJMP | MCOUNT_FL_VFORK))) {
		if (rstack->flags & MCOUNT_FL_LONGJMP) {
			restore_jmpbuf_rstack(mtdp, mtdp->idx + 1);
			rstack->flags &= ~MCOUNT_FL_LONGJMP;
			goto again;
		}

		if (rstack->flags & MCOUNT_FL_VFORK)
			setup_vfork(mtdp);
	}

	if (unlikely(vfork_parent))
		rstack = restore_vfork(mtdp, rstack);

	dyn_idx = rstack->dyn_idx;
	if (dyn_idx == MCOUNT_INVALID_DYNIDX)
		pr_err_ns("<%d> invalid dynsym idx: %d\n", mtdp->idx, dyn_idx);

	pr_dbg3("[%d] exit  %lx: %s\n", dyn_idx,
		plthook_dynsym_addr[dyn_idx],
		find_dynsym(&symtabs, dyn_idx)->name);

	if (!(rstack->flags & MCOUNT_FL_NORECORD))
		rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(mtdp, rstack, retval);

	if (!plthook_dynsym_resolved[dyn_idx]) {
#ifndef SINGLE_THREAD
		static pthread_mutex_t resolver_mutex = PTHREAD_MUTEX_INITIALIZER;

		pthread_mutex_lock(&resolver_mutex);
#endif
		if (!plthook_dynsym_resolved[dyn_idx]) {
			new_addr = plthook_got_ptr[3 + dyn_idx];
			/* restore GOT so plt_hooker keep called */
			plthook_got_ptr[3 + dyn_idx] = mtdp->plthook_addr;

			plthook_dynsym_addr[dyn_idx] = new_addr;
			plthook_dynsym_resolved[dyn_idx] = true;
		}
#ifndef SINGLE_THREAD
		pthread_mutex_unlock(&resolver_mutex);
#endif
	}

	compiler_barrier();

	mtdp->idx--;
	mtdp->recursion_guard = false;
	mtdp->plthook_guard = false;

	return rstack->parent_ip;
}

void plthook_setup(struct symtabs *symtabs)
{
	plthook_dynsym_resolved = xcalloc(sizeof(bool),
					  count_dynsym(symtabs));
	plthook_dynsym_addr = xcalloc(sizeof(unsigned long),
				      count_dynsym(symtabs));
}
