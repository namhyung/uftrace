#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <link.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <dlfcn.h>
#include <fnmatch.h>
#include <errno.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "plthook"
#define PR_DOMAIN  DBG_PLTHOOK

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "mcount-arch.h"
#include "utils/utils.h"
#include "utils/filter.h"
#include "utils/script.h"
#include "utils/symbol.h"

#ifndef  PT_GNU_RELRO
# define PT_GNU_RELRO  0x6474e552  /* Read-only after relocation */
#endif

/* global symbol tables for libmcount */
extern struct symtabs symtabs;

/* address of dynamic linker's resolver routine (copied from GOT[2]) */
unsigned long plthook_resolver_addr;	/* referenced by arch/.../plthook.S */

/* list of plthook_data for each library (module) */
static LIST_HEAD(plthook_modules);

/* check getenv("LD_BIND_NOT") */
static bool plthook_no_pltbind;

static void overwrite_pltgot(struct plthook_data *pd, int idx, void *data)
{
	/* overwrite it - might be write-protected */
	pd->pltgot_ptr[idx] = (unsigned long)data;
}

unsigned long setup_pltgot(struct plthook_data *pd, int got_idx, int sym_idx,
			   void *data)
{
	unsigned long real_addr = pd->pltgot_ptr[got_idx];

	pd->resolved_addr[sym_idx] = real_addr;

	overwrite_pltgot(pd, got_idx, data);
	return real_addr;
}

static void resolve_pltgot(struct plthook_data *pd, int idx)
{
	if (pd->resolved_addr[idx] == 0) {
		unsigned long addr;
		struct sym *sym;

		sym = &pd->dsymtab.sym[idx];
		addr = (unsigned long) dlsym(RTLD_DEFAULT, sym->name);

		/* On ARM dlsym(DEFAULT) returns the address of PLT */
		if (unlikely(pd->base_addr <= addr &&
			     addr < sym->addr + sym->size)) {
			void *real_addr = dlsym(RTLD_NEXT, sym->name);

			if (real_addr)
				addr = (unsigned long)real_addr;
		}

		pr_dbg2("resolved addr of %s = %#lx\n", sym->name, addr);
		pd->resolved_addr[idx] = addr;
	}
}

/* use weak reference for non-defined (arch-dependent) symbols */
#define ALIAS_DECL(_sym)  extern __weak void (*uftrace_##_sym)(void);

ALIAS_DECL(mcount);
ALIAS_DECL(_mcount);
ALIAS_DECL(__fentry__);
ALIAS_DECL(__gnu_mcount_nc);
ALIAS_DECL(__cyg_profile_func_enter);
ALIAS_DECL(__cyg_profile_func_exit);

#define SKIP_SYM(func)  { #func, &uftrace_ ## func }

const struct plthook_skip_symbol plt_skip_syms[] = {
	SKIP_SYM(mcount),
	SKIP_SYM(_mcount),
	SKIP_SYM(__fentry__),
	SKIP_SYM(__gnu_mcount_nc),
	SKIP_SYM(__cyg_profile_func_enter),
	SKIP_SYM(__cyg_profile_func_exit),
};
size_t plt_skip_nr = ARRAY_SIZE(plt_skip_syms);

#undef SKIP_SYM
#undef ALIAS_DECL

/*
 * The `mcount` (and its friends) are part of uftrace itself,
 * so no need to use PLT hook for them.
 */
static void restore_plt_functions(struct plthook_data *pd)
{
	unsigned i, k;
	struct symtab *dsymtab = &pd->dsymtab;

	for (i = 0; i < dsymtab->nr_sym; i++) {
		/*
		 * GOT[0], GOT[1], and GOT[2] are reserved.
		 * GOT[2] initially points to the runtime resolver, but updated
		 * to plt_hooker for library tracing by uftrace.
		 * The addresses from GOT[3] are supposed to point the resolved
		 * addresses for each library function.
		 */
		int got_idx = 3 + i;
		bool skipped = false;
		unsigned long plthook_addr;
		unsigned long resolved_addr;
		struct sym *sym = dsymtab->sym_names[i];

		for (k = 0; k < plt_skip_nr; k++) {
			const struct plthook_skip_symbol *skip_sym;

			skip_sym = &plt_skip_syms[k];
			if (strcmp(sym->name, skip_sym->name))
				continue;

			overwrite_pltgot(pd, got_idx, skip_sym->addr);
			pr_dbg2("overwrite GOT[%d] to %p (%s)\n",
				got_idx, skip_sym->addr, skip_sym->name);

			skipped = true;
			break;
		}
		if (skipped)
			continue;

		resolved_addr = pd->pltgot_ptr[got_idx];
		plthook_addr = mcount_arch_plthook_addr(pd, i);
		if (resolved_addr != plthook_addr) {
			/* save already resolved address and hook it */
			pd->resolved_addr[i] = resolved_addr;
			overwrite_pltgot(pd, got_idx, (void *)plthook_addr);
			pr_dbg2("restore GOT[%d] from \"%s\"(%#lx) to PLT(base + %#lx)\n",
				got_idx, sym->name, resolved_addr,
				plthook_addr - pd->base_addr);
		}
	}
}

extern void __weak plt_hooker(void);
extern unsigned long plthook_return(void);

__weak struct plthook_data *mcount_arch_hook_no_plt(struct uftrace_elf_data *elf,
						    const char *modname,
						    unsigned long offset)
{
	return NULL;
}

__weak void mcount_arch_plthook_setup(struct plthook_data *pd,
				      struct uftrace_elf_data *elf)
{
	pd->arch = NULL;
}

static int find_got(struct uftrace_elf_data *elf,
		    struct uftrace_elf_iter *iter,
		    const char *modname,
		    unsigned long offset)
{
	bool plt_found = false;
	unsigned long pltgot_addr = 0;
	unsigned long plt_addr = 0;
	struct plthook_data *pd;

	elf_for_each_shdr(elf, iter) {
		if (iter->shdr.sh_type == SHT_DYNAMIC)
			break;
	}

	elf_for_each_dynamic(elf, iter) {
		switch (iter->dyn.d_tag) {
		case DT_PLTGOT:
			pltgot_addr = (unsigned long)iter->dyn.d_un.d_val + offset;
			break;
		case DT_JMPREL:
			plt_found = true;
			break;
		default:
			break;
		}
	}

	if (!plt_found) {
		pd = mcount_arch_hook_no_plt(elf, modname, offset);
		if (pd == NULL)
			pr_dbg2("no PLTGOT found.. ignoring...\n");
		else
			list_add_tail(&pd->list, &plthook_modules);

		return 0;
	}

	elf_for_each_shdr(elf, iter) {
		char *shstr = elf_get_name(elf, iter, iter->shdr.sh_name);

		if (strcmp(shstr, ".plt") == 0) {
			plt_addr = iter->shdr.sh_addr + offset;
			break;
		}
	}

	if (plt_addr == 0) {
		pr_dbg("cannot find PLT address\n");
		return 0;
	}

	pd = xmalloc(sizeof(*pd));
	pd->mod_name   = xstrdup(modname);
	pd->pltgot_ptr = (void *)pltgot_addr;
	pd->module_id  = pd->pltgot_ptr[1];
	pd->base_addr  = offset;
	pd->plt_addr   = plt_addr;

	pr_dbg2("\"%s\" is loaded at %#lx\n",
		basename(pd->mod_name), pd->base_addr);

	memset(&pd->dsymtab, 0, sizeof(pd->dsymtab));
	load_elf_dynsymtab(&pd->dsymtab, elf, pd->base_addr, SYMTAB_FL_DEMANGLE);

	pd->resolved_addr = xcalloc(pd->dsymtab.nr_sym, sizeof(long));
	pd->special_funcs = NULL;
	pd->nr_special    = 0;

	mcount_arch_plthook_setup(pd, elf);
	list_add_tail(&pd->list, &plthook_modules);

	if (plthook_resolver_addr == 0)
		plthook_resolver_addr = pd->pltgot_ptr[2];

	/*
	 * BIND_NOW (+ RELRO) makes module id not used and resets to 0.
	 * but we still need it to find pd from plthook_enter().
	 */
	if (pd->module_id == 0) {
		pr_dbg2("update module id to %p\n", pd);
		overwrite_pltgot(pd, 1, pd);
		pd->module_id = (unsigned long)pd;
	}

	pr_dbg2("found GOT at %p (base_addr + %#lx)\n", pd->pltgot_ptr,
		(unsigned long)pd->pltgot_ptr - pd->base_addr);
	pr_dbg2("module id = %#lx, PLT resolver = %#lx\n",
		pd->module_id, plthook_resolver_addr);

	restore_plt_functions(pd);

	overwrite_pltgot(pd, 2, plt_hooker);

	if (getenv("LD_BIND_NOT"))
		plthook_no_pltbind = true;

	return 0;
}

static int hook_pltgot(const char *modname, unsigned long offset)
{
	int ret = -1;
	bool relro = false;
	unsigned long relro_start = 0;
	unsigned long relro_size = 0;
	unsigned long page_size;
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	bool found_dynamic = false;

	pr_dbg2("opening executable image: %s\n", modname);

	if (elf_init(modname, &elf) < 0)
		return -1;

	elf_for_each_phdr(&elf, &iter) {
		if (iter.phdr.p_type == PT_DYNAMIC)
			found_dynamic = true;

		if (iter.phdr.p_type == PT_GNU_RELRO) {
			relro_start = iter.phdr.p_vaddr + offset;
			relro_size  = iter.phdr.p_memsz;

			page_size = getpagesize();

			relro_start &= ~(page_size - 1);
			relro_size   = ALIGN(relro_size, page_size);
			relro = true;
		}
	}

	if (found_dynamic) {
		if (relro) {
			mprotect((void *)relro_start, relro_size,
				 PROT_READ | PROT_WRITE);
		}

		ret = find_got(&elf, &iter, modname, offset);

		if (relro)
			mprotect((void *)relro_start, relro_size, PROT_READ);
	}

	elf_finish(&elf);
	return ret;
}

/* functions should skip PLT hooking */
static const char *skip_syms[] = {
	"_mcleanup",
	"__libc_start_main",
	"__cxa_throw",
	"__cxa_rethrow",
	"__cxa_begin_catch",
	"__cxa_end_catch",
	"__cxa_finalize",
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

static const char *dlsym_syms[] = {
	"dlsym",
	"dlvsym",
};

static const char *flush_syms[] = {
	"fork", "vfork", "daemon", "exit",
	"longjmp", "siglongjmp", "__longjmp_chk",
	"execl", "execlp", "execle", "execv", "execve", "execvp", "execvpe",
	"fexecve", "posix_spawn", "posix_spawnp",
};

static const char *except_syms[] = {
	"_Unwind_RaiseException",
};

static const char *resolve_syms[] = {
	"execl", "execlp", "execle", "execv", "execve", "execvp", "execvpe",
	"fexecve", "posix_spawn", "posix_spawnp", "pthread_exit",
};

static void add_special_func(struct plthook_data *pd, unsigned idx, unsigned flags)
{
	int i;
	struct plthook_special_func *func;

	for (i = 0; i < pd->nr_special; i++) {
		func = &pd->special_funcs[i];

		if (func->idx == idx) {
			func->flags |= flags;
			return;
		}
	}

	pd->special_funcs = xrealloc(pd->special_funcs,
				     (pd->nr_special + 1) * sizeof(*func));

	func = &pd->special_funcs[pd->nr_special++];

	func->idx     = idx;
	func->flags   = flags;
}

static void build_special_funcs(struct plthook_data *pd, const char *syms[],
				unsigned nr_sym, unsigned flag)
{
	unsigned i;
	struct dynsym_idxlist idxlist;

	build_dynsym_idxlist(&pd->dsymtab, &idxlist, syms, nr_sym);
	for (i = 0; i < idxlist.count; i++)
		add_special_func(pd, idxlist.idx[i], flag);
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

void setup_dynsym_indexes(struct plthook_data *pd)
{
	build_special_funcs(pd, skip_syms, ARRAY_SIZE(skip_syms),
			    PLT_FL_SKIP);
	build_special_funcs(pd, longjmp_syms, ARRAY_SIZE(longjmp_syms),
			    PLT_FL_LONGJMP);
	build_special_funcs(pd, setjmp_syms, ARRAY_SIZE(setjmp_syms),
			    PLT_FL_SETJMP);
	build_special_funcs(pd, vfork_syms, ARRAY_SIZE(vfork_syms),
			    PLT_FL_VFORK);
	build_special_funcs(pd, dlsym_syms, ARRAY_SIZE(dlsym_syms),
			    PLT_FL_DLSYM);
	build_special_funcs(pd, flush_syms, ARRAY_SIZE(flush_syms),
			    PLT_FL_FLUSH);
	build_special_funcs(pd, except_syms, ARRAY_SIZE(except_syms),
			    PLT_FL_EXCEPT);
	build_special_funcs(pd, resolve_syms, ARRAY_SIZE(resolve_syms),
			    PLT_FL_RESOLVE);

	/* built all table, now sorting */
	qsort(pd->special_funcs, pd->nr_special, sizeof(*pd->special_funcs), idxsort);
}

void destroy_dynsym_indexes(void)
{
	struct plthook_data *pd;

	pr_dbg2("destroy plthook special function index\n");

	list_for_each_entry(pd, &plthook_modules, list) {
		free(pd->special_funcs);
		pd->special_funcs = NULL;
		pd->nr_special = 0;
	}
}

static int setup_mod_plthook_data(struct dl_phdr_info *info, size_t sz, void *arg)
{
	const char *exename = info->dlpi_name;
	unsigned long offset = info->dlpi_addr;
	static const char * const skip_libs[] = {
		/* uftrace internal libraries */
		"libmcount.so",
		"libmcount-fast.so",
		"libmcount-single.so",
		"libmcount-fast-single.so",
		/* system base libraries */
		"libc.so.6",
		"libc-2.*.so",
		"libgcc_s.so.1",
		"libpthread.so.0",
		"libpthread-2.*.so",
		"linux-vdso.so.1",
		"linux-gate.so.1",
		"ld-linux-*.so.*",
		"libdl.so.2",
		"libdl-2.*.so",
	};
	size_t k;
	static bool exe_once = true;

	if (exename[0] == '\0') {
		if (!exe_once)
			return 0;

		exename = arg;
		exe_once = false;
	}

	for (k = 0; k < ARRAY_SIZE(skip_libs); k++) {
		if (!fnmatch(skip_libs[k], basename(exename), 0))
			return 0;
	}

	pr_dbg2("setup plthook data for %s (offset: %lx)\n", exename, offset);

	if (hook_pltgot(exename, offset) < 0)
		pr_dbg("error when hooking plt: skipping...\n");

	return 0;
}

static int setup_exe_plthook_data(struct dl_phdr_info *info, size_t sz, void *arg)
{
	const char *exename = arg;
	unsigned long offset = info->dlpi_addr;

	pr_dbg2("setup plthook data for %s (offset: %lx)\n", exename, offset);

	hook_pltgot(exename, offset);
	return 1;
}

void mcount_setup_plthook(char *exename, bool nest_libcall)
{
	struct plthook_data *pd;

	pr_dbg("setup %sPLT hooking \"%s\"\n", nest_libcall ? "nested " : "",
		exename);

	if (!nest_libcall)
		dl_iterate_phdr(setup_exe_plthook_data, exename);
	else
		dl_iterate_phdr(setup_mod_plthook_data, exename);

	list_for_each_entry(pd, &plthook_modules, list)
		setup_dynsym_indexes(pd);
}

struct mcount_jmpbuf_rstack {
	struct list_head list;
	unsigned long addr;
	int count;
	int record_idx;
	struct mcount_ret_stack rstack[MCOUNT_RSTACK_MAX];
};

static LIST_HEAD(jmpbuf_list);

static void setup_jmpbuf_rstack(struct mcount_thread_data *mtdp,
				unsigned long addr)
{
	int i;
	struct mcount_jmpbuf_rstack *jbstack;

	list_for_each_entry(jbstack, &jmpbuf_list, list) {
		if (jbstack->addr == addr)
			break;
	}
	if (list_no_entry(jbstack, &jmpbuf_list, list)) {
		jbstack = xmalloc(sizeof(*jbstack));
		jbstack->addr = addr;

		list_add(&jbstack->list, &jmpbuf_list);
	}

	pr_dbg2("setup jmpbuf rstack at %lx (%d entries)\n", addr, mtdp->idx);

	/* currently, only saves a single jmpbuf */
	jbstack->count      = mtdp->idx;
	jbstack->record_idx = mtdp->record_idx;

	for (i = 0; i < jbstack->count; i++)
		jbstack->rstack[i] = mtdp->rstack[i];
}

static void restore_jmpbuf_rstack(struct mcount_thread_data *mtdp,
				  unsigned long addr)
{
	int i;
	struct mcount_jmpbuf_rstack *jbstack;

	list_for_each_entry(jbstack, &jmpbuf_list, list) {
		if (jbstack->addr == addr)
			break;
	}
	assert(!list_no_entry(jbstack, &jmpbuf_list, list));

	pr_dbg2("restore jmpbuf rstack at %lx (%d entries)\n", addr, jbstack->count);

	mtdp->idx        = jbstack->count;
	mtdp->record_idx = jbstack->record_idx;

	for (i = 0; i < jbstack->count; i++) {
		mtdp->rstack[i] = jbstack->rstack[i];

		/* setjmp() already wrote rstacks */
		mtdp->rstack[i].flags |= MCOUNT_FL_WRITTEN;
	}
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

	mcount_memcpy4(&vfork_rstack, rstack, sizeof(*rstack));
	/* it will be force flushed */
	vfork_rstack.flags |= MCOUNT_FL_WRITTEN;
}

/* this function will be called in child */
static void setup_vfork(struct mcount_thread_data *mtdp)
{
	struct uftrace_msg_task tmsg = {
		.pid = getppid(),
		.tid = getpid(),
		.time = mcount_gettime(),
	};

	/* update tid cache */
	mtdp->tid = tmsg.tid;

	mcount_memcpy4(&vfork_shmem, &mtdp->shmem, sizeof(vfork_shmem));

	/* setup new shmem buffer for child */
	mcount_memset4(&mtdp->shmem, 0, sizeof(mtdp->shmem));
	prepare_shmem_buffer(mtdp);

	uftrace_send_message(UFTRACE_MSG_FORK_START, &tmsg, sizeof(tmsg));
	uftrace_send_message(UFTRACE_MSG_FORK_END, &tmsg, sizeof(tmsg));

	update_kernel_tid(tmsg.tid);
}

/* this function detects whether child is finished */
static struct mcount_ret_stack * restore_vfork(struct mcount_thread_data *mtdp,
					       struct mcount_ret_stack *rstack)
{
	/*
	 * On vfork, parent sleeps until child is exec'ed or exited.
	 * So if it sees parent pid, that means child was done.
	 */
	if (getpid() == vfork_parent) {
		/* flush tid cache */
		mtdp->tid = 0;

		mtdp->idx = vfork_rstack_idx;
		mtdp->record_idx = vfork_record_idx;
		rstack = &mtdp->rstack[mtdp->idx - 1];

		vfork_parent = 0;

		mcount_memcpy4(&mtdp->shmem, &vfork_shmem, sizeof(vfork_shmem));

		mcount_memcpy4(rstack, &vfork_rstack, sizeof(*rstack));
	}

	return rstack;
}

/*
 * mcount_arch_plthook_addr() returns the address of GOT entry.
 * The initial value for each GOT entry redirects the execution to
 * the runtime resolver. (_dl_runtime_resolve in ld-linux.so)
 *
 * The GOT entry is updated by the runtime resolver to the resolved address of
 * the target library function for later reference.
 *
 * However, uftrace gets this address to update it back to the initial value.
 * Even if the GOT entry is resolved by runtime resolver, uftrace restores the
 * address back to the initial value to watch library function calls.
 *
 * Before doing this work, GOT[2] is updated from the address of runtime
 * resolver(_dl_runtime_resolve) to uftrace hooking routine(plt_hooker).
 *
 * This address depends on the PLT structure of each architecture so this
 * function is implemented differently for each architecture.
 */
__weak unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx)
{
	struct sym *sym;

	sym = &pd->dsymtab.sym[idx];
	return sym->addr + ARCH_PLTHOOK_ADDR_OFFSET;
}

static void update_pltgot(struct mcount_thread_data *mtdp,
			  struct plthook_data *pd, int dyn_idx)
{
	if (unlikely(plthook_no_pltbind))
		return;

	if (!pd->resolved_addr[dyn_idx]) {
		unsigned long plthook_addr;
#ifndef SINGLE_THREAD
		static pthread_mutex_t resolver_mutex = PTHREAD_MUTEX_INITIALIZER;

		pthread_mutex_lock(&resolver_mutex);
#endif
		if (!pd->resolved_addr[dyn_idx]) {
			int got_idx = 3 + dyn_idx;
			plthook_addr = mcount_arch_plthook_addr(pd, dyn_idx);
			setup_pltgot(pd, got_idx, dyn_idx, (void*)plthook_addr);
		}

#ifndef SINGLE_THREAD
		pthread_mutex_unlock(&resolver_mutex);
#endif
	}
}

__weak unsigned long mcount_arch_child_idx(unsigned long child_idx)
{
	return child_idx;
}

static unsigned long __plthook_entry(unsigned long *ret_addr,
				     unsigned long child_idx,
				     unsigned long module_id,
				     struct mcount_regs *regs)
{
	struct sym *sym;
	struct mcount_thread_data *mtdp = NULL;
	struct mcount_ret_stack *rstack;
	bool skip = false;
	bool recursion = true;
	enum filter_result filtered;
	struct plthook_data *pd;
	struct plthook_special_func *func;
	unsigned long special_flag = 0;
	unsigned long real_addr = 0;
	struct uftrace_trigger tr;

	mcount_memset4(&tr, 0, sizeof(tr));

	// if necessary, implement it by architecture.
	child_idx = mcount_arch_child_idx(child_idx);
	list_for_each_entry(pd, &plthook_modules, list) {
		if (module_id == pd->module_id)
			break;
	}

	if (list_no_entry(pd, &plthook_modules, list)) {
		pr_dbg("cannot find pd for module id: %lx\n", module_id);
		pd = NULL;
		goto out;
	}

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			goto out;
	}
	else {
		if (!mcount_guard_recursion(mtdp))
			goto out;
	}

	recursion = false;

	func = bsearch((void *)child_idx, pd->special_funcs, pd->nr_special,
		       sizeof(*func), idxfind);
	if (func)
		special_flag |= func->flags;

	if (unlikely(special_flag & PLT_FL_SKIP))
		goto out;

	if (likely(child_idx < pd->dsymtab.nr_sym)) {
		sym = &pd->dsymtab.sym[child_idx];
		pr_dbg3("[idx: %4d] enter %"PRIx64": %s@plt (mod: %lx)\n",
			(int)child_idx, sym->addr, sym->name, module_id);
	}
	else {
		sym = NULL;
		pr_err_ns("invalid function idx found! (idx: %lu/%zu, module: %s)\n",
			  child_idx, pd->dsymtab.nr_sym, pd->mod_name);
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

	rstack = &mtdp->rstack[mtdp->idx++];

	rstack->depth      = mtdp->record_idx;
	rstack->pd         = pd;
	rstack->dyn_idx    = child_idx;
	rstack->parent_loc = ret_addr;
	rstack->parent_ip  = *ret_addr;
	rstack->child_ip   = sym->addr;
	rstack->start_time = skip ? 0 : mcount_gettime();
	rstack->end_time   = 0;
	rstack->flags      = skip ? MCOUNT_FL_NORECORD : 0;
	rstack->nr_events  = 0;
	rstack->event_idx  = ARGBUF_SIZE;

	/* hijack the return address of child */
	*ret_addr = (unsigned long)plthook_return;

	/* restore return address of parent */
	if (mcount_auto_recover)
		mcount_auto_restore(mtdp);

	mcount_entry_filter_record(mtdp, rstack, &tr, regs);

	if (unlikely(special_flag)) {
		/* force flush rstack on some special functions */
		if (special_flag & PLT_FL_FLUSH) {
			record_trace_data(mtdp, rstack, NULL);
		}

		if (special_flag & PLT_FL_SETJMP) {
			setup_jmpbuf_rstack(mtdp, ARG1(regs));
		}
		else if (special_flag & PLT_FL_LONGJMP) {
			rstack->flags |= MCOUNT_FL_LONGJMP;
			/* abuse end-time for the jmpbuf addr */
			rstack->end_time = ARG1(regs);
		}
		else if (special_flag & PLT_FL_VFORK) {
			rstack->flags |= MCOUNT_FL_VFORK;
			prepare_vfork(mtdp, rstack);
		}
		else if (special_flag & PLT_FL_DLSYM) {
			/*
			 * Using RTLD_NEXT in a shared library caused
			 * an infinite loop since libdl thinks it's
			 * called from libmcount due to the return address.
			 */
			if (ARG1(regs) == (unsigned long)RTLD_NEXT &&
			    strcmp(pd->mod_name, mcount_exename)) {
				*ret_addr = rstack->parent_ip;
				if (mcount_auto_recover)
					mcount_auto_reset(mtdp);

				/*
				 * as its return address was recovered,
				 * we need to manually resolve the function
				 * not to overwrite PLT entry by the linker.
				 */
				special_flag |= PLT_FL_RESOLVE;

				if (!(rstack->flags & MCOUNT_FL_NORECORD))
					rstack->end_time = mcount_gettime();

				mcount_exit_filter_record(mtdp, rstack, NULL);

				mtdp->idx--;
			}
		}
		else if (special_flag & PLT_FL_EXCEPT) {
			/* exception handling requires stack unwind */
			mcount_rstack_restore(mtdp);
		}

		if (special_flag & PLT_FL_RESOLVE) {
			/* some functions don't have a chance to resolve */
			resolve_pltgot(pd, child_idx);
		}
	}

out:
	if (likely(pd && child_idx < pd->dsymtab.nr_sym) &&
	    pd->resolved_addr[child_idx] != 0)
		real_addr = pd->resolved_addr[child_idx];

	if (!recursion)
		mcount_unguard_recursion(mtdp);

	return real_addr;
}

unsigned long plthook_entry(unsigned long *ret_addr, unsigned long child_idx,
			    unsigned long module_id, struct mcount_regs *regs)
{
	int saved_errno = errno;
	unsigned long ret;

	ret = __plthook_entry(ret_addr, child_idx, module_id, regs);
	errno = saved_errno;
	return ret;
}


void mtd_dtor(void *arg);

static unsigned long __plthook_exit(long *retval)
{
	unsigned dyn_idx;
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	unsigned long *ret_loc;
	unsigned long ret_addr = 0;

	mtdp = get_thread_data();
	assert(!check_thread_data(mtdp));

	/*
	 * it's only called when mcount_entry() was succeeded and
	 * no need to check recursion here.  But still needs to
	 * prevent recursion during this call.
	 */
	__mcount_guard_recursion(mtdp);

again:
	if (likely(mtdp->idx > 0))
		rstack = &mtdp->rstack[mtdp->idx - 1];
	else
		rstack = restore_vfork(mtdp, NULL);  /* FIXME! */

	if (unlikely(rstack->flags & (MCOUNT_FL_LONGJMP | MCOUNT_FL_VFORK))) {
		if (rstack->flags & MCOUNT_FL_LONGJMP) {
			update_pltgot(mtdp, rstack->pd, rstack->dyn_idx);
			rstack->flags &= ~MCOUNT_FL_LONGJMP;
			restore_jmpbuf_rstack(mtdp, rstack->end_time);
			goto again;
		}

		if (rstack->flags & MCOUNT_FL_VFORK)
			setup_vfork(mtdp);
	}

	if (unlikely(vfork_parent))
		rstack = restore_vfork(mtdp, rstack);

	dyn_idx = rstack->dyn_idx;
	if (unlikely(dyn_idx == MCOUNT_INVALID_DYNIDX ||
		     dyn_idx >= rstack->pd->dsymtab.nr_sym))
		pr_err_ns("<%d> invalid dynsym idx: %d\n", mtdp->idx, dyn_idx);

	if (!ARCH_CAN_RESTORE_PLTHOOK && unlikely(mtdp->dead)) {
		ret_addr = rstack->parent_ip;

		/* make sure it doesn't have plthook below */
		mtdp->idx--;

		if (!mcount_rstack_has_plthook(mtdp)) {
			free(mtdp->rstack);
			mtdp->rstack = NULL;
			mtdp->idx = 0;
		}
		return ret_addr;
	}

	if (!(rstack->flags & MCOUNT_FL_NORECORD))
		rstack->end_time = mcount_gettime();

	mcount_exit_filter_record(mtdp, rstack, retval);

	/*
	 * Since dynamic linker calls fixup routine to patch this GOT entry
	 * to the resolved address, it needs to restore GOT entry back to the
	 * initial value so that it can go to plt_hooker again.
	 * Otherwise, it will directly jump to the resolved address and there's
	 * no way to trace it in the next reference.
	 */
	update_pltgot(mtdp, rstack->pd, dyn_idx);

	ret_loc  = rstack->parent_loc;
	ret_addr = rstack->parent_ip;

	pr_dbg3("[idx: %4d] exit  %lx: %s     (resolved addr: %lx)\n",
		dyn_idx, ret_addr, rstack->pd->dsymtab.sym[dyn_idx].name,
		rstack->pd->resolved_addr[dyn_idx]);

	/* re-hijack return address of parent */
	if (mcount_auto_recover)
		mcount_auto_reset(mtdp);

	__mcount_unguard_recursion(mtdp);

	if (unlikely(mcount_should_stop())) {
		mtd_dtor(mtdp);
		/*
		 * mtd_dtor() will free rstack but current ret_addr
		 * might be plthook_return() when it was a tail call.
		 * Reload the return address after mtd_dtor() restored
		 * all the parent locations.
		 */
		if (ARCH_CAN_RESTORE_PLTHOOK)
			ret_addr = *ret_loc;
	}

	compiler_barrier();

	mtdp->idx--;
	return ret_addr;
}

unsigned long plthook_exit(long *retval)
{
	int saved_errno = errno;
	unsigned long ret = __plthook_exit(retval);

	errno = saved_errno;
	return ret;
}
