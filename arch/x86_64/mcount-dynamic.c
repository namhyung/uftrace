#include <errno.h>
#include <semaphore.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if HAVE_MEMBARRIER
#include <linux/membarrier.h>
#else
#include <cpuid.h>
#endif

/* This should be defined before #include "utils.h" */
#define PR_FMT "dynamic"
#define PR_DOMAIN DBG_DYNAMIC

#include "libmcount/dynamic.h"
#include "libmcount/internal.h"
#include "mcount-arch.h"
#include "utils/hashmap.h"
#include "utils/symbol.h"
#include "utils/utils.h"

static const unsigned char fentry_nop_patt1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
static const unsigned char fentry_nop_patt2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
static const unsigned char patchable_gcc_nop[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
static const unsigned char patchable_clang_nop[] = { 0x0f, 0x1f, 0x44, 0x00, 0x08 };

static const unsigned char endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };

/*
 * Hashmap of trampoline locations for every installed int3 trap. The traps are
 * used when patching and unpatching functions: they prevent threads from
 * entering the critical zone. When a trap is reached, the trap handler fetches
 * the trampoline location from the hmap, and emulates a call to the trampoline,
 * to mimic regular instrumentation.
 *
 * (void *int3_location -> void *trampoline)
 */
static struct Hashmap *int3_hmap;

/* Hashmap of the addresses of instructions that are in patching zones and need
 * to be executed out of line. The addresses are mapped to their out of line
 * equivalent.
 *
 * (void *critical_insn -> void *out_of_line_insn)
 */
static struct Hashmap *patch_region_hmap;

/* Realtime signal number to instruct running threads to move out of patching
   regions */
static int sig_clear_patch_region;

/* counter for the threads that are guaranteed to be out of registered patching
   regions when a signal is issued */
static sem_t sem_clear_patch_region;

/**
 * register_trap - save trampoline associated to a trap
 * @trap     - trap address
 * @call_loc - address of the symbol to emulate a call to
 * @return   - -1 on error, 0 on success
 */
static int register_trap(void *trap, void *call_loc)
{
	if (!hashmap_put(int3_hmap, trap, call_loc))
		return -1;

	return 0;
}

/**
 * unregister_trap - remove trap entry from hmap
 * @trap     - trap address
 * @return   - -1 on error, 0 on success
 */
static int unregister_trap(void *trap)
{
	if (hashmap_remove(int3_hmap, trap))
		return 0;

	return -1;
}

/**
 * emulate_trampoline_call - SIGTRAP handler, emulates a call to the trampoline
 * associated with the trap location
 *
 * When the trap handler is executed, it changes the program counter to point to
 * <trampoline>. When the trap handler exits, the code at <trampoline> will
 * execute (which is __dentry__ defined in dynamic.S).
 *
 * As __dentry__ is expected to be called like a function, it depends on the
 * address of the caller to know which tracepoint was executed. The address is
 * expected to be found on the stack. Therefore, the trap handler actually needs
 * to emulate a call instruction entirely (moving the instruction pointer is not
 * enough).
 *
 * To do so, the trap handler will also push on the stack the next instruction
 * pointer that would be used if the executed instruction was a call instead of
 * a trap.
 *
 * @sig      - signal caught
 * @info     - (unused)
 * @ucontext - user context, containing registers
 */
static void emulate_trampoline_call(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *uctx = ucontext;
	mcontext_t *mctx = &uctx->uc_mcontext;
	void *int3_addr;
	unsigned long trampoline;
	unsigned long child_addr; /* probe location for mcount_entry */

	ASSERT(sig == SIGTRAP);

	__atomic_signal_fence(__ATOMIC_SEQ_CST);
	int3_addr = (void *)mctx->gregs[REG_RIP] - 1; /* int3 size = 1 */
	trampoline = (unsigned long)hashmap_get(int3_hmap, int3_addr);

	child_addr = (unsigned long)int3_addr + CALL_INSN_SIZE;

	mctx->gregs[REG_RSP] -= 8;
	memcpy((void *)mctx->gregs[REG_RSP], &child_addr, 8);
	mctx->gregs[REG_RIP] = trampoline;
}

/**
 * configure_sigtrap_handler - emulate call to trampoline on SIGTRAP
 * @return - -1 on failure, 0 on success
 */
static int configure_sigtrap_handler(void)
{
	struct sigaction act;

	act.sa_sigaction = emulate_trampoline_call;
	act.sa_flags = SA_SIGINFO;

	if (sigaction(SIGTRAP, &act, NULL) < 0) {
		pr_err("failed to configure SIGTRAP handler\n");
		return -1;
	}

	pr_dbg2("configured SIGTRAP handler\n");
	return 0;
}

#if HAVE_MEMBARRIER

/**
 * setup_synchronization_mechanism - register intent to use the 'private
 * expedited sync core' membarrier to synchronize instruction pipelines and
 * caches across cores, for safe cross-modification.
 * @return - negative on error, 0 on success
 */
static int setup_synchronization_mechanism(void)
{
	int ret =
		syscall(__NR_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
	if (ret < 0)
		pr_dbg2("failed to register membarrier intent: %s\n", strerror(errno));
	return ret;
}

/**
 * synchronize_all_cores - use membarrier to perform cache and pipeline
 * synchronization across cores executing cross-modified code
 * @return - negative on error, 0 on success
 */
static int synchronize_all_cores(void)
{
	int ret = syscall(__NR_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
	if (ret < 0)
		pr_dbg2("failed to use membarrier: %s\n", strerror(errno));
	return ret;
}

#else /* HAVE_MEMBARRIER */

/* signal used to perform cache and pipeline synchronization across cores */
static int sig_sync_cores;

/* counter for the threads that have performed serialization when a signal is
   issued */
static sem_t sem_sync_cores;

/**
 * serialize_instruction_execution - execute core serialize instruction
 *
 * According to Intel manual, CPUID is a serializing instruction.
 */
static void serialize_instruction_execution(int signum, siginfo_t *info, void *arg)
{
	int _;
	__cpuid(_, _, _, _, _);
	sem_post(&sem_sync_cores);
}

/**
 * setup_synchronization_mechanism - setup real-time signal and its handler to
 * perform core synchronization across all threads
 * @return - 0 on success, -1 on failure
 */
static int setup_synchronization_mechanism(void)
{
	struct sigaction act;

	if (sig_sync_cores > 0)
		return 0;

	sig_sync_cores = find_unused_sigrt();
	if (sig_sync_cores == -1)
		return -1;

	sem_init(&sem_sync_cores, 0, 0);

	act.sa_sigaction = serialize_instruction_execution;
	act.sa_flags = 0;

	if (sigaction(sig_sync_cores, &act, NULL) < 0) {
		pr_dbg("failed to configure core synchronization signal handler\n");
		return -1;
	}

	pr_dbg("configured core synchronization signal (SIGRT%d) handler\n", sig_sync_cores);
	return 0;
}

/**
 * serialize_instruction_cache - send RT signals to perform cache and pipeline
 * synchronization across cores executing cross-modified code.
 * @return - -1 on error, 0 on success
 */
static int synchronize_all_cores(void)
{
	int signal_count;
	int sync_count = 0;
	struct timespec ts;

	ASSERT(sig_sync_cores >= SIGRTMIN);

	signal_count = thread_broadcast_signal(sig_sync_cores);

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		return -1;
	ts.tv_sec += 1;

	for (int i = 0; i < signal_count; i++) {
		if (sem_timedwait(&sem_sync_cores, &ts) == -1) {
			if (errno == EINTR)
				i--;
			else
				pr_dbg3("error syncing with signal handler: %s\n", strerror(errno));
		}
		else
			sync_count++;
	}
	pr_dbg3("synced core in %d/%d thread(s)\n", sync_count, signal_count);

	return 0;
}

#endif /* HAVE_MEMBARRIER */

/**
 * register_patch_region - mark a memory region as critical by registering the
 * addresses that it contains in 'patch_region_hmap'
 * @start  - address of the patch region
 * @len    - length of the patch region
 * @return - -1 on error, 0 on success
 */
static int register_patch_region(void *start, int len)
{
	void *out_of_line_buffer = mcount_find_code((unsigned long)start + CALL_INSN_SIZE);
	if (!out_of_line_buffer)
		return -1;

	for (int i = 0; i < len; i++) {
		if (!hashmap_put(patch_region_hmap, start + i, out_of_line_buffer + i))
			return -1;
	}

	return 0;
}

/**
 * unregister_patch_region - unmark a memory region as critical
 * @start  - address of the patch region
 * @len    - length of the patch region
 * @return - -1 on error, 0 on success
 */
static int unregister_patch_region(void *start, int len)
{
	void *out_of_line_buffer = mcount_find_code((unsigned long)start);
	if (!out_of_line_buffer)
		return -1;

	for (int i = 0; i < len; i++) {
		if (!hashmap_remove(patch_region_hmap, start + i))
			return -1;
	}

	return 0;
}

/**
 * leave_patch_region - signal handler on which a thread executes out of line if
 * it happens to be in a registered patching region
 * @sig      - signal number
 * @info     - signal info (unused)
 * @ucontext - user context
 */
static void leave_patch_region(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *uctx = ucontext;
	mcontext_t *mctx = &uctx->uc_mcontext;
	void *next_insn;
	void *out_of_line_insn;
	(void)sig;

	next_insn = (void *)mctx->gregs[REG_RIP];
	out_of_line_insn = hashmap_get(patch_region_hmap, next_insn);
	if (out_of_line_insn)
		mctx->gregs[REG_RIP] = (uint64_t)out_of_line_insn;

	sem_post(&sem_clear_patch_region);
}

/**
 * clear_patch_regions - move threads that are in a patching region out of line
 * @return - 0
 */
static int clear_patch_regions(void)
{
	int signal_count;
	int move_count = 0;
	struct timespec ts;

	ASSERT(sig_clear_patch_region >= SIGRTMIN);

	signal_count = thread_broadcast_signal(sig_clear_patch_region);

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		return -1;
	ts.tv_sec += 1;

	for (int i = 0; i < signal_count; i++) {
		if (sem_timedwait(&sem_clear_patch_region, &ts) == -1) {
			if (errno == EINTR)
				i--;
			else
				pr_dbg3("error syncing with signal handler: %s\n", strerror(errno));
		}
		else
			move_count++;
	}
	pr_dbg3("checked ip of %d/%d thread(s)\n", move_count, signal_count);

	return 0;
}

/**
 * setup_clear_patch_region - initialize data structures and signals used to
 * move threads of patching regions
 *  @return - -1 on error, 0 on success
 */
int setup_clear_patch_region(void)
{
	struct sigaction act;

	if (!patch_region_hmap) {
		patch_region_hmap = hashmap_create(4, hashmap_ptr_hash, hashmap_ptr_equals);
		if (!patch_region_hmap) {
			pr_dbg("failed to create patch region hashmap\n");
			return -1;
		}
	}

	if (sig_clear_patch_region > 0)
		return 0;

	sig_clear_patch_region = find_unused_sigrt();
	if (sig_clear_patch_region == -1)
		return -1;

	sem_init(&sem_clear_patch_region, 0, 0);

	act.sa_sigaction = leave_patch_region;
	act.sa_flags = 0;

	if (sigaction(sig_clear_patch_region, &act, NULL) < 0) {
		pr_dbg("failed to configure clear signal (SIGRT%d) handler\n",
		       sig_clear_patch_region);
		return -1;
	}

	pr_dbg("configured clear signal (SIGRT%d) handler\n", sig_clear_patch_region);
	return 0;
}

/* This list is used to store functions that need to be optimized or cleaned up
 * later in the code. In both case, a SIGRTMIN+n must be send. By optimizing or
 * cleaning all of them up at the same time, we only need to send one signal per
 * thread.
 */
LIST_HEAD(normal_funcs_patch);

struct patch_dynamic_info {
	struct list_head list;
	struct mcount_dynamic_info *mdi;
	struct mcount_disasm_info *info;
};

static void commit_normal_func(struct list_head *list, struct mcount_dynamic_info *mdi,
			       struct mcount_disasm_info *info)
{
	struct patch_dynamic_info *pdi;
	pdi = xmalloc(sizeof(*pdi));

	pdi->mdi = mdi;
	pdi->info = info;
	INIT_LIST_HEAD(&pdi->list);

	list_add(&pdi->list, list);
}

/**
 * mcount_arch_dynamic_init - initialize arch-specific data structures to
 * perform runtime dynamic instrumentation
 */
int mcount_arch_dynamic_init(void)
{
	if (!int3_hmap) {
		int3_hmap = hashmap_create(4, hashmap_ptr_hash, hashmap_ptr_equals);
		if (!int3_hmap) {
			pr_dbg("failed to create int3 hashmap\n");
			return -1;
		}
	}
	if (configure_sigtrap_handler() < 0)
		return -1;

	if (setup_synchronization_mechanism() < 0)
		return -1;

	setup_clear_patch_region();

	return 0;
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	unsigned char trampoline[] = { 0x3e, 0xff, 0x25, 0x01, 0x00, 0x00, 0x00, 0xcc };
	unsigned long fentry_addr = (unsigned long)__fentry__;
	unsigned long xray_entry_addr = (unsigned long)__xray_entry;
	unsigned long xray_exit_addr = (unsigned long)__xray_exit;
	size_t trampoline_size = 16;
	void *trampoline_check;

	if (mdi->type == DYNAMIC_XRAY)
		trampoline_size *= 2;

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE);
	mdi->trampoline -= trampoline_size;

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline += trampoline_size;
		mdi->text_size += PAGE_SIZE;

		pr_dbg2("adding a page for fentry trampoline at %#lx\n", mdi->trampoline);

		trampoline_check = mmap((void *)mdi->trampoline, PAGE_SIZE,
					PROT_READ | PROT_WRITE | PROT_EXEC,
					MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (trampoline_check == MAP_FAILED)
			pr_err("failed to mmap trampoline for setup");
	}

	if (mprotect(PAGE_ADDR(mdi->text_addr), PAGE_LEN(mdi->text_addr, mdi->text_size),
		     PROT_READ | PROT_WRITE | PROT_EXEC)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	if (mdi->type == DYNAMIC_XRAY) {
		/* jmpq  *0x1(%rip)     # <xray_entry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline), &xray_entry_addr,
		       sizeof(xray_entry_addr));

		/* jmpq  *0x1(%rip)     # <xray_exit_addr> */
		memcpy((void *)mdi->trampoline + 16, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + 16 + sizeof(trampoline), &xray_exit_addr,
		       sizeof(xray_exit_addr));
	}
	else if (mdi->type == DYNAMIC_FENTRY_NOP || mdi->type == DYNAMIC_PATCHABLE) {
		/* jmpq  *0x1(%rip)     # <fentry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline), &fentry_addr,
		       sizeof(fentry_addr));
	}
	else if (mdi->type == DYNAMIC_NONE) {
#ifdef HAVE_LIBCAPSTONE
		unsigned long dentry_addr = (unsigned long)__dentry__;

		/* jmpq  *0x2(%rip)     # <dentry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline), &dentry_addr,
		       sizeof(dentry_addr));
#endif
	}
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect(PAGE_ADDR(mdi->text_addr), PAGE_LEN(mdi->text_addr, mdi->text_size),
		     PROT_READ | PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");
}

static void read_xray_map(struct mcount_dynamic_info *mdi, struct uftrace_elf_data *elf,
			  struct uftrace_elf_iter *iter, unsigned long offset)
{
	struct xray_instr_map *xrmap;
	unsigned i;
	typeof(iter->shdr) *shdr = &iter->shdr;

	mdi->nr_patch_target = shdr->sh_size / sizeof(*xrmap);
	mdi->patch_target = xmalloc(mdi->nr_patch_target * sizeof(*xrmap));

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, mdi->patch_target, shdr->sh_size);

	for (i = 0; i < mdi->nr_patch_target; i++) {
		xrmap = &((struct xray_instr_map *)mdi->patch_target)[i];

		if (xrmap->version == 2) {
			xrmap->address += offset + (shdr->sh_offset + i * sizeof(*xrmap));
			xrmap->function += offset + (shdr->sh_offset + i * sizeof(*xrmap) + 8);
		}
		else if (elf->ehdr.e_type == ET_DYN) {
			xrmap->address += offset;
			xrmap->function += offset;
		}
	}
}

static void read_mcount_loc(struct mcount_dynamic_info *mdi, struct uftrace_elf_data *elf,
			    struct uftrace_elf_iter *iter, unsigned long offset)
{
	typeof(iter->shdr) *shdr = &iter->shdr;

	mdi->nr_patch_target = shdr->sh_size / sizeof(long);
	mdi->patch_target = xmalloc(shdr->sh_size);

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, mdi->patch_target, shdr->sh_size);

	/* symbol has relative address, fix it to match each other */
	if (elf->ehdr.e_type == ET_EXEC) {
		unsigned long *mcount_loc = mdi->patch_target;
		unsigned i;

		for (i = 0; i < mdi->nr_patch_target; i++) {
			mcount_loc[i] -= offset;
		}
	}
}

static void read_patchable_loc(struct mcount_dynamic_info *mdi, struct uftrace_elf_data *elf,
			       struct uftrace_elf_iter *iter, unsigned long offset)
{
	typeof(iter->shdr) *shdr = &iter->shdr;
	unsigned i;
	unsigned long *patchable_loc;
	unsigned long sh_addr;

	mdi->nr_patch_target = shdr->sh_size / sizeof(long);
	mdi->patch_target = xmalloc(shdr->sh_size);
	patchable_loc = mdi->patch_target;

	sh_addr = shdr->sh_addr;
	if (elf->ehdr.e_type == ET_DYN)
		sh_addr += offset;

	for (i = 0; i < mdi->nr_patch_target; i++) {
		unsigned long *entry = (unsigned long *)sh_addr + i;
		patchable_loc[i] = *entry - offset;
	}
}

void mcount_arch_find_module(struct mcount_dynamic_info *mdi, struct uftrace_symtab *symtab)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	unsigned i = 0;

	mdi->type = DYNAMIC_NONE;

	if (elf_init(mdi->map->libname, &elf) < 0)
		goto out;

	elf_for_each_shdr(&elf, &iter) {
		char *shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (!strcmp(shstr, PATCHABLE_SECT)) {
			mdi->type = DYNAMIC_PATCHABLE;
			read_patchable_loc(mdi, &elf, &iter, mdi->base_addr);
			goto out;
		}

		if (!strcmp(shstr, XRAY_SECT)) {
			mdi->type = DYNAMIC_XRAY;
			read_xray_map(mdi, &elf, &iter, mdi->base_addr);
			goto out;
		}

		if (!strcmp(shstr, MCOUNTLOC_SECT)) {
			read_mcount_loc(mdi, &elf, &iter, mdi->base_addr);
			/* still needs to check pg or fentry */
		}
	}

	/*
	 * check first few functions have fentry or patchable function entry
	 * signature.
	 */
	for (i = 0; i < symtab->nr_sym; i++) {
		struct uftrace_symbol *sym = &symtab->sym[i];
		void *code_addr = (void *)sym->addr + mdi->map->start;

		if (sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC)
			continue;

		/* don't check special functions */
		if (sym->name[0] == '_')
			continue;

		/*
		 * there might be some chances of not having patchable section
		 * '__patchable_function_entries' but shows the NOPs pattern.
		 * this can be treated as DYNAMIC_FENTRY_NOP.
		 */
		if (!memcmp(code_addr, patchable_gcc_nop, CALL_INSN_SIZE) ||
		    !memcmp(code_addr, patchable_clang_nop, CALL_INSN_SIZE)) {
			mdi->type = DYNAMIC_FENTRY_NOP;
			goto out;
		}

		/* only support calls to __fentry__ at the beginning */
		if (!memcmp(code_addr, fentry_nop_patt1, CALL_INSN_SIZE) ||
		    !memcmp(code_addr, fentry_nop_patt2, CALL_INSN_SIZE)) {
			mdi->type = DYNAMIC_FENTRY_NOP;
			goto out;
		}
	}

	switch (check_trace_functions(mdi->map->libname)) {
	case TRACE_MCOUNT:
		mdi->type = DYNAMIC_PG;
		break;
	case TRACE_FENTRY:
		mdi->type = DYNAMIC_FENTRY;
		break;
	default:
		break;
	}

out:
	pr_dbg("dynamic patch type: %s: %d (%s)\n", basename(mdi->map->libname), mdi->type,
	       mdi_type_names[mdi->type]);

	elf_finish(&elf);
}

/**
 * get_trampoline_offest - compute the relative address of the trampoline
 * @mdi    - mcount dynamic info
 * @origin - origin address
 * @return - distance to the trampoline
 */
static unsigned long get_trampoline_offset(struct mcount_dynamic_info *mdi, unsigned long origin)
{
	return mdi->trampoline - (origin + CALL_INSN_SIZE);
}

static int patch_fentry_code(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	unsigned char *insn = (void *)sym->addr + mdi->map->start;
	unsigned int target_addr;

	/* skip 'endbr64' instruction, which is inserted by (implicit) -fcf-protection option. */
	if (!memcmp(insn, endbr64, sizeof(endbr64)))
		insn += sizeof(endbr64);

	/* support patchable function entry and __fentry__ at the beginning */
	if (memcmp(insn, patchable_gcc_nop, sizeof(patchable_gcc_nop)) &&
	    memcmp(insn, patchable_clang_nop, sizeof(patchable_clang_nop)) &&
	    memcmp(insn, fentry_nop_patt1, sizeof(fentry_nop_patt1)) &&
	    memcmp(insn, fentry_nop_patt2, sizeof(fentry_nop_patt2))) {
		pr_dbg4("skip non-applicable functions: %s\n", sym->name);
		return INSTRUMENT_SKIPPED;
	}

	/* get the jump offset to the trampoline */
	target_addr = get_trampoline_offset(mdi, (unsigned long)insn);
	if (target_addr == 0)
		return INSTRUMENT_SKIPPED;

	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));

	pr_dbg3("update %p for '%s' function dynamically to call __fentry__\n", insn, sym->name);

	return INSTRUMENT_SUCCESS;
}

static int patch_fentry_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	return patch_fentry_code(mdi, sym);
}

static int patch_patchable_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	/* it does the same patch logic with fentry. */
	return patch_fentry_code(mdi, sym);
}

static int update_xray_code(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			    struct xray_instr_map *xrmap)
{
	unsigned char entry_insn[] = { 0xeb, 0x09 };
	unsigned char exit_insn[] = { 0xc3, 0x2e };
	unsigned char pad[] = { 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x02, 0x00, 0x00 };
	unsigned char nop6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char nop4[] = { 0x0f, 0x1f, 0x40, 0x00 };
	unsigned int target_addr;
	unsigned char *func = (void *)xrmap->address;
	union {
		unsigned long word;
		char bytes[8];
	} patch;

	if (memcmp(func + 2, pad, sizeof(pad)))
		return INSTRUMENT_FAILED;

	if (xrmap->kind == 0) { /* ENTRY */
		if (memcmp(func, entry_insn, sizeof(entry_insn)))
			return INSTRUMENT_FAILED;

		target_addr = mdi->trampoline - (xrmap->address + 5);

		memcpy(func + 5, nop6, sizeof(nop6));

		/* need to write patch_word atomically */
		patch.bytes[0] = 0xe8; /* "call" insn */
		memcpy(&patch.bytes[1], &target_addr, sizeof(target_addr));
		memcpy(&patch.bytes[5], nop6, 3);

		memcpy(func, patch.bytes, sizeof(patch));
	}
	else { /* EXIT */
		if (memcmp(func, exit_insn, sizeof(exit_insn)))
			return INSTRUMENT_FAILED;

		target_addr = mdi->trampoline + 16 - (xrmap->address + 5);

		memcpy(func + 5, nop4, sizeof(nop4));

		/* need to write patch_word atomically */
		patch.bytes[0] = 0xe9; /* "jmp" insn */
		memcpy(&patch.bytes[1], &target_addr, sizeof(target_addr));
		memcpy(&patch.bytes[5], nop4, 3);

		memcpy(func, patch.bytes, sizeof(patch));
	}

	pr_dbg3("update %p for '%s' function %s dynamically to call xray functions\n", func,
		sym->name, xrmap->kind == 0 ? "entry" : "exit ");
	return INSTRUMENT_SUCCESS;
}

static int patch_xray_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	unsigned i;
	int ret = -2;
	struct xray_instr_map *xrmap;
	uint64_t sym_addr = sym->addr + mdi->map->start;

	/* xray provides a pair of entry and exit (or more) */
	for (i = 0; i < mdi->nr_patch_target; i++) {
		xrmap = &((struct xray_instr_map *)mdi->patch_target)[i];

		if (xrmap->address < sym_addr || xrmap->address >= sym_addr + sym->size)
			continue;

		while ((ret = update_xray_code(mdi, sym, xrmap)) == 0) {
			if (i == mdi->nr_patch_target - 1)
				break;
			i++;

			if (xrmap->function != xrmap[1].function)
				break;
			xrmap++;
		}

		break;
	}

	return ret;
}

/**
 * patch_region_lock - insert a trap at the beginning of a patching region so no
 * new incoming thread will execute it, and register the region as critical for
 * next step
 * @mdi    - mcount dynamic info
 * @info   - disassembly info for the patched symbol
 * @return - INSTRUMENT_SUCCESS
 */
static int patch_region_lock(struct mcount_dynamic_info *mdi, struct mcount_disasm_info *info)
{
	/*
	 * Let's assume we have the following instructions.
	 *
	 *     0x0: push %rbp             <= origin_code_addr
	 *     0x1: mov  %rsp,%rbp
	 *     0x4: lea  0xeb0(%rip),%rdi
	 *     0xb: <other instructions>
	 *
	 * The goal is to modify the instructions in order to get the following
	 * ones.
	 *
	 *     0x0: call <trampoline>
	 *     0x5: <nop instructions>
	 *     0xb: <other instructions>
	 */

	void *origin_code_addr;

	origin_code_addr = (void *)info->addr;
	if (info->has_intel_cet)
		origin_code_addr += ENDBR_INSN_SIZE;

	/* The first step is to insert a 1-byte trap-based probe point (atomic).
	 * This will prevent threads to enter the critical zone while we patch it,
	 * so no core will see partial modifications.
	 *
	 *     0x0: int3                  <= origin_code_addr
	 *     0x1: mov  %rsp,%rbp
	 *     0x4: lea  0xeb0(%rip),%rdi
	 *     0xb: <other instructions>
	 *
	 * The trap will emulate a call to the trampoline while in place.
	 */

	if (register_trap(origin_code_addr, (void *)mdi->trampoline) == -1)
		return INSTRUMENT_FAILED;
	((uint8_t *)origin_code_addr)[0] = 0xcc;

	/* The second step is to move any thread out of the critical zone if still
	 * present. Threads in the critical zone resume execution out of line, in
	 * their dedicated OLX region.
	 *
	 * The method used to move the threads is to signal all the threads, so they
	 * check if their instruction pointer is in the patching region. If so, they
	 * move their instruction pointer to the corresponding one in the OLX
	 * region.
	 */

	if (register_patch_region(origin_code_addr, info->orig_size) == -1)
		pr_dbg3("failed to register patch region\n");

	return INSTRUMENT_SUCCESS;
}

/**
 * patch_code - patch a region of the code with the operand of the call
 * instruction used to probe a function. The call opcode needs to be inserted
 * later.
 * @mdi  - mcount dynamic info for the current module
 * @info - disassembly info for the patched symbol
 */
static void patch_code(struct mcount_dynamic_info *mdi, struct mcount_disasm_info *info)
{
	void *trampoline_rel_addr;
	void *origin_code_addr;

	origin_code_addr = (void *)info->addr;
	if (info->has_intel_cet)
		origin_code_addr += ENDBR_INSN_SIZE;
	trampoline_rel_addr = (void *)get_trampoline_offset(mdi, (unsigned long)origin_code_addr);

	/* The third step is to write the target address of the call. From the
	 * processor view the 4-bytes address can be any garbage instructions.
	 *
	 * We fill the remaining part of the patching region with nops.
	 *
	 *     0x0: int3
	 *     0x1: <trampoline>
	 *     0x5: <nop instructions>
	 *     0xb: <other instructions>
	 */

	memcpy(&((uint8_t *)origin_code_addr)[1], &trampoline_rel_addr, CALL_INSN_SIZE - 1);
	memset(origin_code_addr + CALL_INSN_SIZE, 0x90, /* NOP */
	       info->orig_size - CALL_INSN_SIZE);
}

/**
 * patch_region_unlock - unmark a region as critical and remove the trap that
 * prevents execution.
 * @info   - disassembly info for the patched symbol
 */
static void patch_region_unlock(struct mcount_disasm_info *info)
{
	void *origin_code_addr;

	origin_code_addr = (void *)info->addr;
	if (info->has_intel_cet)
		origin_code_addr += ENDBR_INSN_SIZE;

	if (unregister_patch_region(origin_code_addr, info->orig_size) == -1)
		pr_dbg3("failed to unregister patch region\n");

	/*
	 * The fourth and last step is to replace the trap with the call opcode.
	 *
	 *     0x0: call <trampoline>
	 *     0x5: <nop instructions>
	 *     0xb: <other instructions>
	 */

	((uint8_t *)origin_code_addr)[0] = 0xe8;
}

/**
 * patch_normal_func_init - perform the initial steps of the patching process,
 * awaiting for sanitization of the critical region. This step is batched with
 * subsequent ones.
 * @mdi    - mcount dynamic info for the current module
 * @sym    - symbol to patch
 * @disasm - disassembly engine
 * @return - instrumentation status
 */
static int patch_normal_func_init(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
				  struct mcount_disasm_engine *disasm)
{
	uint8_t jmp_insn[15] = {
		0x3e,
		0xff,
		0x25,
	};
	uint64_t jmp_target;
	struct mcount_disasm_info *info;
	unsigned call_offset = CALL_INSN_SIZE;
	int state;

	info = xmalloc(sizeof(*info));
	memset(info, 0, sizeof(*info));
	info->sym = sym;
	info->addr = mdi->map->start + sym->addr;

	state = disasm_check_insns(disasm, mdi, info);
	if (state != INSTRUMENT_SUCCESS) {
		pr_dbg3("  >> %s: %s\n", state == INSTRUMENT_FAILED ? "FAIL" : "SKIP", sym->name);
		return state;
	}

	pr_dbg2("force patch normal func: %s (patch size: %d)\n", sym->name, info->orig_size);

	/*
	 *  stored origin instruction block:
	 *  ----------------------
	 *  | [origin_code_size] |
	 *  ----------------------
	 *  | [jmpq    *0x0(rip) |
	 *  ----------------------
	 *  | [Return   address] |
	 *  ----------------------
	 */
	jmp_target = info->addr + info->orig_size;
	if (info->has_intel_cet) {
		jmp_target += ENDBR_INSN_SIZE;
		call_offset += ENDBR_INSN_SIZE;
	}

	memcpy(jmp_insn + CET_JMP_INSN_SIZE, &jmp_target, sizeof(jmp_target));

	if (info->has_jump)
		mcount_save_code(info, call_offset, jmp_insn, 0);
	else
		mcount_save_code(info, call_offset, jmp_insn, sizeof(jmp_insn));

	state = patch_region_lock(mdi, info);
	commit_normal_func(&normal_funcs_patch, mdi, info);

	return state;
}

/**
 * mcount_patch_normal_func_fini - perform the final step of the patching process and cleanup
 * @return - 0
 */
void mcount_patch_normal_func_fini(void)
{
	struct patch_dynamic_info *pdi, *tmp;

	if (list_empty(&normal_funcs_patch))
		return;

	/* We ensure that every core sees the trap before patching the critical
	 * zone, by synchronizing the them.
	 */
	synchronize_all_cores();
	clear_patch_regions();

	list_for_each_entry_safe(pdi, tmp, &normal_funcs_patch, list) {
		patch_code(pdi->mdi, pdi->info);
		write_memory_barrier();
		patch_region_unlock(pdi->info);
	}

	synchronize_all_cores();

	list_for_each_entry_safe(pdi, tmp, &normal_funcs_patch, list) {
		void *origin_code_addr;

		origin_code_addr = (void *)pdi->info->addr;
		if (pdi->info->has_intel_cet)
			origin_code_addr += ENDBR_INSN_SIZE;

		unregister_trap(origin_code_addr);
		list_del(&pdi->list);
		free(pdi->info);
		free(pdi);
	}
}

static int unpatch_func(uint8_t *insn, char *name)
{
	uint8_t nop5[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	uint8_t nop6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	uint8_t *nop_insn;
	size_t nop_size;

	if (*insn == 0xe8) {
		nop_insn = nop5;
		nop_size = sizeof(nop5);
	}
	else if (insn[0] == 0xff && insn[1] == 0x15) {
		nop_insn = nop6;
		nop_size = sizeof(nop6);
	}
	else {
		return INSTRUMENT_SKIPPED;
	}

	pr_dbg3("unpatch fentry: %s\n", name);
	memcpy(insn, nop_insn, nop_size);
	__builtin___clear_cache((void *)insn, (void *)insn + nop_size);

	return INSTRUMENT_SUCCESS;
}

static int unpatch_fentry_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	uint64_t sym_addr = sym->addr + mdi->map->start;

	return unpatch_func((void *)sym_addr, sym->name);
}

static int cmp_loc(const void *a, const void *b)
{
	const struct uftrace_symbol *sym = a;
	uintptr_t loc = *(uintptr_t *)b;

	if (sym->addr <= loc && loc < sym->addr + sym->size)
		return 0;

	return sym->addr > loc ? 1 : -1;
}

static int unpatch_mcount_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	unsigned long *mcount_loc = mdi->patch_target;
	uintptr_t *loc;

	if (mdi->nr_patch_target != 0) {
		loc = bsearch(sym, mcount_loc, mdi->nr_patch_target, sizeof(*mcount_loc), cmp_loc);

		if (loc != NULL) {
			uint8_t *insn = (uint8_t *)*loc;
			return unpatch_func(insn + mdi->map->start, sym->name);
		}
	}

	return INSTRUMENT_SKIPPED;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size)
{
	int result = INSTRUMENT_SKIPPED;

	if (min_size < CALL_INSN_SIZE + 1)
		min_size = CALL_INSN_SIZE + 1;

	if (sym->size < min_size)
		return result;

	switch (mdi->type) {
	case DYNAMIC_XRAY:
		result = patch_xray_func(mdi, sym);
		break;

	case DYNAMIC_FENTRY_NOP:
		result = patch_fentry_func(mdi, sym);
		break;

	case DYNAMIC_PATCHABLE:
		result = patch_patchable_func(mdi, sym);
		break;

	case DYNAMIC_NONE:
		result = patch_normal_func_init(mdi, sym, disasm);
		break;

	default:
		break;
	}
	return result;
}

int mcount_unpatch_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			struct mcount_disasm_engine *disasm)
{
	int result = INSTRUMENT_SKIPPED;

	switch (mdi->type) {
	case DYNAMIC_FENTRY:
		result = unpatch_fentry_func(mdi, sym);
		break;

	case DYNAMIC_PG:
		result = unpatch_mcount_func(mdi, sym);
		break;

	default:
		break;
	}
	return result;
}

static void revert_normal_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			       struct mcount_disasm_engine *disasm)
{
	void *addr = (void *)(uintptr_t)sym->addr + mdi->map->start;
	struct mcount_orig_insn *moi;

	if (!memcmp(addr, endbr64, sizeof(endbr64)))
		addr += sizeof(endbr64);

	moi = mcount_find_insn((uintptr_t)addr + CALL_INSN_SIZE);
	if (moi == NULL)
		return;

	memcpy(addr, moi->orig, moi->orig_size);
	__builtin___clear_cache(addr, addr + moi->orig_size);
}

void mcount_arch_dynamic_recover(struct mcount_dynamic_info *mdi,
				 struct mcount_disasm_engine *disasm)
{
	struct dynamic_bad_symbol *badsym, *tmp;

	list_for_each_entry_safe(badsym, tmp, &mdi->bad_syms, list) {
		if (!badsym->reverted)
			revert_normal_func(mdi, badsym->sym, disasm);

		list_del(&badsym->list);
		free(badsym);
	}
}

static bool addr_in_prologue(struct mcount_disasm_info *info, unsigned long addr)
{
	return info->addr <= addr && addr < (info->addr + info->orig_size);
}

int mcount_arch_branch_table_size(struct mcount_disasm_info *info)
{
	struct cond_branch_info *jcc_info;
	int count = 0;
	int i;

	for (i = 0; i < info->nr_branch; i++) {
		jcc_info = &info->branch_info[i];

		/* no need to allocate entry for jcc that jump directly to prologue */
		if (addr_in_prologue(info, jcc_info->branch_target))
			continue;

		count++;
	}
	return count * ARCH_BRANCH_ENTRY_SIZE;
}

void mcount_arch_patch_branch(struct mcount_disasm_info *info, struct mcount_orig_insn *orig)
{
	/*
	 * The first entry in the table starts right after the out-of-line
	 * execution buffer.
	 */
	uint64_t entry_offset = orig->insn_size;
	uint8_t trampoline[ARCH_TRAMPOLINE_SIZE] = {
		0x3e,
		0xff,
		0x25,
	};
	struct cond_branch_info *jcc_info;
	unsigned long jcc_target;
	unsigned long jcc_index;
	uint32_t disp;
	int i;

	for (i = 0; i < info->nr_branch; i++) {
		jcc_info = &info->branch_info[i];
		jcc_target = jcc_info->branch_target;
		jcc_index = jcc_info->insn_index;

		/* leave the original disp of jcc that target the prologue as it is */
		if (addr_in_prologue(info, jcc_target)) {
			jcc_target -= jcc_info->insn_addr + jcc_info->insn_size;
			info->insns[jcc_index + 1] = jcc_target;
			continue;
		}

		/* setup the branch entry trampoline */
		memcpy(trampoline + CET_JMP_INSN_SIZE, &jcc_target, sizeof(jcc_target));

		/* write the entry to the branch table */
		memcpy(orig->insn + entry_offset, trampoline, sizeof(trampoline));

		/* previously, all jcc32 are downgraded to jcc8 */
		disp = entry_offset - (jcc_index + JCC8_INSN_SIZE);
		if (disp > SCHAR_MAX) { /* should not happen */
			pr_err("target is not in reach");
		}

		/* patch jcc displacement to target corresponding entry in the table */
		info->insns[jcc_index + 1] = disp;

		entry_offset += ARCH_BRANCH_ENTRY_SIZE;
	}
}
