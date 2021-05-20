#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <linux/membarrier.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "mcount-arch.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/hashmap.h"
#include "utils/membarrier.h"

#define PAGE_SIZE  4096
#define PAGE_ADDR(a)    ((void *)((a) & ~(PAGE_SIZE - 1)))
#define PAGE_LEN(a, l)    (a + l - (unsigned long)PAGE_ADDR(a))
#define XRAY_SECT  "xray_instr_map"
#define MCOUNTLOC_SECT  "__mcount_loc"

/* target instrumentation function it needs to call */
extern void __fentry__(void);
extern void __dentry__(void);
extern void __xray_entry(void);
extern void __xray_exit(void);

typedef struct saved_instructions {
	unsigned int len;
	uint8_t insns[];
} saved_instructions_t;

/*
 * This hashmap contains a mapping between function start addresses and the
 * relevant saved instructions. It is used when restoring the original
 * instructions in the unpatching process.
 *
 * (void* -> saved_instructions_t*)
 */
static struct Hashmap *saved_instructions_hmap = NULL;

static int save_instructions(void* addr, unsigned int len) {
	saved_instructions_t *insns;

	if (hashmap_contains_key(saved_instructions_hmap, addr)) {
		return 0;
	}

	insns = malloc(sizeof(unsigned int) + sizeof(uint8_t) * len);
	if (insns == NULL) {
		return -1;
	}

	insns->len = len;
	memcpy(&insns->insns, addr, len);

	if (hashmap_put(saved_instructions_hmap, addr, insns) == NULL) {
		free(insns);
		return -1;
	}

	return 0;
}

static int restore_saved_instructions(void* addr, unsigned int offset, unsigned int count) {
	saved_instructions_t *insns = hashmap_get(saved_instructions_hmap, addr);
	if (insns == NULL) {
		return -1;
	}

	if (offset + count >= insns->len) {
		return 0;
	}

	if (count == 0) {
		count = insns->len - offset;
	}

	memcpy(addr + offset, &insns->insns[offset], count);

	return 0;
}

static int get_saved_instructions_length(void* addr) {
	saved_instructions_t *insns;

	if (saved_instructions_hmap == NULL) {
		return -1;
	}

	insns = hashmap_get(saved_instructions_hmap, addr);
	if (insns == NULL) {
		return -1;
	}

	return insns->len;
}

typedef struct int3_patch {
	void *address;
	void *return_address;
	struct mcount_dynamic_info *mdi;
} int3_patch_t;

/*
 * This hashmap contains a mapping between an int3 trap tracepoint and its
 * relevant information. Is is used in the patching/unpatching process. When
 * a trap get executed (SIGTRAP handler), the trap will emulate an equivalent
 * call instruction.
 *
 * (void* -> int3_patch_t*)
 */
static struct Hashmap *int3_patchs_hmap = NULL;

static int save_int3_mdi(void *address, void *return_address, struct mcount_dynamic_info *mdi) {
	int3_patch_t *patch;

	if (hashmap_contains_key(int3_patchs_hmap, address)) {
		return 0;
	}

	patch = malloc(sizeof(*patch));
	if (patch == NULL) {
		return -1;
	}

	patch->address = address;
	patch->return_address = return_address;
	patch->mdi = mdi;

	if (hashmap_put(int3_patchs_hmap, patch->address, patch) == NULL) {
		return -1;
	}

	return 0;
}

static void sigtrap_handler(int sig, siginfo_t *info, void *ucontext) {
	ucontext_t *uctx = ucontext;
	mcontext_t *mctx = &uctx->uc_mcontext;
	int3_patch_t *patch;
	uint64_t return_address;
	void* int3_address;
	(void) sig;

	__atomic_signal_fence(__ATOMIC_SEQ_CST);
	int3_address = (void*) mctx->gregs[REG_RIP] - 1;
	patch = hashmap_get(int3_patchs_hmap, int3_address);

	return_address = (uint64_t) patch->return_address;

	mctx->gregs[REG_RIP] = patch->mdi->trampoline;
	mctx->gregs[REG_RSP] -= 8;
	memcpy((void*) mctx->gregs[REG_RSP], &return_address, 8);

	pr_dbg("int3 address   = %p\n", int3_address);
	pr_dbg("return address = %p\n", (void*) return_address);
}

static bool sigtrap_handler_configured = false;

static int configure_sigtrap_handler() {
	struct sigaction act;

	if (sigtrap_handler_configured) {
		return 0;
	}

	act.sa_sigaction = sigtrap_handler;
	act.sa_flags = SA_SIGINFO;

	if (sigaction(SIGTRAP, &act, NULL) < 0) {
		pr_err("failed to configure SIGTRAP handler\n");
		return -1;
	}

	pr_dbg("configured SIGTRAP handler\n");
	sigtrap_handler_configured = true;

	return 0;
}

/*
 * This hashmap contains a mapping between a return address that is emulated by
 * the SIGTRAP handler and the real return address that would be pushed onto the
 * stack a by a real call instruction.
 *
 * (void* -> void*)
 */
static struct Hashmap *call_return_addresses_hmap = NULL;

static int map_emulated_call_return_address(void* emulated, void* real) {
	if (emulated == real) {
		return 0;
	}

	if (hashmap_contains_key(call_return_addresses_hmap, emulated)) {
		return 0;
	}

	if (hashmap_put(call_return_addresses_hmap, emulated, real) == NULL) {
		return -1;
	}

	return 0;
}

void* get_real_call_return_adress(void* emulated) {
	void* real = hashmap_get(call_return_addresses_hmap, emulated);
	if (real == NULL) {
		return emulated;
	}

	return real;
}

/*
 * This hashmap contains a mapping between an instruction to another another
 * instruction. It is used in the SIGRTMIN+n handler of a thread during the
 * patching/unpatching process.
 *
 * When patching, the mapping will be from the original instructions to the
 * one in the trampoline. When unpatching, the mapping will be from the
 * trampoline instructions to the original one.
 *
 * (instruction address -> instruction address)
 */
static struct Hashmap *move_instruction_hmap;

static int map_move_instructions(void* insns, void* trampoline_insns, unsigned int count) {
	for (unsigned int i = 0; i < count; i++) {
		if (hashmap_contains_key(move_instruction_hmap, insns + i)) {
			continue;
		}

		if (hashmap_put(move_instruction_hmap, insns + i, trampoline_insns + i) == NULL) {
			return -1;
		}
	}

	return 0;
}

static int unmap_move_instructions(void* insns, void* trampoline_insns, unsigned int count) {
	for (unsigned int i = 0; i < count; i++) {
		if (!hashmap_contains_key(move_instruction_hmap, insns + i)) {
			continue;
		}

		if (hashmap_remove(move_instruction_hmap, insns + i)) {
			return -1;
		}
	}

	return 0;
}

static void* get_move_instruction_address(void* insn) {
	return hashmap_get(move_instruction_hmap, insn);
}

static void sigrt_handler(int sig, siginfo_t *info, void *ucontext) {
	ucontext_t *uctx = ucontext;
	mcontext_t *mctx = &uctx->uc_mcontext;
	void* next_insn;
	void* trampoline_insn;
	(void) sig;

	next_insn = (void*) mctx->gregs[REG_RIP];
	trampoline_insn = get_move_instruction_address(next_insn);
	if (trampoline_insn == NULL) {
		return;
	}

	pr_dbg("moving thread to trampoline: %p -> %p\n", next_insn, trampoline_insn);
	mctx->gregs[REG_RIP] = (uint64_t) trampoline_insn;
}

static int sigrt_offset = -1;

static int send_sigrt_to_all_threads() {
	char path[256];
	DIR* directory;
	struct dirent* directory_entry;
	long tid;

	if (sigrt_offset < 0) {
		pr_err("invalid SIGRTMIN offset\n");
		goto fail_sigrt_check;
	}

	snprintf(path, 256, "/proc/%u/task", getpid());

	directory = opendir(path);
	if (directory == NULL) {
		pr_err("failed to open directory `%s`\n", path);
		goto fail_open_directory;
	}

	errno = 0;
	while (1) {
		directory_entry = readdir(directory);
		if (directory_entry == NULL) {
			if (errno != 0) {
				pr_err("failed to read directory entry\n");
				goto fail_read_directory;
			}

			break;
		}

		/* skip "." and ".." directories */
		if (directory_entry->d_name[0] == '.') {
			continue;
		}

		tid = strtol(directory_entry->d_name, NULL, 10);
		if (errno != 0 || tid < 0) {
			pr_err("failed to parse TID\n");
			goto fail_parse_tid;
		}

		/* ignore our TID */
		if (tid == getpid()) {
			continue;
		}

		/*
		 * By reading /proc/<pid>/task directory, there is the possibility of
		 * a race condition where a thread exits before we send the signal.
		 * Therefore, we do not check for errors on this call.
		 */
		kill((pid_t) tid, SIGRTMIN+sigrt_offset);
	}

	if (closedir(directory) < 0) {
		pr_err("failed to close directory\n");
	}

	return 0;

fail_parse_tid:
fail_read_directory:
	closedir(directory);
fail_open_directory:
fail_sigrt_check:
	return -1;
}

static int find_unused_sigrt(void) {
    struct sigaction oldact;

	for (int n = 0; SIGRTMIN + n <= SIGRTMAX; n++) {
		if (sigaction(SIGRTMIN + n, NULL, &oldact) < 0) {
			pr_err("failed to check current handler\n");
			return -1;
		}

		if (oldact.sa_handler == NULL) {
			return n;
		}
	}

	return -1;
}

static int configure_sigrt_handler(void) {
	static bool sigrt_configured = false;
	struct sigaction act;

	if (sigrt_configured) {
		return 0;
	}

	sigrt_offset = find_unused_sigrt();
	if (sigrt_offset < 0) {
		pr_err("failed to find unused SIGRT\n");
		return -1;
	}

	act.sa_sigaction = sigrt_handler;
	act.sa_flags = SA_SIGINFO;

	if (sigaction(SIGRTMIN+sigrt_offset, &act, NULL) < 0) {
		pr_err("failed to configure SIGRTMIN+%d handler\n", sigrt_offset);
		return -1;
	}

	pr_dbg("configured SIGRTMIN+%d handler\n", sigrt_offset);
	sigrt_configured = true;

	return 0;
}

int mcount_dynamic_init_arch(void) {
	saved_instructions_hmap = hashmap_create(4, hashmap_ptr_hash, hashmap_ptr_equals);
	if (saved_instructions_hmap == NULL) {
		pr_dbg("mcount_dynamic_init_arch: failed to create hashmap\n");
		return -1;
	}

	int3_patchs_hmap = hashmap_create(4, hashmap_ptr_hash, hashmap_ptr_equals);
	if (int3_patchs_hmap == NULL) {
		pr_dbg("mcount_dynamic_init_arch: failed to create hashmap\n");
		return -1;
	}

	call_return_addresses_hmap = hashmap_create(4, hashmap_ptr_hash, hashmap_ptr_equals);
	if (call_return_addresses_hmap == NULL) {
		pr_dbg("mcount_dynamic_init_arch: failed to create hashmap\n");
		return -1;
	}

	move_instruction_hmap = hashmap_create(4, hashmap_ptr_hash, hashmap_ptr_equals);
	if (move_instruction_hmap == NULL) {
		pr_dbg("mcount_dynamic_init_arch: failed to create hashmap\n");
		return -1;
	}

	if (membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0) < 0) {
		pr_err("failed to register intent to use MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE\n");
		return -1;
	}

	return 0;
}

struct xray_instr_map {
	uint64_t address;
	uint64_t function;
	uint8_t kind;
	uint8_t always_instrument;
	uint8_t version;
	uint8_t padding[13];
};

enum mcount_x86_dynamic_type {
	DYNAMIC_NONE,
	DYNAMIC_PG,
	DYNAMIC_FENTRY,
	DYNAMIC_FENTRY_NOP,
	DYNAMIC_XRAY,
};

static const char *adi_type_names[] = {
	"none", "pg", "fentry", "fentry-nop", "xray",
};

struct arch_dynamic_info {
	enum mcount_x86_dynamic_type	type;
	struct xray_instr_map		*xrmap;
	unsigned long			*mcount_loc;
	unsigned			xrmap_count;
	unsigned			nr_mcount_loc;
};

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	unsigned char trampoline[] = { 0x3e, 0xff, 0x25, 0x01, 0x00, 0x00, 0x00, 0xcc };
	unsigned long fentry_addr = (unsigned long)__fentry__;
	unsigned long xray_entry_addr = (unsigned long)__xray_entry;
	unsigned long xray_exit_addr = (unsigned long)__xray_exit;
	struct arch_dynamic_info *adi = mdi->arch;
	size_t trampoline_size = 16;
	void *trampoline_check;

	if (adi->type == DYNAMIC_XRAY)
		trampoline_size *= 2;

	if (configure_sigtrap_handler() < 0) {
		return -1;
	}

	if (configure_sigrt_handler() < 0) {
		return -1;
	}

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline  = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE);
	mdi->trampoline -= trampoline_size;

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline += trampoline_size;
		mdi->text_size  += PAGE_SIZE;

		pr_dbg2("adding a page for fentry trampoline at %#lx\n",
			mdi->trampoline);

		trampoline_check = mmap((void *)mdi->trampoline, PAGE_SIZE,
					PROT_READ | PROT_WRITE | PROT_EXEC,
		     			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
					-1, 0);

		if (trampoline_check == MAP_FAILED)
			pr_err("failed to mmap trampoline for setup");
	}

	if (mprotect(PAGE_ADDR(mdi->text_addr), 
			 PAGE_LEN(mdi->text_addr, mdi->text_size),
		     PROT_READ | PROT_WRITE | PROT_EXEC)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	if (adi->type == DYNAMIC_XRAY) {
		/* jmpq  *0x1(%rip)     # <xray_entry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &xray_entry_addr, sizeof(xray_entry_addr));

		/* jmpq  *0x1(%rip)     # <xray_exit_addr> */
		memcpy((void *)mdi->trampoline + 16, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + 16 + sizeof(trampoline),
		       &xray_exit_addr, sizeof(xray_exit_addr));
	}
	else if (adi->type == DYNAMIC_FENTRY_NOP) {
		/* jmpq  *0x1(%rip)     # <fentry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &fentry_addr, sizeof(fentry_addr));
	}
	else if (adi->type == DYNAMIC_NONE) {
#ifdef HAVE_LIBCAPSTONE
		unsigned long dentry_addr = (unsigned long)__dentry__;

		/* jmpq  *0x2(%rip)     # <dentry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &dentry_addr, sizeof(dentry_addr));
#endif
	}
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect(PAGE_ADDR(mdi->text_addr),
		     PAGE_LEN(mdi->text_addr, mdi->text_size),
		     PROT_READ | PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");
}

static void read_xray_map(struct arch_dynamic_info *adi,
			  struct uftrace_elf_data *elf,
			  struct uftrace_elf_iter *iter,
			  unsigned long offset)
{
	struct xray_instr_map *xrmap;
	unsigned i;
	typeof(iter->shdr) *shdr = &iter->shdr;

	adi->xrmap_count = shdr->sh_size / sizeof(*adi->xrmap);
	adi->xrmap = xmalloc(adi->xrmap_count * sizeof(*adi->xrmap));

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, adi->xrmap, shdr->sh_size);

	for (i = 0; i < adi->xrmap_count; i++) {
		xrmap = &adi->xrmap[i];

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

static void read_mcount_loc(struct arch_dynamic_info *adi,
			    struct uftrace_elf_data *elf,
			    struct uftrace_elf_iter *iter,
			    unsigned long offset)
{
	typeof(iter->shdr) *shdr = &iter->shdr;

	adi->nr_mcount_loc = shdr->sh_size / sizeof(long);
	adi->mcount_loc = xmalloc(shdr->sh_size);

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, adi->mcount_loc, shdr->sh_size);

	/* symbol has relative address, fix it to match each other */
	if (elf->ehdr.e_type == ET_EXEC) {
		unsigned i;

		for (i = 0; i < adi->nr_mcount_loc; i++) {
			adi->mcount_loc[i] -= offset;
		}
	}
}

void mcount_arch_find_module(struct mcount_dynamic_info *mdi,
			     struct symtab *symtab)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	struct arch_dynamic_info *adi;
	unsigned char fentry_nop_patt1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char fentry_nop_patt2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned i = 0;

	adi = xzalloc(sizeof(*adi));  /* DYNAMIC_NONE */

	if (elf_init(mdi->map->libname, &elf) < 0)
		goto out;

	elf_for_each_shdr(&elf, &iter) {
		char *shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (!strcmp(shstr, XRAY_SECT)) {
			adi->type = DYNAMIC_XRAY;
			read_xray_map(adi, &elf, &iter, mdi->base_addr);
			goto out;
		}

		if (!strcmp(shstr, MCOUNTLOC_SECT)) {
			read_mcount_loc(adi, &elf, &iter, mdi->base_addr);
			/* still needs to check pg or fentry */
		}
	}

	/* check first few functions have fentry signature */
	for (i = 0; i < symtab->nr_sym; i++) {
		struct sym *sym = &symtab->sym[i];
		void *code_addr = (void *)sym->addr + mdi->map->start;

		if (sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC)
			continue;

		/* dont' check special functions */
		if (sym->name[0] == '_')
			continue;

		/* only support calls to __fentry__ at the beginning */
		if (!memcmp(code_addr, fentry_nop_patt1, CALL_INSN_SIZE) ||
		    !memcmp(code_addr, fentry_nop_patt2, CALL_INSN_SIZE)) {
			adi->type = DYNAMIC_FENTRY_NOP;
			goto out;
		}
	}

	switch (check_trace_functions(mdi->map->libname)) {
	case TRACE_MCOUNT:
		adi->type = DYNAMIC_PG;
		break;
	case TRACE_FENTRY:
		adi->type = DYNAMIC_FENTRY;
		break;
	default:
		break;
	}

out:
	pr_dbg("dynamic patch type: %s: %d (%s)\n", basename(mdi->map->libname),
	       adi->type, adi_type_names[adi->type]);

	mdi->arch = adi;
	elf_finish(&elf);
}

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi, unsigned long addr)
{
	return mdi->trampoline - (addr + CALL_INSN_SIZE);
}

static int patch_fentry_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	unsigned char nop1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char nop2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char *insn = (void *)sym->addr + mdi->map->start;
	unsigned int target_addr;

	/* only support calls to __fentry__ at the beginning */
	if (memcmp(insn, nop1, sizeof(nop1)) &&  /* old pattern */
	    memcmp(insn, nop2, sizeof(nop2))) {  /* new pattern */
		pr_dbg("skip non-applicable functions: %s\n", sym->name);
		return INSTRUMENT_FAILED;
	}

	/* get the jump offset to the trampoline */
	target_addr = get_target_addr(mdi, (unsigned long)insn);
	if (target_addr == 0)
		return INSTRUMENT_SKIPPED;

	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));

	pr_dbg3("update function '%s' dynamically to call __fentry__\n",
		sym->name);

	return INSTRUMENT_SUCCESS;
}

static uint8_t xray_unpatched_entry[2] = {
	/* 2-bytes relative jump */
	0xeb, 0x09,
};

static uint8_t xray_unpatched_exit[1] = {
	/* 1-byte procedure return */
	0xc3,
};

static int enable_xray_tracepoint(struct mcount_dynamic_info *mdi, struct sym *sym,
			    struct xray_instr_map *xrmap)
{
	uint32_t target_addr;
	uint8_t *func = (void *)xrmap->address;

	uint8_t patch[11] = {
		/* 4-bytes call/jump instruction opcode */
		(xrmap->kind == 0) ? 0xe8 : 0xe9,

		/* 4-bytes call/jump target address */
		0x00, 0x00, 0x00, 0x00,

		/* 6-bytes NOP */
		0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
	};

	if (xrmap->kind == 0) {  /* ENTRY */
		if (memcmp(func, xray_unpatched_entry, sizeof(xray_unpatched_entry)))
			return INSTRUMENT_FAILED;

		target_addr = mdi->trampoline - (xrmap->address + 5);
		memcpy(&patch[1], &target_addr, sizeof(target_addr));

		/* write the 9 last bytes */
		memcpy(&func[2], &patch[2], sizeof(patch) - 2);

		/* syncronize the instruction cache of each processor*/
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0) < 0){
			pr_err("failed to execute serializing instruction\n");
		}

		/* atomically replace 2-bytes jump with our call */
		__atomic_store((uint16_t*)func, (uint16_t*)patch, __ATOMIC_SEQ_CST);
	}
	else {  /* EXIT */
		if (memcmp(func, xray_unpatched_exit, sizeof(xray_unpatched_exit)))
			return INSTRUMENT_FAILED;

		target_addr = mdi->trampoline + 16 - (xrmap->address + 5);
		memcpy(&patch[1], &target_addr, sizeof(target_addr));

		/* write the 10 last bytes */
		memcpy(&func[1], &patch[1], sizeof(patch) - 1);

		/* syncronize the instruction cache of each processor*/
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0) < 0){
			pr_err("failed to execute serializing instruction\n");
		}

		/* atomically replace 1-byte ret with our jump */
		__atomic_store((uint8_t*)func, (uint8_t*)patch, __ATOMIC_SEQ_CST);
	}

	pr_dbg3("dynamically enabled '%s' xray tracepoints\n", sym->name);
	return INSTRUMENT_SUCCESS;
}

static int disable_xray_tracepoint(struct mcount_dynamic_info *mdi, struct sym *sym,
			    struct xray_instr_map *xrmap)
{
	uint8_t expected_entry_byte = 0xe8;
	uint8_t expected_exit_byte  = 0xe9;
	uint8_t expected_nop[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	uint8_t *func = (void *)xrmap->address;

	if (memcmp(&func[5], expected_nop, sizeof(expected_nop)))
		return INSTRUMENT_FAILED;

	if (xrmap->kind == 0) {  /* ENTRY */
		if (func[0] != expected_entry_byte)
			return INSTRUMENT_FAILED;

		/* atomically replace our call with 2-bytes jump */
		__atomic_store((uint16_t*)func, (uint16_t*)xray_unpatched_entry, __ATOMIC_SEQ_CST);

		/* syncronize the instruction cache of each processor*/
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0) < 0){
			pr_err("failed to execute serializing instruction\n");
		}
	}
	else {  /* EXIT */
		if (func[0] != expected_exit_byte)
			return INSTRUMENT_FAILED;

		/* atomically replace our jump with a 1-byte ret */
		__atomic_store((uint8_t*)func, (uint8_t*)xray_unpatched_exit, __ATOMIC_SEQ_CST);

		/* syncronize the instruction cache of each processor*/
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0) < 0){
			pr_err("failed to execute serializing instruction\n");
		}
	}

	/*
	 * We do not rewrite the last 9 or 10 original bytes because it creates a race condition
	 * where a thread may try to execute an invalid instruction. Not replacing these original
	 * bytes simplify the cross-thread modifications of the code, plus we don't really need
	 * to do it.
	 */

	pr_dbg3("dynamically disabled '%s' xray tracepoints\n", sym->name);
	return INSTRUMENT_SUCCESS;
}

static int patch_xray_func(struct mcount_dynamic_info *mdi, struct sym *sym, bool enable)
{
	unsigned i;
	int ret = -2;
	struct arch_dynamic_info *adi = mdi->arch;
	struct xray_instr_map *xrmap;
	uint64_t sym_addr = sym->addr + mdi->map->start;

	xray_lock_patching_write();

	/* xray provides a pair of entry and exit (or more) */
	for (i = 0; i < adi->xrmap_count; i++) {
		xrmap = &adi->xrmap[i];

		if (xrmap->address < sym_addr || xrmap->address >= sym_addr + sym->size)
			continue;

		do {
			if (enable)
				ret = enable_xray_tracepoint(mdi, sym, xrmap);
			else
				ret = disable_xray_tracepoint(mdi, sym, xrmap);

			if (i == adi->xrmap_count - 1)
				break;
			i++;

			if (xrmap->function != xrmap[1].function)
				break;
			xrmap++;
		} while (ret == 0);

		break;
	}

	xray_unlock_patching();

	return ret;
}

static void patch_code(struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	/*
	 * Let assume that we have the following instructions.
	 *
	 *     0x0: push %rbp
	 *     0x1: mov  %rsp,%rbp
	 *     0x4: lea  0xeb0(%rip),%rdi
	 *     0xb: <other instructions>
	 *
	 * The goal is to modify the instructions in order to get the
	 * following instructions.
	 *
	 *     0x0: call <trampoline>
	 *     0x5: <garbage instructions>
	 *     0xb: <other instructions>
	 */

	unsigned int original_code_size = info->orig_size;
	void* original_code_addr = (void *)info->addr;
	void* modified_code_addr = mcount_find_code((unsigned long) original_code_addr + CALL_INSN_SIZE);
	void* trampoline_addr = (void*)get_target_addr(mdi, info->addr);

	if (info->has_intel_cet) {
		original_code_addr += ENDBR_INSN_SIZE;
		trampoline_addr = (void *)get_target_addr(mdi, info->addr + ENDBR_INSN_SIZE);
	}

	/*
	 * The first step is to insert a 1-byte trap-based probe point.
	 *
	 *     0x0: int3
	 *     0x1: mov  %rsp,%rbp
	 *     0x4: lea  0xeb0(%rip),%rdi
	 *     0xb: <other instructions>
	 *
	 * When the trap handler is executed, it will change the program
	 * counter to points to <trampoline>. When the trap handler exits,
	 * the code at <trampoline> will execute (which is __dentry__
	 * defined in dynamic.s).
	 *
	 * That said, __dentry__ is expected to be called like a function
	 * and it depends on the return address of the caller, which should
	 * be on the stack, to know which tracepoint was executed. Therefore,
	 * the trap handler actually needs to emulate a call instruction
	 * entirely (moving the instruction pointer is not enough).
	 *
	 * To do so, the trap handler will also push on the stack the next
	 * instruction pointer  that would be used if the executed
	 * instruction was a call instruction.
	 */

	if (map_emulated_call_return_address(original_code_addr + original_code_size, original_code_addr + CALL_INSN_SIZE) < 0) {
		pr_dbg("failed to map emulated return address\n");
	}

	__atomic_signal_fence(__ATOMIC_SEQ_CST);
	save_int3_mdi(original_code_addr, original_code_addr + original_code_size, mdi);
	((uint8_t*) original_code_addr)[0] = 0xcc;

	/*
	 * The second step is to move all thread that are currently
	 * executing in the patching region to the modified instructions
	 * at the end of the trampoline. This is needed in order to prevent
	 * the possible execution of invalid instructions.
	 *
	 * The method used to move the threads is to send the SIGRTMIN+n
	 * signal to all other threads. When their thread handler executes,
	 * it will check if the next instruction pointer is in the patching
	 * region. If it is, will move the next instruction pointer to the
	 * equivalent modified instruction.
	 */

	if (map_move_instructions(original_code_addr, modified_code_addr, original_code_size) < 0) {
		pr_dbg("failed to map instructions to trampoline\n");
	}

	send_sigrt_to_all_threads();

	if (unmap_move_instructions(original_code_addr, modified_code_addr, original_code_size) < 0) {
		pr_dbg("failed to unmap instructions to trampoline\n");
	}

	/*
	 * The third step is to write the target address of the jump. From
	 * the processor view the 4-bytes address can be any garbage
	 * instructions.
	 *
	 *     0x0: int3
	 *     0x1: <trampoline>
	 *     0x5: <garbage instructions>
	 *     0xb: <other instructions>
	 *
	 * Before writing the last byte, a serialization instruction must
	 * be executed in order to syncronize the instruction cache of
	 * each processor. The easiest method is to execute a membarrier
	 * system call with MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE.
	 * It will send a inter-processor interrupt that will execute
	 * the required serialization.
	 */

	memcpy(&((uint8_t*) original_code_addr)[1], &trampoline_addr, CALL_INSN_SIZE - 1);

	if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0) < 0){
		pr_err("failed to execute serializing instruction\n");
	}

	/*
	 * The fourth and last step is to write the missing byte jump
	 * instruction itself.
	 *
	 *     0x0: call <trampoline>
	 *     0x5: <garbage instructions>
	 *     0xb: <other instructions>
	 */

	((uint8_t*) original_code_addr)[0] = 0xe8;
}

static int patch_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			     struct mcount_disasm_engine *disasm)
{
	uint8_t jmp_insn[15] = { 0x3e, 0xff, 0x25, };
	uint64_t jmp_target;
	struct mcount_disasm_info info = {
		.sym  = sym,
		.addr = mdi->map->start + sym->addr,
	};
	unsigned call_offset = CALL_INSN_SIZE;
	int state;

	state = disasm_check_insns(disasm, mdi, &info);
	if (state != INSTRUMENT_SUCCESS) {
		pr_dbg3("  >> %s: %s\n", state == INSTRUMENT_FAILED ? "FAIL" : "SKIP",
			sym->name);
		return state;
	}

	pr_dbg2("patch normal func: %s (patch size: %d)\n",
		sym->name, info.orig_size);

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
	jmp_target = info.addr + info.orig_size;
	if (info.has_intel_cet) {
		jmp_target += ENDBR_INSN_SIZE;
		call_offset += ENDBR_INSN_SIZE;
	}

	memcpy(jmp_insn + CET_JMP_INSN_SIZE, &jmp_target, sizeof(jmp_target));

	if (save_instructions((void*)info.addr, info.orig_size) < 0) {
		pr_err("failed to save instructions for function %s\n", sym->name);
	}

	if (info.has_jump)
		mcount_save_code(&info, call_offset, jmp_insn, 0);
	else
		mcount_save_code(&info, call_offset, jmp_insn, sizeof(jmp_insn));

	patch_code(mdi, &info);

	return INSTRUMENT_SUCCESS;
}

static int unpatch_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	/*
	 * Let assume that we have the following instructions.
	 *
	 *     0x0: call <trampoline>
	 *     0x5: <garbage instructions>
	 *     0xb: <other instructions>
	 *
	 * The goal is to modify the instructions in order to get the
	 * following instructions.
	 *
	 *     0x0: push %rbp
	 *     0x1: mov  %rsp,%rbp
	 *     0x4: lea  0xeb0(%rip),%rdi
	 *     0xb: <other instructions>
	 */

	void* original_code_addr = (void *)mdi->map->start + sym->addr;
	void* modified_code_addr = mcount_find_code((unsigned long) original_code_addr + CALL_INSN_SIZE);

	int original_code_size = get_saved_instructions_length(original_code_addr);
	if (original_code_size < 0) {
		pr_dbg("failed to get original instructions length\n");
		return -1;
	}

	/*
	 * The first step is to insert a trap.
	 *
	 *     0x0: int3
	 *     0x1: <trampoline>
	 *     0x5: <garbage instructions>
	 *     0xb: <other instructions>
	 */

	/*
	 * TODO: The emulated return call address is not unmapped at
	 *       the end of the patching process. Hence, we can reuse
	 *       it and don't need to map it here. That said, it should
	 *       be unmapped after the aptching process and we would
	 *       need to remap it here.
	 */

	((uint8_t*) original_code_addr)[0] = 0xcc;

	/*
	 * The second step is to restore the bytes after the trap instruction.
	 *
	 *     0x0: int3
	 *     0x1: mov  %rsp,%rbp
	 *     0x4: lea  0xeb0(%rip),%rdi
	 *     0xb: <other instructions>
	 *
	 * Before restoring the last byte, a serialization instruction must
	 * be executed in order to syncronize the instruction cache of
	 * each processor. The easiest method is to execute a membarrier
	 * system call with MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE.
	 * It will send a inter-processor interrupt that will execute
	 * the required serialization.
	 */

	if (restore_saved_instructions(original_code_addr, 1, 0) < 0) {
		return 0;
	}

	if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0) < 0){
		pr_err("failed to execute serializing instruction\n");
	}

	/*
	 * The third is to restore the last byte.
	 *
	 *     0x0: push %rbp
	 *     0x1: mov  %rsp,%rbp
	 *     0x4: lea  0xeb0(%rip),%rdi
	 *     0xb: <other instructions>
	 */

	if (restore_saved_instructions(original_code_addr, 0, 1) < 0) {
		return 0;
	}

	/*
	 * The fourth and last step is to move all thread that are currently
	 * executing in the modified instructions to the original instructions
	 * at the end of the trampoline. This is needed in order to free the
	 * memory allocated for the trampoline without any race condition.
	 *
	 * The method used to move the threads is to send the SIGRTMIN+n
	 * signal to all other threads. When their thread handler executes,
	 * it will check if the next instruction pointer is in the patching
	 * region. If it is, will move the next instruction pointer to the
	 * equivalent modified instruction.
	 */

	if (map_move_instructions(modified_code_addr, original_code_addr, original_code_size) < 0) {
		pr_dbg("failed to map instructions to trampoline\n");
	}

	send_sigrt_to_all_threads();

	if (unmap_move_instructions(modified_code_addr, original_code_addr, original_code_size) < 0) {
		pr_dbg("failed to unmap instructions to trampoline\n");
	}

	return 0;
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

static int unpatch_fentry_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	uint64_t sym_addr = sym->addr + mdi->map->start;

	return unpatch_func((void *)sym_addr, sym->name);
}

static int cmp_loc(const void *a, const void *b)
{
	const struct sym *sym = a;
	uintptr_t loc = *(uintptr_t *)b;

	if (sym->addr <= loc && loc < sym->addr + sym->size)
		return 0;

	return sym->addr > loc ? 1 : -1;
}

static int unpatch_mcount_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	struct arch_dynamic_info *adi = mdi->arch;

	uintptr_t *loc;

	if (adi->nr_mcount_loc != 0) {
		loc = bsearch(sym, adi->mcount_loc, adi->nr_mcount_loc,
			       sizeof(*adi->mcount_loc), cmp_loc);

		if (loc != NULL) {
			uint8_t *insn = (uint8_t*) *loc;
			return unpatch_func(insn + mdi->map->start, sym->name);
		}
	}

	return INSTRUMENT_SKIPPED;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct mcount_disasm_engine *disasm,
		      unsigned min_size)
{
	struct arch_dynamic_info *adi = mdi->arch;
	int result = INSTRUMENT_SKIPPED;

	if (min_size < CALL_INSN_SIZE)
		min_size = CALL_INSN_SIZE;

	if (sym->size < min_size)
		return result;

	switch (adi->type) {
	case DYNAMIC_XRAY:
		result = patch_xray_func(mdi, sym, true);
		break;

	case DYNAMIC_FENTRY_NOP:
		result = patch_fentry_func(mdi, sym);
		break;

	case DYNAMIC_NONE:
		result = patch_normal_func(mdi, sym, disasm);
		break;

	default:
		break;
	}
	return result;
}

int mcount_unpatch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			struct mcount_disasm_engine *disasm)
{
	struct arch_dynamic_info *adi = mdi->arch;
	int result = INSTRUMENT_SKIPPED;

	switch (adi->type) {
	case DYNAMIC_XRAY:
		result = patch_xray_func(mdi, sym, false);
		break;

	case DYNAMIC_FENTRY:
		result = unpatch_fentry_func(mdi, sym);
		break;

	case DYNAMIC_PG:
		result = unpatch_mcount_func(mdi, sym);
		break;

	case DYNAMIC_NONE:
		result = unpatch_normal_func(mdi, sym);
		break;

	default:
		break;
	}
	return result;
}

static void revert_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			       struct mcount_disasm_engine *disasm)
{
	void *addr = (void *)(uintptr_t)sym->addr + mdi->map->start;
	uint8_t endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
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

void mcount_arch_patch_branch(struct mcount_disasm_info *info,
			      struct mcount_orig_insn *orig)
{
	/*
	 * The first entry in the table starts right after the out-of-line 
	 * execution buffer.
	 */
	uint64_t entry_offset = orig->insn_size;
	uint8_t trampoline[ARCH_TRAMPOLINE_SIZE] = { 0x3e, 0xff, 0x25, };
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

		/* patch jcc displacement to target correspending entry in the table */
		info->insns[jcc_index + 1] = disp;

		entry_offset += ARCH_BRANCH_ENTRY_SIZE;
	}
}
