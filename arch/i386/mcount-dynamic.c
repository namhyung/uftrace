#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "dynamic"
#define PR_DOMAIN DBG_DYNAMIC

#include "libmcount/dynamic.h"
#include "libmcount/internal.h"
#include "utils/symbol.h"
#include "utils/utils.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED
#endif

static const unsigned char fentry_nop_patt[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	unsigned char trampoline[] = { 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xff, 0x60, 0x04 };
	unsigned long fentry_addr = (unsigned long)__fentry__;
	size_t trampoline_size = 16;
	void *trampoline_check;

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE) - trampoline_size;

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline += trampoline_size;
		mdi->text_size += PAGE_SIZE;

		pr_dbg2("adding a page for fentry trampoline at %#lx\n", mdi->trampoline);

		trampoline_check = mmap((void *)mdi->trampoline, PAGE_SIZE, PROT_READ | PROT_WRITE,
					MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (trampoline_check != (void *)mdi->trampoline) {
			pr_err("could not map trampoline at desired location %#lx, got %#lx: %m\n",
			       mdi->trampoline, (uintptr_t)trampoline_check);
		}
	}

	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_READ | PROT_WRITE)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	/* jmpq  *0x2(%rip)     # <fentry_addr> */
	memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
	memcpy((void *)mdi->trampoline + sizeof(trampoline), &fentry_addr, sizeof(fentry_addr));
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_READ | PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");
}

void mcount_arch_find_module(struct mcount_dynamic_info *mdi, struct uftrace_symtab *symtab)
{
	unsigned i = 0;

	mdi->type = DYNAMIC_NONE;

	/* check first few functions have fentry signature */
	for (i = 0; i < symtab->nr_sym; i++) {
		struct uftrace_symbol *sym = &symtab->sym[i];
		void *code_addr = (unsigned char *)((uintptr_t)(sym->addr + mdi->map->start));

		if (sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC)
			continue;

		/* don't check special functions */
		if (sym->name[0] == '_')
			continue;

		/* only support calls to __fentry__ at the beginning */
		if (!memcmp(code_addr, fentry_nop_patt, CALL_INSN_SIZE)) {
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
	pr_dbg("dynamic patch type: %s: %d (%s)\n", uftrace_basename(mdi->map->libname), mdi->type,
	       mdi_type_names[mdi->type]);
}

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi, unsigned long addr)
{
	while (mdi) {
		if (mdi->text_addr <= addr && addr < mdi->text_addr + mdi->text_size)
			return mdi->trampoline - (addr + CALL_INSN_SIZE);

		mdi = mdi->next;
	}
	return 0;
}

static int patch_fentry_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	unsigned char *insn = (unsigned char *)((uintptr_t)(sym->addr + mdi->map->start));
	unsigned int target_addr;
	/* only support calls to __fentry__ at the beginning */
	if (memcmp(insn, fentry_nop_patt, sizeof(fentry_nop_patt))) {
		pr_dbg2("skip non-applicable functions: %s\n", sym->name);
		return -2;
	}

	/* get the jump offset to the trampoline */
	target_addr = get_target_addr(mdi, (unsigned long)insn);
	if (target_addr == 0)
		return -2;

	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));

	pr_dbg3("update %p for '%s' function dynamically to call __fentry__\n", insn, sym->name);

	return 0;
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
	case DYNAMIC_FENTRY_NOP:
		result = patch_fentry_func(mdi, sym);
		break;
	default:
		break;
	}
	return result;
}
