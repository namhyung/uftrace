#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "mcount-arch.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"

#define PAGE_SIZE  4096
#define CODE_SIZE  8

/* target instrumentation function it needs to call */
extern void __dentry__(void);

static void save_orig_code(unsigned long addr)
{
	struct mcount_orig_insn *orig;
	struct mcount_disasm_info info = {
		.addr = addr,
		.copy_size = CODE_SIZE,
	};
	uint32_t jmp_insn[] = {
		0x58000050,     /* LDR  ip0, addr */
		0xd61f0200,     /* BR   ip0 */
		addr + 8,
		(addr + 8) >> 32,
	};

	memcpy(info.insns, (void *)addr, info.copy_size);
	orig = mcount_save_code(&info, jmp_insn, sizeof(jmp_insn));

	/* make sure orig->addr same as when called from __dentry__ */
	orig->addr += CODE_SIZE;
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	uintptr_t dentry_addr = (uintptr_t)(void *)&__dentry__;
	/*
	 * trampoline assumes {x29,x30} was pushed but x29 was not updated.
	 * make sure stack is 8-byte aligned.
	 */
	uint32_t trampoline[] = {
		0x910003fd,                     /* MOV  x29, sp */
		0x58000050,                     /* LDR  ip0, &__dentry__ */
		0xd61f0200,                     /* BR   ip0 */
		dentry_addr,
		dentry_addr >> 32,
	};

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline  = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE);
	mdi->trampoline -= sizeof(trampoline);

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline += sizeof(trampoline);
		mdi->text_size += PAGE_SIZE;

		pr_dbg("adding a page for fentry trampoline at %#lx\n",
		       mdi->trampoline);

		mmap((void *)mdi->trampoline, PAGE_SIZE,
		     PROT_READ | PROT_WRITE | PROT_EXEC,
		     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}

	if (mprotect((void *)mdi->text_addr, mdi->text_size,
		     PROT_READ | PROT_WRITE | PROT_EXEC)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
	return 0;
}

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi,
				     unsigned long addr)
{
	return (mdi->trampoline - addr - 4) >> 2;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size)
{
	uintptr_t sym_addr = sym->addr + mdi->map->start;
	void *insn = (void *)sym_addr;
	uint32_t push = 0xa9bf7bfd;  /* STP  x29, x30, [sp, #-0x10]! */
	uint32_t target_addr;

	if (min_size < CODE_SIZE)
		min_size = CODE_SIZE;
	if (sym->size <= min_size)
		return INSTRUMENT_SKIPPED;

	if (disasm_check_insns(disasm, mdi, sym) < 0)
		return INSTRUMENT_FAILED;

	save_orig_code(sym_addr);

	target_addr = get_target_addr(mdi, sym_addr);

	if ((target_addr & 0xfc000000) != 0)
		return INSTRUMENT_FAILED;

	/* make a "BL" insn with 26-bit offset */
	target_addr |= 0x94000000;

	/* hopefully we're not patching 'memcpy' itself */
	memcpy(insn, &push, sizeof(push));
	memcpy(insn+4, &target_addr, sizeof(target_addr));

	/* flush icache so that cpu can execute the new code */
	__builtin___clear_cache(insn, insn + CODE_SIZE);

	return INSTRUMENT_SUCCESS;
}

