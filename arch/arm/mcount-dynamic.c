#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
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
	uint32_t jmp_insn[] = {
		0xe59fc000,  /* LDR  ip, <addr> */
		0xe12fff1c,  /* BX   ip */
		addr + 8,
	};

	orig = mcount_save_code(addr, CODE_SIZE, jmp_insn, sizeof(jmp_insn));

	/* make sure orig->addr same as when called from __dentry__ */
	orig->addr += CODE_SIZE;
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	/*
	 * trampoline assumes {r0-r3,lr} was pushed.
	 * make sure stack is 8-byte aligned.
	 */
	uint32_t trampoline[] = {
		0xe59fc000,			/* LDR  ip, &__dentry__ */
		0xe12fff1c,			/* BX   ip */
		(unsigned long) &__dentry__,
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

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");
}

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi, unsigned long addr)
{
	return (mdi->trampoline - addr - 12) >> 2;
}

static int mcount_patch_func_arm(struct mcount_dynamic_info *mdi, struct sym *sym,
				 struct mcount_disasm_engine *disasm)
{
	unsigned char *insn = (void *)(long)sym->addr;
	uint32_t push = 0xe92d400f;  /* PUSH {r0-r3,lr} */
	uint32_t target_addr;

	if (sym->size < CODE_SIZE)
		return INSTRUMENT_SKIPPED;

	save_orig_code(sym->addr);

	target_addr = get_target_addr(mdi, sym->addr);

	/* make a "BL" insn with 24-bit offset */
	target_addr |= 0xeb000000;

	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[0], &push, sizeof(push));
	memcpy(&insn[4], &target_addr, sizeof(target_addr));

	/* flush icache so that cpu can execute the new code */
	__builtin___clear_cache(insn, insn + CODE_SIZE);

	return INSTRUMENT_SUCCESS;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct mcount_disasm_engine *disasm)
{
	int ret;

	/* TODO: support THUMB instructions */
	if (sym->addr & 1)
		return INSTRUMENT_SKIPPED;

	ret = mcount_patch_func_arm(mdi, sym, disasm);
	if (ret < 0)
		return ret;

	pr_dbg3("update function '%s' dynamically to call libmcount.\n",
		sym->name);

	return INSTRUMENT_SUCCESS;
}
