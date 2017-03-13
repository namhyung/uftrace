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

static void save_orig_code_arm(unsigned long addr)
{
	struct mcount_orig_insn *orig;
	uint32_t jmp_insn[] = {
		0xe59fc000,  /* LDR  ip, <addr> */
		0xe12fff1c,  /* BX   ip */
		addr + CODE_SIZE,
	};

	orig = mcount_save_code(addr, CODE_SIZE, jmp_insn, sizeof(jmp_insn));

	/* make sure orig->addr same as when called from __dentry__ */
	orig->addr += CODE_SIZE;
}

static void save_orig_code_thumb(unsigned long addr, unsigned size)
{
	struct mcount_orig_insn *orig;
	unsigned long jmp_insn[] = {
		0xc004f8df,  /* LDR  ip, <addr> */
		0xbf004760,  /* BX   ip; NOP */
		addr + size,
	};

	/* actual instruction address is even */
	orig = mcount_save_code(addr - 1, size, jmp_insn, sizeof(jmp_insn));

	/* make sure orig->addr same as when called from __dentry__ */
	orig->addr += size + 1;
	orig->insn += 1;  /* mark it as THUMB */
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

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi,
					 unsigned long addr)
{
	unsigned long jmp_offset = 12;

	if (addr & 1)
		jmp_offset = 9;

	return (mdi->trampoline - addr - jmp_offset) >> 2;
}

/* see mcount-insn.c */
int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       uintptr_t addr, uint32_t size);

static int mcount_patch_func_arm(struct mcount_dynamic_info *mdi, struct sym *sym,
				 struct mcount_disasm_engine *disasm)
{
	unsigned char *insn = (void *)(long)sym->addr;
	uint32_t push = 0xe92d400f;  /* PUSH {r0-r3,lr} */
	uint32_t target_addr;

	if (sym->size < CODE_SIZE)
		return INSTRUMENT_SKIPPED;

	if (disasm_check_insns(disasm, sym->addr, CODE_SIZE) < 0)
		return INSTRUMENT_FAILED;

	save_orig_code_arm(sym->addr);

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

static int mcount_patch_func_thumb(struct mcount_dynamic_info *mdi, struct sym *sym,
				   struct mcount_disasm_engine *disasm)
{
	uint16_t *insn = (void *)(long)sym->addr - 1;
	uint16_t pushH = 0xe92d;  /* PUSH {r0-r3,lr} */
	uint16_t pushL = 0x400f;
	uint16_t blxH = 0xf000;
	uint16_t blxL = 0xc000;
	unsigned long target_addr;
	unsigned imm10H, imm10L, j1,j2;
	int code_size;

	if (sym->size < CODE_SIZE)
		return INSTRUMENT_SKIPPED;

	code_size = disasm_check_insns(disasm, sym->addr, CODE_SIZE);
	if (code_size < 0)
		return INSTRUMENT_FAILED;

	save_orig_code_thumb(sym->addr, code_size);

	target_addr = get_target_addr(mdi, sym->addr);
	if (target_addr == 0)
		return INSTRUMENT_FAILED;

	if (target_addr >= 0x400000) {
		pr_dbg("too big code, cannot add BLX <imm> insn: %lx\n", target_addr);
		return INSTRUMENT_FAILED;
	}

	imm10L = target_addr & 0x3ff;
	imm10H = (target_addr >> 10) & 0x3ff;
	j1 = (target_addr >> 21) ^ 0x1;
	j2 = (target_addr >> 20) ^ 0x1;

	/* make a "BLX" insn with 22-bit offset */
	blxH |= imm10H;
	blxL |= (j1 << 13) | (j2 << 11) | (imm10L << 1);

	insn[0] = pushH;
	insn[1] = pushL;
	insn[2] = blxH;
	insn[3] = blxL;

	return INSTRUMENT_SUCCESS;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
		      struct mcount_disasm_engine *disasm)
{
	int ret;

	if (sym->addr & 1)
		ret = mcount_patch_func_thumb(mdi, sym, disasm);
	else
		ret = mcount_patch_func_arm(mdi, sym, disasm);

	if (ret != INSTRUMENT_SUCCESS)
		return ret;

	pr_dbg3("update function '%s' dynamically to call libmcount.\n",
		sym->name);

	return INSTRUMENT_SUCCESS;
}
