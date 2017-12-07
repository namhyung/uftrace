#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define PAGE_SIZE  4096

/* target instrumentation function it needs to call */
extern void __fentry__(void);

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	unsigned char trampoline[] = { 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xff, 0x60, 0x04 };
	unsigned long fentry_addr = (unsigned long)__fentry__;
	struct arch_dynamic_info *adi = mdi->arch;
	size_t trampoline_size = 16;

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline = ALIGN(mdi->addr + mdi->size, PAGE_SIZE) - trampoline_size;

	if (unlikely(mdi->trampoline < mdi->addr + mdi->size)) {
		mdi->trampoline += trampoline_size;
		mdi->size += PAGE_SIZE;

		pr_dbg2("adding a page for fentry trampoline at %#lx\n",
			mdi->trampoline);

		mmap((void *)mdi->trampoline, PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}

	if (mprotect((void *)mdi->addr, mdi->size, PROT_READ | PROT_WRITE)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	/* jmpq  *0x2(%rip)     # <fentry_addr> */
	memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
	memcpy((void *)mdi->trampoline + sizeof(trampoline),
	       &fentry_addr, sizeof(fentry_addr));
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect((void *)mdi->addr, mdi->size, PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");
}

#define CALL_INSN_SIZE 5

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi, unsigned long addr)
{
	while (mdi) {
		if (mdi->addr <= addr && addr < mdi->addr + mdi->size)
			return mdi->trampoline - (addr + CALL_INSN_SIZE);

		mdi = mdi->next;
	}
	return 0;
}

static int patch_fentry_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	// In case of "gcc" which is not patched because of old version, 
	// it may not create 5 byte nop.
	unsigned char nop[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char *insn = (void *)sym->addr;
	unsigned int target_addr;

	/* only support calls to __fentry__ at the beginning */
	if (memcmp(insn, nop, sizeof(nop))) {
		pr_dbg2("skip non-applicable functions: %s\n", sym->name);
		return -2;
	}

	/* get the jump offset to the trampoline */
	target_addr = get_target_addr(mdi, sym->addr);
	if (target_addr == 0)
		return -2;

	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));

	pr_dbg3("update function '%s' dynamically to call __fentry__\n",
		sym->name);

	return 0;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	return patch_fentry_func(mdi, sym);
}

