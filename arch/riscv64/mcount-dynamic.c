#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "dynamic"
#define PR_DOMAIN DBG_DYNAMIC

#include "libmcount/dynamic.h"
#include "libmcount/internal.h"
#include "libmcount/mcount.h"
#include "mcount-arch.h"
#include "utils/symbol.h"
#include "utils/utils.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED
#endif

/* the patch region is auipc(4) + jalr/nop4(4) */
#define CODE_SIZE 8

/* implemented in arch/riscv64/dynamic.S */
extern void __dentry__(void);

/*
 * Instruction encodings (verified against the kernel's RISC-V ftrace).
 *   auipc t0, 0        = 0x00000297
 *   jalr  t0, 0(t0)    = 0x000282e7   (rd = t0, rs1 = t0)
 *   nop4 (addi x0,x0,0)= 0x00000013
 * The offset between the patch site and the trampoline is split into the
 * auipc (upper 20 bits) and jalr (lower 12 bits, sign-extended) the same way
 * a normal PC-relative call is built.
 */
#define AUIPC_T0 0x00000297
#define JALR_T0 0x000282e7
#define RISCV_NOP4 0x00000013

#define JALR_SIGN_MASK 0x00000800
#define JALR_OFFSET_MASK 0x00000fff
#define AUIPC_OFFSET_MASK 0xfffff000
#define AUIPC_PAD 0x00001000
#define JALR_SHIFT 20

static inline uint32_t to_auipc_t0(int32_t offset)
{
	if (offset & JALR_SIGN_MASK)
		return ((offset & AUIPC_OFFSET_MASK) + AUIPC_PAD) | AUIPC_T0;
	return (offset & AUIPC_OFFSET_MASK) | AUIPC_T0;
}

static inline uint32_t to_jalr_t0(int32_t offset)
{
	return ((offset & JALR_OFFSET_MASK) << JALR_SHIFT) | JALR_T0;
}

/* expected NOP patterns of a patchable function entry (8 bytes) */
static bool is_patchable_nop(const void *insn)
{
	uint32_t w[2];

	memcpy(w, insn, CODE_SIZE);
	/* 4x c.nop on an RVC target */
	if (w[0] == 0x00010001 && w[1] == 0x00010001)
		return true;
	/* 2x nop4 on a non-RVC target */
	if (w[0] == RISCV_NOP4 && w[1] == RISCV_NOP4)
		return true;
	return false;
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
	}

	/*
	 * The __patchable_function_entries section may be missing (e.g. stripped
	 * by --gc-sections).  Fall back to checking the first few functions for
	 * the patchable NOP pattern.
	 */
	for (i = 0; i < symtab->nr_sym; i++) {
		struct uftrace_symbol *sym = &symtab->sym[i];
		void *code_addr = (void *)sym->addr + mdi->map->start;

		if (sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC)
			continue;
		if (sym->name[0] == '_')
			continue;

		if (is_patchable_nop(code_addr)) {
			mdi->type = DYNAMIC_FENTRY_NOP;
			goto out;
		}
	}

	switch (check_trace_functions(mdi->map->libname)) {
	case TRACE_MCOUNT:
		mdi->type = DYNAMIC_PG;
		break;
	default:
		break;
	}

out:
	pr_dbg("dynamic patch type: %s: %d (%s)\n", uftrace_basename(mdi->map->libname), mdi->type,
	       mdi_type_names[mdi->type]);

	elf_finish(&elf);
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	unsigned long dentry_addr = (unsigned long)(void *)&__dentry__;
	unsigned long page_offset;

	/*
	 *   auipc t1, 0        ; t1 = address of this auipc (PC, hi = 0)
	 *   ld    t1, 12(t1)   ; t1 = *(this + 12) = absolute address of __dentry__
	 *   jr    t1
	 *   .dword __dentry__  ; stored 12 bytes after the auipc
	 */
	uint32_t trampoline[] = {
		0x00000317, /* auipc t1, 0 */
		0x00c33303, /* ld    t1, 12(t1) */
		0x00030067, /* jalr  x0, 0(t1) (jr t1) */
		(uint32_t)dentry_addr,
		(uint32_t)(dentry_addr >> 32),
	};

	/* find unused space at the end of the code segment */
	mdi->trampoline = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE);
	mdi->trampoline -= sizeof(trampoline);

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		/*
		 * There is no room at the end of the text segment (e.g. a shared
		 * library whose next page is already mapped).  Map a fresh page
		 * near the text and let the kernel pick a free address (the hint
		 * is not MAP_FIXED, so it won't fail if the page is taken).
		 *
		 * The auipc + jalr sequence can reach +-2GB and patch_code() skips
		 * any function out of that range, so the trampoline doesn't have to
		 * be adjacent to the text.
		 */
		void *hint = (void *)mdi->trampoline + sizeof(trampoline);
		void *page = mmap(hint, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (page == MAP_FAILED) {
			pr_dbg("cannot map a page for the dynamic trampoline: %m\n");
			return -1;
		}

		mdi->trampoline = (unsigned long)page;
		pr_dbg("mapped dynamic trampoline at %#lx\n", mdi->trampoline);
	}

	page_offset = mdi->text_addr & (PAGE_SIZE - 1);
	if (mprotect((void *)(mdi->text_addr - page_offset), mdi->text_size + page_offset,
		     PROT_READ | PROT_WRITE | PROT_EXEC)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
	__builtin___clear_cache((void *)mdi->trampoline,
				(void *)mdi->trampoline + sizeof(trampoline));
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	/* restore the text protection that setup_trampoline() opened for patching */
	if (mprotect(PAGE_ADDR(mdi->text_addr), PAGE_LEN(mdi->text_addr, mdi->text_size),
		     PROT_READ | PROT_EXEC))
		pr_dbg("cannot restore trampoline protection: %m\n");
}

static int patch_code(struct mcount_dynamic_info *mdi, unsigned long insn_addr)
{
	uint32_t *insn = (uint32_t *)insn_addr;
	long offset = (long)mdi->trampoline - (long)insn_addr;
	uint32_t auipc, jalr;

	/* auipc + jalr can reach +-2GB */
	if (offset != (long)(int32_t)offset) {
		pr_dbg("trampoline is out of range: %#lx\n", offset);
		return INSTRUMENT_FAILED;
	}

	auipc = to_auipc_t0((int32_t)offset);
	jalr = to_jalr_t0((int32_t)offset);

	insn[0] = auipc;
	insn[1] = jalr;
	__builtin___clear_cache((void *)&insn[0], (void *)&insn[2]);

	return INSTRUMENT_SUCCESS;
}

static int patch_patchable_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	unsigned long insn_addr = sym->addr + mdi->map->start;

	if (!is_patchable_nop((void *)insn_addr)) {
		pr_dbg4("skip non-applicable function: %s\n", sym->name);
		return INSTRUMENT_SKIPPED;
	}

	if (patch_code(mdi, insn_addr) < 0)
		return INSTRUMENT_FAILED;

	pr_dbg3("dynamically patch '%s' to call the trampoline\n", sym->name);
	return INSTRUMENT_SUCCESS;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size)
{
	if (min_size < CODE_SIZE + 1)
		min_size = CODE_SIZE + 1;

	if (sym->size < min_size)
		return INSTRUMENT_SKIPPED;

	switch (mdi->type) {
	case DYNAMIC_PATCHABLE:
	case DYNAMIC_FENTRY_NOP:
		return patch_patchable_func(mdi, sym);
	default:
		/* DYNAMIC_NONE (full binary patching) is not supported yet */
		return INSTRUMENT_SKIPPED;
	}
}

int mcount_unpatch_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			struct mcount_disasm_engine *disasm)
{
	/*
	 * -fpatchable-function-entry leaves the entry as NOPs, so a function
	 * that should not be traced is simply left unpatched -- there is
	 * nothing to revert here (unlike -mfentry, which isn't available on
	 * RISC-V).
	 */
	return -1;
}

void mcount_arch_dynamic_recover(struct mcount_dynamic_info *mdi,
				 struct mcount_disasm_engine *disasm)
{
	mcount_free_badsym(mdi);
}

/* The patchable path doesn't use the (capstone) disassembler. */
void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
}

void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
}
