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
#include "utils/rbtree.h"
#include "utils/symbol.h"
#include "utils/utils.h"

#define CODE_SIZE 8

static const unsigned int patchable_nop_patt[] = { 0xd503201f, 0xd503201f };

static void save_orig_code(struct mcount_disasm_info *info)
{
	uint32_t jmp_insn[6] = {
		0x58000050, /* LDR  ip0, addr */
		0xd61f0200, /* BR   ip0 */
		info->addr + 8,
		(info->addr + 8) >> 32,
	};
	size_t jmp_insn_size = 16;

	if (info->modified) {
		memcpy(&jmp_insn[4], &info->insns[24], 8);
		jmp_insn_size += 8;
	}

	/* make sure info.addr same as when called from __dentry__ */
	mcount_save_code(info, CODE_SIZE, jmp_insn, jmp_insn_size);
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	uintptr_t dentry_addr = (uintptr_t)(void *)&__dentry__;
	uintptr_t fentry_addr = (uintptr_t)(void *)&__fentry__;
	/*
	 * trampoline assumes {x29,x30} was pushed but x29 was not updated.
	 * make sure stack is 8-byte aligned.
	 */
	uint32_t trampoline[] = {
		0x910003fd, /* MOV  x29, sp */
		0x58000050, /* LDR  ip0, &__dentry__ */
		0xd61f0200, /* BR   ip0 */
		dentry_addr, dentry_addr >> 32,
	};

	if (mdi->type == DYNAMIC_FENTRY_NOP || mdi->type == DYNAMIC_PATCHABLE) {
		trampoline[3] = fentry_addr;
		trampoline[4] = fentry_addr >> 32;
	}

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE);
	mdi->trampoline -= sizeof(trampoline);

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		mdi->trampoline += sizeof(trampoline);
		mdi->text_size += PAGE_SIZE;

		pr_dbg("adding a page for fentry trampoline at %#lx\n", mdi->trampoline);

		mmap((void *)mdi->trampoline, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
		     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}

	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_READ | PROT_WRITE | PROT_EXEC)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
	return 0;
}

static void read_patchable_loc(struct mcount_dynamic_info *mdi, struct uftrace_elf_data *elf,
			       struct uftrace_elf_iter *iter, unsigned long offset)
{
	typeof(iter->shdr) *shdr = &iter->shdr;

	mdi->nr_patch_target = shdr->sh_size / sizeof(long);
	mdi->patch_target = xmalloc(shdr->sh_size);

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, mdi->patch_target, shdr->sh_size);

	/* symbol has relative address, fix it to match each other */
	if (elf->ehdr.e_type == ET_EXEC) {
		unsigned long *patchable_loc = mdi->patch_target;
		unsigned i;

		for (i = 0; i < mdi->nr_patch_target; i++) {
			patchable_loc[i] -= offset;
		}
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
	 * check first few functions have patchable function entry
	 * signature.
	 */
	for (i = 0; i < symtab->nr_sym; i++) {
		struct uftrace_symbol *sym = &symtab->sym[i];
		void *code_addr = (void *)sym->addr + mdi->map->start;

		if (sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC)
			continue;

		/* dont' check special functions */
		if (sym->name[0] == '_')
			continue;

		/*
		 * there might be some chances of not having patchable section
		 * '__patchable_function_entries' but shows the NOPs pattern.
		 * this can be marked as DYNAMIC_FENTRY_NOP.
		 */
		if (!memcmp(code_addr, patchable_nop_patt, CODE_SIZE)) {
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
	pr_dbg("dynamic patch type: %s: %d (%s)\n", basename(mdi->map->libname), mdi->type,
	       mdi_type_names[mdi->type]);

	elf_finish(&elf);
}

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi, unsigned long addr)
{
	/* encode the target address of the trampoline */
	return (mdi->trampoline - addr - 4) >> 2;
}

static int patch_code(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	uint32_t push = 0xa9bf7bfd; /* STP  x29, x30, [sp, #-0x10]! */
	uint32_t call;
	void *insn = (void *)sym->addr + mdi->map->start;

	call = get_target_addr(mdi, (unsigned long)insn);

	if ((call & 0xfc000000) != 0)
		return INSTRUMENT_FAILED;

	/* make a "BL" insn with 26-bit offset */
	call |= 0x94000000;

	/* hopefully we're not patching 'memcpy' itself */
	memcpy(insn, &push, sizeof(push));
	memcpy(insn + 4, &call, sizeof(call));

	/* flush icache so that cpu can execute the new code */
	__builtin___clear_cache(insn, insn + CODE_SIZE);

	return INSTRUMENT_SUCCESS;
}

static int patch_patchable_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	void *insn = (void *)sym->addr + mdi->map->start;

	/* only support calls to 2 NOPs at the beginning */
	if (memcmp(insn, patchable_nop_patt, sizeof(patchable_nop_patt))) {
		pr_dbg4("skip non-applicable functions: %s\n", sym->name);
		return INSTRUMENT_SKIPPED;
	}

	if (patch_code(mdi, sym) < 0)
		return INSTRUMENT_FAILED;

	pr_dbg3("update %p for '%s' function dynamically to call __fentry__\n", insn, sym->name);

	return INSTRUMENT_SUCCESS;
}

static int patch_normal_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			     struct mcount_disasm_engine *disasm)
{
	struct mcount_disasm_info info = {
		.sym = sym,
		.addr = sym->addr + mdi->map->start,
	};

	if (disasm_check_insns(disasm, mdi, &info) < 0)
		return INSTRUMENT_FAILED;

	save_orig_code(&info);

	if (patch_code(mdi, sym) < 0)
		return INSTRUMENT_FAILED;

	pr_dbg3("force patch normal func: %s (patch size: %d)\n", sym->name, info.orig_size);

	return INSTRUMENT_SUCCESS;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size)
{
	int result = INSTRUMENT_SKIPPED;

	if (min_size < CODE_SIZE + 1)
		min_size = CODE_SIZE + 1;

	if (sym->size < min_size)
		return result;

	switch (mdi->type) {
	case DYNAMIC_PATCHABLE:
	case DYNAMIC_FENTRY_NOP:
		result = patch_patchable_func(mdi, sym);
		break;

	case DYNAMIC_NONE:
		result = patch_normal_func(mdi, sym, disasm);
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
	void *saved_insn;

	saved_insn = mcount_find_code((uintptr_t)addr + CODE_SIZE);
	if (saved_insn == NULL)
		return;

	memcpy(addr, saved_insn, CODE_SIZE);
	__builtin___clear_cache(addr, addr + CODE_SIZE);
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
