#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "mcount-arch.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"

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

struct xray_instr_map {
	unsigned long addr;
	unsigned long entry;
	unsigned long type;
	unsigned long count;
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
	unsigned char trampoline[] = { 0xff, 0x25, 0x02, 0x00, 0x00, 0x00, 0xcc, 0xcc };
	unsigned long fentry_addr = (unsigned long)__fentry__;
	unsigned long xray_entry_addr = (unsigned long)__xray_entry;
	unsigned long xray_exit_addr = (unsigned long)__xray_exit;
	struct arch_dynamic_info *adi = mdi->arch;
	size_t trampoline_size = 16;
	void *trampoline_check;

	if (adi->type == DYNAMIC_XRAY)
		trampoline_size *= 2;

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
		/* jmpq  *0x2(%rip)     # <xray_entry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &xray_entry_addr, sizeof(xray_entry_addr));

		/* jmpq  *0x2(%rip)     # <xray_exit_addr> */
		memcpy((void *)mdi->trampoline + 16, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + 16 + sizeof(trampoline),
		       &xray_exit_addr, sizeof(xray_exit_addr));
	}
	else if (adi->type == DYNAMIC_FENTRY_NOP) {
		/* jmpq  *0x2(%rip)     # <fentry_addr> */
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
	typeof(iter->shdr) *shdr = &iter->shdr;

	adi->xrmap_count = shdr->sh_size / sizeof(*adi->xrmap);
	adi->xrmap = xmalloc(adi->xrmap_count * sizeof(*adi->xrmap));

	elf_get_secdata(elf, iter);
	elf_read_secdata(elf, iter, 0, adi->xrmap, shdr->sh_size);

	/* handle position independent code */
	if (elf->ehdr.e_type == ET_DYN) {
		struct xray_instr_map *xrmap;
		unsigned i;

		for (i = 0; i < adi->xrmap_count; i++) {
			xrmap = &adi->xrmap[i];

			xrmap->addr  += offset;
			xrmap->entry += offset;
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

static int update_xray_code(struct mcount_dynamic_info *mdi, struct sym *sym,
			    struct xray_instr_map *xrmap)
{
	unsigned char entry_insn[] = { 0xeb, 0x09 };
	unsigned char exit_insn[]  = { 0xc3, 0x2e };
	unsigned char pad[] = { 0x66, 0x0f, 0x1f, 0x84, 0x00,
				0x00, 0x02, 0x00, 0x00 };
	unsigned char nop6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char nop4[] = { 0x0f, 0x1f, 0x40, 0x00 };
	unsigned int target_addr;
	unsigned char *func = (void *)xrmap->addr;
	union {
		unsigned long word;
		char bytes[8];
	} patch;

	if (memcmp(func + 2, pad, sizeof(pad)))
		return INSTRUMENT_FAILED;

	if (xrmap->type == 0) {  /* ENTRY */
		if (memcmp(func, entry_insn, sizeof(entry_insn)))
			return INSTRUMENT_FAILED;

		target_addr = mdi->trampoline - (xrmap->addr + 5);

		memcpy(func + 5, nop6, sizeof(nop6));

		/* need to write patch_word atomically */
		patch.bytes[0] = 0xe8;  /* "call" insn */
		memcpy(&patch.bytes[1], &target_addr, sizeof(target_addr));
		memcpy(&patch.bytes[5], nop6, 3);

		memcpy(func, patch.bytes, sizeof(patch));
	}
	else {  /* EXIT */
		if (memcmp(func, exit_insn, sizeof(exit_insn)))
			return INSTRUMENT_FAILED;

		target_addr = mdi->trampoline + 16 - (xrmap->addr + 5);

		memcpy(func + 5, nop4, sizeof(nop4));

		/* need to write patch_word atomically */
		patch.bytes[0] = 0xe9;  /* "jmp" insn */
		memcpy(&patch.bytes[1], &target_addr, sizeof(target_addr));
		memcpy(&patch.bytes[5], nop4, 3);

		memcpy(func, patch.bytes, sizeof(patch));
	}

	pr_dbg3("update function '%s' dynamically to call xray functions\n",
		sym->name);
	return INSTRUMENT_SUCCESS;
}

static int patch_xray_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	unsigned i;
	int ret = -2;
	struct arch_dynamic_info *adi = mdi->arch;
	struct xray_instr_map *xrmap;
	uint64_t sym_addr = sym->addr + mdi->map->start;

	/* xray provides a pair of entry and exit (or more) */
	for (i = 0; i < adi->xrmap_count; i++) {
		xrmap = &adi->xrmap[i];

		if (xrmap->addr < sym_addr || xrmap->addr >= sym_addr + sym->size)
			continue;

		while ((ret = update_xray_code(mdi, sym, xrmap)) == 0) {
			if (i == adi->xrmap_count - 1)
				break;
			i++;

			if (xrmap->entry != xrmap[1].entry)
				break;
			xrmap++;
		}

		break;
	}

	return ret;
}

/*
 *  we overwrite instructions over 5bytes from start of function
 *  to call '__dentry__' that seems similar like '__fentry__'.
 *
 *  while overwriting, After adding the generated instruction which
 *  returns to the address of the original instruction end,
 *  save it in the heap.
 *
 *  for example:
 *
 *   4005f0:       31 ed                   xor     %ebp,%ebp
 *   4005f2:       49 89 d1                mov     %rdx,%r9
 *   4005f5:       5e                      pop     %rsi
 *
 *  will changed like this :
 *
 *   4005f0	call qword ptr [rip + 0x200a0a] # 0x601000
 *
 *  and keeping original instruction :
 *
 *  Original Instructions---------------
 *    f1cff0:	xor ebp, ebp
 *    f1cff2:	mov r9, rdx
 *    f1cff5:	pop rsi
 *  Generated Instruction to return-----
 *    f1cff6:	jmp qword ptr [rip]
 *    f1cffc:	QW 0x00000000004005f6
 *
 *  In the original case, address 0x601000 has a dynamic symbol
 *  start address. It is also the first element in the GOT array.
 *  while initializing the mcount library, we will replace it with
 *  the address of the function '__dentry__'. so, the changed
 *  instruction will be calling '__dentry__'.
 *
 *  '__dentry__' has a similar function like '__fentry__'.
 *  the other thing is that it returns to original instructions
 *  we keeping. it makes it possible to execute the original
 *  instructions and return to the address at the end of the original
 *  instructions. Thus, the execution will goes on.
 *
 */

/*
 * Patch the instruction to the address as given for arguments.
 */
static void patch_code(struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	void *origin_code_addr;
	unsigned char call_insn[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 };
	uint32_t target_addr = get_target_addr(mdi, info->addr);

	/* patch address */
	origin_code_addr = (void *)info->addr;

	if (info->has_intel_cet) {
		origin_code_addr += ENDBR_INSN_SIZE;
		target_addr = get_target_addr(mdi, info->addr + ENDBR_INSN_SIZE);
	}

	/* build the instrumentation instruction */
	memcpy(&call_insn[1], &target_addr, CALL_INSN_SIZE - 1);

	/*
	 * we need 5-bytes at least to instrumentation. however,
	 * if instructions is not fit 5-bytes, we will overwrite the
	 * 5-bytes and fill the remaining part of the last
	 * instruction with nop.
	 *
	 * [example]
	 * In this example, we overwrite 9-bytes to use 5-bytes.
	 *
	 * dynamic: 0x19e98b0[01]:push rbp
	 * dynamic: 0x19e98b1[03]:mov rbp, rsp
	 * dynamic: 0x19e98b4[05]:mov edi, 0x4005f4
	 *
	 * dynamic: 0x40054c[05]:call 0x400ff0
	 * dynamic: 0x400551[01]:nop
	 * dynamic: 0x400552[01]:nop
	 * dynamic: 0x400553[01]:nop
	 * dynamic: 0x400554[01]:nop
	 */
	memcpy(origin_code_addr, call_insn, CALL_INSN_SIZE);
	memset(origin_code_addr + CALL_INSN_SIZE, 0x90,  /* NOP */
	       info->orig_size - CALL_INSN_SIZE);

	/* flush icache so that cpu can execute the new insn */
	__builtin___clear_cache(origin_code_addr,
				origin_code_addr + info->orig_size);
}

static int patch_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			     struct mcount_disasm_engine *disasm)
{
	uint8_t jmp_insn[14] = { 0xff, 0x25, };
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

	memcpy(jmp_insn + JMP_INSN_SIZE, &jmp_target, sizeof(jmp_target));

	if (info.has_jump)
		mcount_save_code(&info, call_offset, jmp_insn, 0);
	else
		mcount_save_code(&info, call_offset, jmp_insn, sizeof(jmp_insn));

	patch_code(mdi, &info);

	return INSTRUMENT_SUCCESS;
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
		result = patch_xray_func(mdi, sym);
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

static void revert_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			       struct mcount_disasm_engine *disasm)
{
	void *addr = (void *)(uintptr_t)sym->addr + mdi->map->start;
	struct mcount_orig_insn *moi;

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
	uint8_t trampoline[ARCH_TRAMPOLINE_SIZE] = { 0xff, 0x25, };
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
		memcpy(trampoline + JMP_INSN_SIZE, &jcc_target, sizeof(jcc_target));

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
