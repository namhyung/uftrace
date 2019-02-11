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
#define XRAY_SECT  "xray_instr_map"

#define CALL_INSN_SIZE  5
#define JMP_INSN_SIZE   6

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

struct arch_dynamic_info {
	struct xray_instr_map *xrmap;
	unsigned xrmap_count;
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

#ifdef HAVE_LIBCAPSTONE
	trampoline_size *= 2;
#else
	if (adi && adi->xrmap_count)
		trampoline_size *= 2;
#endif

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

	if (mprotect((void *)mdi->text_addr, mdi->text_size,
		     PROT_READ | PROT_WRITE | PROT_EXEC)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	if (adi && adi->xrmap_count) {
		/* jmpq  *0x2(%rip)     # <xray_entry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &xray_entry_addr, sizeof(xray_entry_addr));

		/* jmpq  *0x2(%rip)     # <xray_exit_addr> */
		memcpy((void *)mdi->trampoline + 16, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + 16 + sizeof(trampoline),
		       &xray_exit_addr, sizeof(xray_exit_addr));
	}
	else {
		/* jmpq  *0x2(%rip)     # <fentry_addr> */
		memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + sizeof(trampoline),
		       &fentry_addr, sizeof(fentry_addr));

#ifdef HAVE_LIBCAPSTONE
		unsigned long dentry_addr = (unsigned long)__dentry__;

		/* jmpq  *0x2(%rip)     # <dentry_addr> */
		memcpy((void *)mdi->trampoline + 16, trampoline, sizeof(trampoline));
		memcpy((void *)mdi->trampoline + 16 + sizeof(trampoline),
		       &dentry_addr, sizeof(dentry_addr));
#endif
	}
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");
}

void mcount_arch_find_module(struct mcount_dynamic_info *mdi)
{
	Elf64_Ehdr ehdr;
	Elf64_Shdr shdr;
	char *mod_name = mdi->mod_name;
	char *names = NULL;
	int fd;
	unsigned i;
	off_t pos;

	mdi->arch = NULL;

	if (*mod_name == '\0')
		mod_name = read_exename();

	fd = open(mod_name, O_RDONLY);
	if (fd < 0)
		pr_err("cannot open %s", mod_name);

	if (read_all(fd, &ehdr, sizeof(ehdr)) < 0)
		goto out;
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG))
		goto out;

	/* read section header name */
	if (pread_all(fd, &shdr, sizeof(shdr),
		      ehdr.e_shoff + (ehdr.e_shstrndx * ehdr.e_shentsize)) < 0)
		goto out;

	names = xmalloc(shdr.sh_size);
	if (pread_all(fd, names, shdr.sh_size, shdr.sh_offset) < 0)
		goto out;

	pos = ehdr.e_shoff;
	for (i = 0; i < ehdr.e_shnum; i++, pos += ehdr.e_shentsize) {
		struct arch_dynamic_info *adi;

		if (pread_all(fd, &shdr, sizeof(shdr), pos) < 0)
			goto out;

		if (strcmp(&names[shdr.sh_name], XRAY_SECT))
			continue;

		adi = xmalloc(sizeof(*adi));
		adi->xrmap_count = shdr.sh_size / sizeof(*adi->xrmap);
		adi->xrmap = xmalloc(adi->xrmap_count * sizeof(*adi->xrmap));

		if (pread_all(fd, adi->xrmap, shdr.sh_size, shdr.sh_offset) < 0) {
			free(adi);
			goto out;
		}

		/* handle position independent code */
		if (ehdr.e_type == ET_DYN) {
			struct xray_instr_map *xrmap;

			for (i = 0; i < adi->xrmap_count; i++) {
				xrmap = &adi->xrmap[i];

				xrmap->addr  += mdi->base_addr;
				xrmap->entry += mdi->base_addr;
			}
		}

		mdi->arch = adi;
		break;
	}

out:
	close(fd);
	free(names);
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

static int patch_fentry_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	unsigned char nop1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char nop2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char *insn = (void *)sym->addr;
	unsigned int target_addr;

	/* only support calls to __fentry__ at the beginning */
	if (memcmp(insn, nop1, sizeof(nop1)) &&  /* old pattern */
	    memcmp(insn, nop2, sizeof(nop2))) {  /* new pattern */
		pr_dbg("skip non-applicable functions: %s\n", sym->name);
		return INSTRUMENT_SKIPPED;
	}

	/* get the jump offset to the trampoline */
	target_addr = get_target_addr(mdi, sym->addr);
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

static int patch_xray_func(struct mcount_dynamic_info *mdi, struct sym *sym,
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

static int update_xray_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	unsigned i;
	int ret = -2;
	struct arch_dynamic_info *adi = mdi->arch;
	struct xray_instr_map *xrmap;

	/* xray provides a pair of entry and exit (or more) */
	for (i = 0; i < adi->xrmap_count; i++) {
		xrmap = &adi->xrmap[i];

		if (xrmap->addr < sym->addr || xrmap->addr >= sym->addr + sym->size)
			continue;

		while ((ret = patch_xray_func(mdi, sym, xrmap)) == 0) {
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

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#include <capstone/platform.h>

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

static csh csh_handle;

/* stored original instructions */
struct address_entry {
	uintptr_t addr;
	uintptr_t saved_addr;
	struct list_head list;
};
static LIST_HEAD(address_list);

uintptr_t find_original_code(unsigned long addr)
{
	struct address_entry* entry;
	uintptr_t patched_addr, ret_addr = 0;

	patched_addr = addr - CALL_INSN_SIZE;

	list_for_each_entry(entry, &address_list, list) {
		if (entry->addr == patched_addr) {
			ret_addr = entry->saved_addr;
			break;
		}
	}
	return ret_addr;
}

/* get relative offset from address to dentry trampoline */
static unsigned long get_dentry_addr(struct mcount_dynamic_info *mdi,
				     unsigned long addr)
{
	return mdi->trampoline - (addr + CALL_INSN_SIZE) + 16;
}

void mcount_disasm_init(void)
{
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &csh_handle) != CS_ERR_OK) {
		pr_dbg("failed to init Capstone disasm engine\n");
		return;
	}

	cs_option(csh_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

void mcount_disasm_finish(void)
{
	cs_close(&csh_handle);
}

#define CODE_PATCH_OK  0x1
#define CODE_PATCH_NO  0x2

/*
 * check whether the instruction can be executed regardless of its location.
 * TODO: this function does not completed, need more classify the cases.
 */
static int check_instrumentable(csh ud, cs_insn *ins)
{
	int i, n;
	csh handle = ud;
	cs_x86 *x86;
	cs_detail *detail;
	bool jmp_or_call = false;
	int status = CODE_PATCH_NO;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (ins->detail == NULL)
		return status;

	detail = ins->detail;

	/* print the groups this instruction belong to */
	if (detail->groups_count > 0) {
		for (n = 0; n < detail->groups_count; n++) {
			pr_dbg3("Instr Groups: %s\n",
				cs_group_name(handle, detail->groups[n]));

			if (detail->groups[n] == X86_GRP_CALL ||
			    detail->groups[n] == X86_GRP_JUMP) {
				jmp_or_call = true;
			}
		}
	}

	x86 = &(ins->detail->x86);

	/* no operand */
	if (!x86->op_count)
		return CODE_PATCH_NO;

	pr_dbg3("0x%" PRIx64 "[%02d]:\t%s\t%s\n",
		ins->address, ins->size, ins->mnemonic, ins->op_str);

	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
		case X86_OP_REG:
			status = CODE_PATCH_OK;
			break;
		case X86_OP_IMM:
			if (jmp_or_call)
				return CODE_PATCH_NO;
			status = CODE_PATCH_OK;
			break;
		case X86_OP_MEM:
			// temporary till discover possibility of x86 instructions.
			status = CODE_PATCH_NO;

			if (op->mem.segment != X86_REG_INVALID)
				pr_dbg3("\t\t\toperands[%u].mem.segment: REG = %s\n",
					i, cs_reg_name(handle, op->mem.segment));
			if (op->mem.base != X86_REG_INVALID)
				pr_dbg3("\t\t\toperands[%u].mem.base: REG = %s\n",
					i, cs_reg_name(handle, op->mem.base));
			if (op->mem.index != X86_REG_INVALID)
				pr_dbg3("\t\t\toperands[%u].mem.index: REG = %s\n",
					i, cs_reg_name(handle, op->mem.index));
			if (op->mem.scale != 1)
				pr_dbg3("\t\t\toperands[%u].mem.scale: %u\n",
					i, op->mem.scale);
			if (op->mem.disp != 0)
				pr_dbg3("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n",
					i, op->mem.disp);
			return status;
		default:
			break;
		}
	}
	return status;
}

/*
 * Patch the instruction to the address as given for arguments.
 */
static unsigned char * patch_code(uintptr_t addr, uint32_t target_addr,
				  uint32_t origin_code_size)
{
	unsigned char *stored_addr, *origin_code_addr;
	unsigned char call_insn[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 };
	unsigned char jmp_insn[] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00 };

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
	uint32_t store_code_size = origin_code_size + sizeof(jmp_insn) +
				   sizeof(long);

	/*
	 * XXX: allocate memory to store the original instructions
	 * and make them to executable.
	 *
	 * FIXME: use mmap() instead
	 */
	stored_addr = xmalloc(store_code_size);
	memset(stored_addr, 0, store_code_size);

	mprotect((void *)ROUND_DOWN((unsigned long)stored_addr, 4096),
		 store_code_size + ((unsigned long)stored_addr & 0xfff),
		 PROT_READ | PROT_WRITE | PROT_EXEC);

	/* return address */
	origin_code_addr = (void *)addr + origin_code_size;

	memcpy(stored_addr, (void *)addr, origin_code_size);
	memcpy(stored_addr + origin_code_size, jmp_insn, JMP_INSN_SIZE);
	memcpy(stored_addr + origin_code_size + JMP_INSN_SIZE,
	       &origin_code_addr, sizeof(long));

	/* patch address */
	origin_code_addr = (void *)addr;

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
	       origin_code_size - CALL_INSN_SIZE);

	/* flush icache so that cpu can execute the new insn */
	__builtin___clear_cache(origin_code_addr,
				origin_code_addr + origin_code_size);

	return stored_addr;
}

void do_instrument(struct mcount_dynamic_info *mdi,
		   uintptr_t addr, uint32_t insn_size)
{
	uint32_t target_addr;
	struct address_entry* el;
	unsigned char *stored_code;

	/* get the jump offset to the trampoline */
	target_addr = get_dentry_addr(mdi, addr);

	stored_code = patch_code(addr, target_addr, insn_size);
	if (stored_code) {
		// TODO : keep and manage stored_code chunks.
		el = malloc(sizeof(*el));
		el->addr = addr;
		el->saved_addr = (uintptr_t)stored_code;
		list_add_tail(&el->list, &address_list);
	}
}


static int check_instrument_size(uintptr_t addr, uint32_t size)
{
	cs_insn *insn;
	uint32_t code_size = 0, count = 0, i;

	count = cs_disasm(csh_handle, (unsigned char*)addr, size, addr, 0, &insn);

	for (i = 0; i < count; i++) {
		if (check_instrumentable(csh_handle, &insn[i]) == CODE_PATCH_NO) {
			pr_dbg3("instruction not supported: %s\t %s\n",
				insn[i].mnemonic, insn[i].op_str);
			return INSTRUMENT_FAILED;
		}

		code_size += insn[i].size;
		if (code_size >= CALL_INSN_SIZE)
			return code_size;
	}

	return INSTRUMENT_FAILED;
}

static int patch_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	int instr_size;

	instr_size = check_instrument_size(sym->addr, sym->size);
	if (instr_size < CALL_INSN_SIZE)
		return instr_size;

	pr_dbg2("patch normal func: %s (patch size: %d)\n",
		sym->name, instr_size);

	do_instrument(mdi, sym->addr, instr_size);
	return INSTRUMENT_SUCCESS;
}

#endif /* HAVE_LIBCAPSTONE */

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	int result;

	if (mdi->arch) {
		return update_xray_func(mdi, sym);
	}
	else {
		result = patch_fentry_func(mdi, sym);
#ifdef HAVE_LIBCAPSTONE
		// function prolog does not match with nops instruction.
		if (result == INSTRUMENT_SKIPPED) {
			if (sym->size < CALL_INSN_SIZE)
				return result;

			return patch_normal_func(mdi, sym);
		}
#endif
		return result;
	}
}
