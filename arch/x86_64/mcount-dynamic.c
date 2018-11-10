#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "mcount-arch.h"
#include "libmcount/dynamic.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define PAGE_SIZE  4096
#define XRAY_SECT  "xray_instr_map"

/* target instrumentation function it needs to call */
extern void __fentry__(void);
extern void __xray_entry(void);
extern void __xray_exit(void);
extern void __dentry__(void);

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
					PROT_READ | PROT_WRITE,
		     			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
					-1, 0);

		if (trampoline_check == MAP_FAILED)
			pr_err("failed to mmap trampoline for setup");
	}

	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_READ | PROT_WRITE)) {
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

#define CALL_INSN_SIZE 5

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
		return -1;

	if (xrmap->type == 0) {  /* ENTRY */
		if (memcmp(func, entry_insn, sizeof(entry_insn)))
			return -1;

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
			return -1;

		target_addr = mdi->trampoline + 16 - (xrmap->addr + 5);

		memcpy(func + 5, nop4, sizeof(nop4));

		/* need to write patch_word atomically */
		patch.bytes[0] = 0xe9;  /* "jmp" insn */
		memcpy(&patch.bytes[1], &target_addr, sizeof(target_addr));
		memcpy(&patch.bytes[5], nop4, 3);

		memcpy(func, patch.bytes, sizeof(patch));
	}

	pr_dbg("update function '%s' dynamically to call xray functions\n",
		sym->name);
	return 0;
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

/* include for using capstone */
#include <inttypes.h>
#include <capstone/capstone.h>
#include <capstone/platform.h>

// Change Memory protection flags.
// to allow execute permission to stored code chunk.
#define SETRWX(addr, len)   mprotect((void*)((addr) &~ 0xFFF),\
		(len) + ((addr) - ((addr) &~ 0xFFF)),\
		PROT_READ | PROT_EXEC | PROT_WRITE)
#define SETROX(addr, len)   mprotect((void*)((addr) &~ 0xFFF),\
		(len) + ((addr) - ((addr) &~ 0xFFF)),\
		PROT_READ | PROT_EXEC)

// for Capstone
csh csh_handle;
extern cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle);

extern int debug;

// store original instructions.
struct address_entry {
	uintptr_t addr;
	uintptr_t saved_addr;
	struct list_head list;
};
static LIST_HEAD(address_list);

// This code to be injected will used to call the __dentry__
// by calling the trampoline.
static unsigned char g_patch_code[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
static const unsigned int g_patch_code_size = sizeof(g_patch_code);

// This jump code will used in stored code to return original code flow.
// jmpq *0x0(rip)
static unsigned char g_jmp_insn[] ={0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};

typedef unsigned char* puchar;
typedef char* pchar;

uintptr_t mcount_find_origin_code_addr(uintptr_t addr)
{
	uintptr_t patched_addr, ret_addr = 0;
	patched_addr = addr - g_patch_code_size;
	struct address_entry* entry;
	list_for_each_entry(entry, &address_list, list) {
		if (entry->addr == patched_addr) {
			pr_dbg2("found patched address : %lx\n", entry->addr);
			ret_addr = entry->saved_addr;
			break;
		}
	}
	pr_dbg2("Address : %lx %lx\n", entry->addr, entry->saved_addr);
	return ret_addr;
}

static unsigned long get_trampoline_addr(struct mcount_dynamic_info *mdi,
		unsigned long addr, unsigned int offset)
{
	while (mdi) {
		if (mdi->text_addr <= addr && addr < mdi->text_addr + mdi->text_size)
			return mdi->trampoline - (addr + CALL_INSN_SIZE) + offset;

		mdi = mdi->next;
	}
	return 0;
}

// get relative offset from address to dentry trampoline.
static unsigned long get_dentry_rel_trampoline_addr(struct mcount_dynamic_info *mdi,
							 unsigned long addr)
{
	return get_trampoline_addr(mdi, addr, 16);
}

/*
 * Initializing capston the disassembler.
 */
int disassembler_init()
{
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &csh_handle) != CS_ERR_OK) {
		pr_dbg("Create Capstone Failed.\n");
		return -1;
	}
	cs_option(csh_handle, CS_OPT_DETAIL, CS_OPT_ON);
	pr_dbg("Create Capston Success.\n");
	return 0;
}

void disassembler_fini()
{
	cs_close(&csh_handle);
}

void print_disassemble(uintptr_t address, uint32_t size)
{
	cs_insn *insn;
	int count = cs_disasm(csh_handle, (unsigned char*)address, size, address, 0, &insn);
	pr_dbg2("============  DISASM ================\n");
	int j;
	for(j = 0;j < count;j++) {
		pr_dbg2("0x%"PRIx64"[%02d]:%s %s\n", insn[j].address,
			insn[j].size, insn[j].mnemonic, insn[j].op_str);
	}
	cs_free(insn, count);
}

/*
 * check whether the instruction can be executed regardless of its location.
 * TODO: this function does not completed, need more classify the cases.
 */
int check_instrumentable(csh ud, cs_mode mode, cs_insn *ins)
{
	int i, n;
	csh handle = ud;
	cs_x86 *x86;
	cs_detail *detail;
	bool CALLnJMP = false;

	// default.
	int status = CODE_PATCH_NO;

	// detail can be NULL on "data" instruction
	// if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return status;

	detail = ins->detail;

	// print the groups this instruction belong to
	if (detail->groups_count > 0) {
		for (n = 0; n < detail->groups_count; n++) {
			pr_dbg2("Instr Groups: %s\n", cs_group_name(handle, detail->groups[n]));
			if (detail->groups[n] == X86_GRP_CALL
				|| detail->groups[n] == X86_GRP_JUMP) {
				CALLnJMP = true;
			}
		}
	}

	x86 = &(ins->detail->x86);

	// there is no operand.
	if (!x86->op_count)
		return CODE_PATCH_NO;

	pr_dbg2("0x%" PRIx64 "[%02d]:\t%s\t%s\n",
		ins->address, ins->size, ins->mnemonic, ins->op_str);

	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
			case X86_OP_REG:
				status = CODE_PATCH_OK;
				pr_dbg2("\t\toperands[%u].type: REG = %s\n",
					i, cs_reg_name(handle, op->reg));
				break;
			case X86_OP_IMM:
				if (CALLnJMP) {
					status = CODE_PATCH_NO;
					return status;
				} else {
					status = CODE_PATCH_OK;
				}
				pr_dbg2("\t\toperands[%u].type: IMM = 0x%"
				        PRIx64 "\n", i, op->imm);
				break;
			case X86_OP_MEM:
				// temporary till discover possibility of x86 instructions.
				status = CODE_PATCH_NO;
				pr_dbg2("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.segment != X86_REG_INVALID)
					pr_dbg2("\t\t\toperands[%u].mem.segment: REG = %s\n",
						i, cs_reg_name(handle, op->mem.segment));
				if (op->mem.base != X86_REG_INVALID)
					pr_dbg2("\t\t\toperands[%u].mem.base: REG = %s\n",
						i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					pr_dbg2("\t\t\toperands[%u].mem.index: REG = %s\n",
						i, cs_reg_name(handle, op->mem.index));
				if (op->mem.scale != 1)
					pr_dbg2("\t\t\toperands[%u].mem.scale: %u\n",
						i, op->mem.scale);
				if (op->mem.disp != 0)
					pr_dbg2("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n",
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
puchar patch_code(uintptr_t addr, uint32_t target_addr,
		  uint32_t origin_code_size)
{
	puchar stored_addr, origin_code_addr;
	puchar ptr = (puchar)&target_addr;

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
	uint32_t store_code_size = origin_code_size + sizeof(g_jmp_insn)
				   + sizeof(long);

	// build the instrumentation instruction.
	uint32_t i;
	for(i=0;i < 4;i++) {
		// E8 XX XX XX XX ; Relative call to trampoline
		g_patch_code[1 + i] = *(ptr+i);
	}

	// allocate memory to store the original instructions
	// and make them to executable.
	stored_addr = (puchar)xmalloc(store_code_size);
	memset((void *)stored_addr, 0, store_code_size);
	SETRWX((uintptr_t)stored_addr, store_code_size);

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
	origin_code_addr = (puchar)addr;
	for (i=0;i < origin_code_size;i++) {
		stored_addr[i] = origin_code_addr[i];
		if (i > g_patch_code_size -1) {
			pr_dbg2("patching... : %x to %x \n",
				origin_code_addr[i], 0x90);
			origin_code_addr[i] = 0x90;
		} else {
			pr_dbg2("patching... : %x to %x \n",
				origin_code_addr[i], g_patch_code[i]);
			origin_code_addr[i] = g_patch_code[i];
		}
	}
	/*
	 * we build jump block in here.
	 *  ----------------------
	 *  | [jmpq    *0x0(rip) |
	 *  ----------------------
	 */
	stored_addr[origin_code_size+0] = g_jmp_insn[0];
	stored_addr[origin_code_size+1] = g_jmp_insn[1];
	stored_addr[origin_code_size+2] = g_jmp_insn[2];
	stored_addr[origin_code_size+3] = g_jmp_insn[3];
	stored_addr[origin_code_size+4] = g_jmp_insn[4];
	stored_addr[origin_code_size+5] = g_jmp_insn[5];
	/*
	 *  append return address.
	 *  the 'return address' mean the last address that was overwritten.
	 *  ----------------------
	 *  | [Return   address] |
	 *  ----------------------
	 * [example]
	 *  f1cff6:	jmp qword ptr [rip]
	 *  f1cffc:	QW 0x0000000000400555 << return address
	 *
	 *  ...
	 *  40054c[05]:call 0x400ff0
	 *  400551[01]:nop
	 *  400552[01]:nop
	 *  400553[01]:nop
	 *  400554[01]:nop
	 *  400555		<< jump to here
	 */
	*((uintptr_t *)(&stored_addr[origin_code_size+6])) =
			(uintptr_t)&origin_code_addr[origin_code_size];

	pr_dbg2("RETURN ADDRESS : %llx\n", &origin_code_addr[origin_code_size]);
	if (debug) {
		print_disassemble((uintptr_t)stored_addr, store_code_size);
		print_disassemble((uintptr_t)origin_code_addr, origin_code_size);
	}
	return stored_addr;
}

/*
 *
 */
void do_instrument(struct mcount_dynamic_info *mdi,
		   uintptr_t addr, uint32_t insn_size)
{
	uint32_t target_addr;
	struct address_entry* el;
	puchar stored_code;

	/* get the jump offset to the trampoline */
	target_addr = get_dentry_rel_trampoline_addr(mdi, addr);
	pr_dbg("Use Trampoline address : %llx\n", target_addr);
	stored_code = patch_code(addr, target_addr, insn_size);
	if (stored_code) {
		// TODO : keep and manage stored_code chunks.
		pr_dbg("Keep original instruction [%03d]: %llx\n",
			insn_size, (uintptr_t)stored_code);
		el = malloc(sizeof(struct address_entry));
		el->addr = addr;
		el->saved_addr = (uintptr_t)stored_code;
		list_add_tail(&el->list, &address_list);
	} else {
		// TODO : we need error handling here.
		pr_err("GRRRRRRRRRRRRRRRRRRRRR......\n");
	}
}


static int check_instrument_size(uintptr_t addr, uint32_t size)
{
	cs_insn *insn;
	uint32_t code_size = 0, count = 0, i;

	count = cs_disasm(csh_handle, (unsigned char*)addr, size, addr, 0, &insn);

	for(i = 0;i < count;i++) {
		int res = check_instrumentable(csh_handle, CS_MODE_64, &insn[i]);
		if (res & CODE_PATCH_NO) {
			pr_dbg2("\tThe instruction not supported : %s\t %s\n",
				insn[i].mnemonic, insn[i].op_str);
			return INSTRUMENT_SKIPED;
		}
		code_size += insn[i].size;
		if (code_size >= g_patch_code_size) {
			break;
		}
	}

	return code_size;
}

static int instrument(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	int instr_size = 0;
	instr_size = check_instrument_size(sym->addr, sym->size);
	pr_dbg2("%s - patch instruction, size of %d\n", sym->name, instr_size);
	if (instr_size > 0) {
		do_instrument(mdi, sym->addr, instr_size);
		return INSTRUMENT_SUCCESS;
	} else if (instr_size == 0) {
		return INSTRUMENT_SKIPED;
	}

	return instr_size;
}

#endif //capstone

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
		if (result & INSTRUMENT_SKIPED) {
			if (!strcmp(sym->name, "_start")) {
				pr_dbg2("SKIP _start\n");
				return INSTRUMENT_SKIPED;
			}
			if (!strcmp(sym->name, "__libc_csu_init")) {
				pr_dbg2("SKIP %s\n", sym->name);
				return INSTRUMENT_SKIPED;
			}
			if (sym->size < g_patch_code_size)
				return INSTRUMENT_SKIPED;

			pr_dbg("Try to instrumentation : %s\n", sym->name);
			return instrument(mdi, sym);
		}
#endif
		return result;
	}
}
