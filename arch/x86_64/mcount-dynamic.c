#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "mcount-arch.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define PAGE_SIZE  4096
#define PAGE_MASK  (~(PAGE_SIZE-1))
#define XRAY_SECT  "xray_instr_map"

#define CALL_INSN_SIZE  5
#define JMP_INSN_SIZE   6

#define REG(name) REG_R##name

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
	DYNAMIC_FENTRY,
	DYNAMIC_XRAY,
};

struct arch_dynamic_info {
	enum mcount_x86_dynamic_type	type;
	struct xray_instr_map		*xrmap;
	unsigned			xrmap_count;
	struct list_head		bad_targets;  /* for non-local jumps */
};

static struct rb_root redirection_tree = RB_ROOT;

#ifdef HAVE_LIBCAPSTONE
void install_trap_handler()
{
	struct sigaction act;

	sigaction(SIGTRAP, NULL, &act); /* get current trap handler */
	/*
	* reuse current trap handler and set mcount_dynamic_trap as the
	* master trap handler 
	*/
	sigaction(SIGTRAP, &act, NULL);
}
#endif

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

	if (mprotect((void *)mdi->text_addr, mdi->text_size,
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
	else if (adi->type == DYNAMIC_FENTRY) {
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
		
		install_trap_handler();
#endif
	}
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect((void *)mdi->text_addr, mdi->text_size, PROT_EXEC))
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

void mcount_arch_find_module(struct mcount_dynamic_info *mdi,
			     struct symtab *symtab)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	struct arch_dynamic_info *adi;
	const char *adi_type_names[] = { "none", "fentry", "xray" };
	unsigned char fentry_patt1[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char fentry_patt2[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	int num_check = 5;
	unsigned i = 0;

	adi = xzalloc(sizeof(*adi));  /* DYNAMIC_NONE */
	INIT_LIST_HEAD(&adi->bad_targets);

	if (elf_init(mdi->map->libname, &elf) < 0)
		goto out;

	elf_for_each_shdr(&elf, &iter) {
		char *shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (!strcmp(shstr, XRAY_SECT)) {
			adi->type = DYNAMIC_XRAY;
			read_xray_map(adi, &elf, &iter, mdi->base_addr);
			goto out;
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
		if (!memcmp(code_addr, fentry_patt1, CALL_INSN_SIZE) ||
		    !memcmp(code_addr, fentry_patt2, CALL_INSN_SIZE)) {
			adi->type = DYNAMIC_FENTRY;
			break;
		}

		if (num_check-- == 0)
			break;
	}

out:
	pr_dbg("dynamic patch type: %d (%s)\n", adi->type,
	       adi_type_names[adi->type]);

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
		       uintptr_t addr, uint32_t origin_code_size)
{
	void *origin_code_addr;
	unsigned char call_insn[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 };
	uint32_t target_addr = get_target_addr(mdi, addr);

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
}

struct dynamic_bad_symbol * find_bad_jump(struct mcount_dynamic_info *mdi,
					  unsigned long addr)
{
	struct sym *sym;
	struct arch_dynamic_info *adi = mdi->arch;
	struct dynamic_bad_symbol *badsym;

	sym = find_sym(&mdi->map->mod->symtab, addr - mdi->map->start);
	if (sym == NULL)
		return NULL;

	list_for_each_entry(badsym, &adi->bad_targets, list) {
		if (badsym->sym == sym)
			return badsym;
	}

	return NULL;
}

bool add_bad_jump(struct mcount_dynamic_info *mdi, unsigned long callsite,
		  unsigned long target)
{
	struct sym *sym;
	struct arch_dynamic_info *adi = mdi->arch;
	struct dynamic_bad_symbol *badsym;

	if (find_bad_jump(mdi, target))
		return true;

	sym = find_sym(&mdi->map->mod->symtab, target - mdi->map->start);
	if (sym == NULL)
		return true;

	/* only care about jumps to the middle of a function */
	if (sym->addr + mdi->map->start == target)
		return false;

	pr_dbg2("bad jump: %s:%lx to %lx\n", sym ? sym->name : "<unknown>",
		callsite - mdi->map->start, target - mdi->map->start);

	badsym = xmalloc(sizeof(*badsym));
	badsym->sym = sym;

	list_add_tail(&badsym->list, &adi->bad_targets);
	return true;
}

static int patch_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			     struct mcount_disasm_engine *disasm)
{
	int instr_size;
	uint8_t jmp_insn[14] = { 0xff, 0x25, };
	uint64_t jmp_target;
	struct mcount_orig_insn *orig;
	uint64_t sym_addr = sym->addr + mdi->map->start;

	instr_size = disasm_check_insns(disasm, mdi, sym);
	if (instr_size < CALL_INSN_SIZE)
		return instr_size;

	pr_dbg2("patch normal func: %s (patch size: %d)\n",
		sym->name, instr_size);

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
	jmp_target = sym_addr + instr_size;
	memcpy(jmp_insn + JMP_INSN_SIZE, &jmp_target, sizeof(jmp_target));
	orig = mcount_save_code(sym_addr , instr_size,
				jmp_insn, sizeof(jmp_insn));
	/* make sure orig->addr same as when called from __dentry__ */
	orig->addr += CALL_INSN_SIZE;

	patch_code(mdi, sym_addr, instr_size);
	return INSTRUMENT_SUCCESS;
}

static struct dynamic_mem_region * read_mem_regions()
{
	FILE *fp;
	char buf[PATH_MAX];

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL)
		return NULL;

	struct dynamic_mem_region *ret = xzalloc(sizeof(struct dynamic_mem_region));
	struct dynamic_mem_region *regions = ret;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *p = buf, *next;
		unsigned long start, end;

		start = strtoul(p, &next, 16);
		if (*next != '-')
			pr_warn("invalid /proc/map format\n");

		p = next + 1;
		end = strtoul(p, &next, 16);

		regions->range.start = start;
		regions->range.end = end;
		regions->next = xzalloc(sizeof(struct dynamic_mem_region));
		regions = regions->next;
	}
	regions->next = NULL;

	fclose(fp);
	return ret;
}

static void destroy_mem_regions(struct dynamic_mem_region *regions)
{
	struct dynamic_mem_region *current = regions;
	struct dynamic_mem_region *previous;

	while(current != NULL) {
		previous = current;
		current = current->next; 
		free(previous);
	}
}

/*
 * Find the memory regions that are not mapped in the process address space.
 */
static struct dynamic_mem_region * get_free_mem_regions(struct dynamic_mem_region *mapped_mem_reg)
{
	struct dynamic_mem_region *ret = xzalloc(sizeof(struct dynamic_mem_region));
	struct dynamic_mem_region *mapped_reg = mapped_mem_reg;
	struct dynamic_mem_region *free_reg = ret;

	if(mapped_reg->range.start != 0){
		free_reg->range.start = 0;
		free_reg->range.end = mapped_reg->range.start;
	}

	while(mapped_reg != NULL 
			&& mapped_reg->next != NULL 
			&& mapped_reg->next->next != NULL) 
	{

		if(mapped_reg->range.end == mapped_reg->next->range.start) {
			mapped_reg = mapped_reg->next;
			continue;
		}
		free_reg->next = xzalloc(sizeof(struct dynamic_mem_region));
		free_reg = free_reg->next;

		free_reg->range.start = mapped_reg->range.end;
		mapped_reg = mapped_reg->next;
		free_reg->range.end = mapped_reg->range.start;
	}

	if(mapped_reg->range.end != ULONG_MAX) {
		free_reg->next = xzalloc(sizeof(struct dynamic_mem_region));
		free_reg = free_reg->next;

		free_reg->range.start = mapped_reg->range.end;
		free_reg->range.end = ULONG_MAX;
	}
	free_reg->next = NULL;
	
	return ret;
}

uintptr_t add_saturation(uintptr_t x, int32_t y)
{
    if(y > 0 && ULONG_MAX - y < x)
        return ULONG_MAX;
    else if(y < 0 &&  (uintptr_t)(0 - y) > x)
        return 0;
    else
        return x + y;
}

static int32_t constaint_to_integer(struct dynamic_constraint dc, uint8_t val)
{
	uint8_t ret[4];

	for(int i = 0; i < 4; i++)
		ret[i] = dc.constraint[i] ? dc.constraint[i] : val;

	return ret[0] + (ret[1] << 8) + (ret[2] << 16) + (ret[3] << 24);
}

struct mcount_address_range intersect(struct mcount_address_range range1, 
				struct mcount_address_range range2)
{
	uintptr_t min = max(range1.start, range2.start);
	uintptr_t max = min(range1.end, range2.end);
	struct mcount_address_range range = {0, 0};

	if (min < max) {
		range.start = min;
		range.end = max;
	}	

	return range;
}

struct mcount_address_range constraint_to_range(struct dynamic_constraint dc, uintptr_t sym_addr)
{
	int32_t start = constaint_to_integer(dc, 0x00);
	int32_t end = constaint_to_integer(dc, 0xff);
	struct mcount_address_range ret;
	
	/* if MSB of constraint is zero, start will be positive and end negative */
	if(!dc.constraint[3]){
		start |= (1 << 31);
		end &= (0 << 31);
	}

	/* we add to saturation for overflows*/
	ret.start = add_saturation(sym_addr, start);
	ret.end = add_saturation(sym_addr, end);

	return ret;
}

/*
 * Find a free memory range that intersect with the range of the constraint.
 */
static uintptr_t find_free_address(struct dynamic_constraint dc, uintptr_t sym_addr, int size) 
{
	struct dynamic_mem_region *mapped_reg;
	struct dynamic_mem_region *free_reg;
	struct dynamic_mem_region *reg;
	struct mcount_address_range inter_range;
	struct mcount_address_range cond_range = constraint_to_range(dc, sym_addr);
	uintptr_t ret = 0;
	int64_t offset;

	mapped_reg = read_mem_regions();
	if(mapped_reg == NULL)
		return ret;
	free_reg = get_free_mem_regions(mapped_reg);

	reg = free_reg;
	while(reg != NULL) {
		inter_range = intersect(reg->range, cond_range);
		pr_dbg3("search free address in range: [%p, %p] intersect [%p, %p] = [%p, %p] \n", reg->range.start,
				reg->range.end, cond_range.start, cond_range.end, inter_range.start, inter_range.end);

		if(inter_range.start != 0 && inter_range.end != 0) {
			offset = inter_range.start - sym_addr;
			if(offset < INT_MIN || offset > INT_MAX) 
				goto next;

			for(int i = 0; i < 4; i++)
				((uint8_t*) &offset)[i] = dc.constraint[i] ? dc.constraint[i] : ((uint8_t*) &offset)[i] ;
				
			if( (sym_addr + (int32_t)offset) >= inter_range.start 
					&& (sym_addr + (int32_t)offset + size) <= inter_range.end)
			{
				ret = sym_addr + (int32_t)offset;
				pr_dbg3("found free address: %p \n", ret);
				break;
			}			
		}
		next:
		reg = reg->next; 
	}

	destroy_mem_regions(mapped_reg);
	destroy_mem_regions(free_reg);
	return ret;
}

static mcount_redirection *lookup_redirection(struct rb_root *root,
					    unsigned long addr, bool create)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	mcount_redirection *iter;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, mcount_redirection, node);

		if (iter->addr == addr)
			return iter;

		if (iter->addr > addr)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	if (!create)
		return NULL;

	iter = xmalloc(sizeof(*iter));
	iter->addr = addr;

	rb_link_node(&iter->node, parent, p);
	rb_insert_color(&iter->node, root);
	return iter;
}

uintptr_t setup_trampoline_constraint(struct dynamic_constraint dc, uintptr_t addr)
{
	void *trampoline_check;
	uintptr_t first_page;
	uintptr_t last_page;
	unsigned char trampoline[] = { 0xff, 0x25, 0x02, 0x00, 0x00, 0x00, 0xcc, 0xcc };
	unsigned long dentry_addr = (unsigned long)__dentry__;
	uintptr_t free_addr = find_free_address(dc, addr + CALL_INSN_SIZE, PAGE_SIZE);
	if(!free_addr)
		return free_addr;

	first_page = free_addr & PAGE_MASK;
	last_page = (free_addr + sizeof(trampoline) * 2 - 1) & PAGE_MASK;

	/* TODO: keep track of mapped pages and reuse them to increase the success rate */

	/* always mmap first page */
	trampoline_check = mmap((void *)first_page, PAGE_SIZE,
					PROT_READ | PROT_WRITE | PROT_EXEC,
		     			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
					-1, 0);
	if (trampoline_check == MAP_FAILED)
		pr_err("failed to mmap trampoline for setup");

	/* mmap second page if needed */
	if(first_page != last_page) {
		trampoline_check = mmap((void *)last_page, PAGE_SIZE,
						PROT_READ | PROT_WRITE | PROT_EXEC,
							MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
						-1, 0);
		if (trampoline_check == MAP_FAILED)
			pr_err("failed to mmap trampoline for setup");
	}

	memcpy((void *)free_addr, trampoline, sizeof(trampoline));
	memcpy((void *)free_addr + sizeof(trampoline),
			&dentry_addr, sizeof(dentry_addr));

	return free_addr;
}

static int patch_code_constraint(struct dynamic_constraint dc, uintptr_t addr, struct mcount_orig_insn *orig)
{
	void *origin_code_addr;
	unsigned char call_insn[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 };
	int64_t target_addr;
	uintptr_t free_addr;
	mcount_redirection *red;
	
	free_addr = setup_trampoline_constraint(dc, addr);
	if(!free_addr)
		return INSTRUMENT_FAILED;

	target_addr = free_addr - (addr + CALL_INSN_SIZE);
	if(target_addr < INT_MIN || target_addr > INT_MAX)
		return INSTRUMENT_FAILED;

	/* patch address */
	origin_code_addr = (void *)addr;

	/* build the instrumentation instruction */
	memcpy(&call_insn[1], &target_addr, CALL_INSN_SIZE - 1);

	for(int i = 0; i < 4; i++){
		if(dc.constraint[i]){
			red = lookup_redirection(&redirection_tree, addr + 1 + i, true);
			red->insn = orig->insn + 1 + i;
		}
	}

	memcpy(origin_code_addr, call_insn, CALL_INSN_SIZE);
	memset(origin_code_addr + CALL_INSN_SIZE, 0x90,  /* NOP */
	       dc.instr_size - CALL_INSN_SIZE);

	/* flush icache so that cpu can execute the new insn */
	__builtin___clear_cache(origin_code_addr,
				origin_code_addr + dc.instr_size);

	pr_dbg3("instrument address: %p, offset: %i, instr: %X%X%X%X%X \n", addr, target_addr, 
			call_insn[0], call_insn[1], call_insn[2], call_insn[3], call_insn[4]);
			 
	return INSTRUMENT_SUCCESS;
}

/*
 * To safely patch unsupported functions that jumps or may jump to their
 * prologues, we embed an illegal instruction like "int3" in 
 * offset of the call. The illegal instruction should be embedded
 * in the head of every overwritten instruction, but the first one (it will be
 * set to the call opcode).
 * 
 * [example]:
 * In this example, the first instruction (push rbp) will be replaced by the call opcode. The second
 * byte is the head of the first overwritten instruction, and it should be replaced by "int3".
 * The 3rd and 4th bytes can be set to whatever value. The 5th byte is the head of the 
 * second overwritten instruction, thus it should be replaced with "int3". The remaining bytes will
 * be replaced by a "nop".
 * Note: "int3" opcode is "0xCC"
 *
 *   dynamic: 0x19e98b0[01]:push rbp
 *   dynamic: 0x19e98b1[03]:mov rbp, rsp
 *   dynamic: 0x19e98b4[05]:mov edi, 0x4005f4
 *
 *   dynamic: 0x40054c[05]:call 0xCC????CC
 *   dynamic: 0x400551[01]:nop
 *   dynamic: 0x400552[01]:nop
 *   dynamic: 0x400553[01]:nop
 *   dynamic: 0x400554[01]:nop  
 *  
 * The role of "int3" is to redirect the thread that step into it to the out of line 
 * instructions so that he could resume his execution without executing random instructions.
 * 
 * This instrumentation technique doesn't restrain to function entry and exit
 * it could also be used to instrument an arbitrary location in a function.
 * 
 * Since we need to respect a constraint made from the "int3" in the offset of
 * the call, we intersect free memory regions and the reachable range
 * with the offset, to find a suitable place to put the trampoline in.
 * 
 * [example]:
 * 
 *   mapped region      free region      mapped region     free region        mapped region
 *      [a, b]             [c, d]           [e, f]           [g, h]              [i, j]
 * 							 ^				   ^				^
 * 					  [x - 0x00CCCC00		   x		 x + 0xFFCCCCFF] 
 *  
 * let's suppose the symbol we instrument starts at the address x that falls in the range [e, f]
 * and the constraint we should respect is "?? CC CC ??". the reachable range 
 * is [x - 0x00CCCC00, x + 0xFFCCCCFF]. Any free range that intersect with our reachable range 
 * is potentially  suitable for the trampoline. The intersection of the free range [c, d] with
 * the reachable range gives [x - 0x00CCCC00, d]. if the size of the resulted range is smaller than
 * the trampoline size, we move on to the next intersection. 
 * 
 * To make sure that the techniques works even when the user override our dynamic
 * trap handler, we hook sigaction() to make sure that our trap handler always get 
 * the trap signal first and then dispatch it to the user trap handler if needed.
 *  
 */
static int patch_unsupported_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			     struct mcount_disasm_engine *disasm)
{
	uint8_t jmp_insn[14] = { 0xff, 0x25, };
	uint64_t jmp_target;
	struct mcount_orig_insn *orig;
	uint64_t sym_addr = sym->addr + mdi->map->start;
	int ret = INSTRUMENT_FAILED;

	struct dynamic_constraint dc = create_constraint(disasm, mdi, sym);
	if (dc.instr_size < CALL_INSN_SIZE)
		return dc.instr_size;

	jmp_target = sym_addr + dc.instr_size;
	memcpy(jmp_insn + JMP_INSN_SIZE, &jmp_target, sizeof(jmp_target));
	orig = mcount_save_code(sym_addr , dc.instr_size,
				jmp_insn, sizeof(jmp_insn));
	/* make sure orig->addr same as when called from __dentry__ */
	orig->addr += CALL_INSN_SIZE;

	ret = patch_code_constraint(dc, sym_addr, orig);
	if(ret == INSTRUMENT_SUCCESS){
		pr_dbg2("patch unsupported func: %s (patch size: %d)\n",
			sym->name, dc.instr_size);
	}

	return ret;
}

#ifdef HAVE_LIBCAPSTONE
void mcount_dynamic_trap(int sig, siginfo_t* info, void* _ctx)
{
	mcount_redirection *red;
	/* (%rip) - 1 is the addr of the trap instruction */
	unsigned long addr = ((ucontext_t*)_ctx)->uc_mcontext.gregs[REG(IP)] - 1;

	red = lookup_redirection(&redirection_tree, addr, false);
	if (red == NULL){
		/* raise sigaction and run normal handler */
		if(mcount_user_handler.sa_handler || mcount_user_handler.sa_sigaction)
		{
			if(mcount_user_handler.sa_flags & SA_SIGINFO)
				mcount_user_handler.sa_sigaction(sig, info, _ctx);
			else
				mcount_user_handler.sa_handler(sig);
		}
	} else {
		/* redirect thread to original instruction */
		((ucontext_t*)_ctx)->uc_mcontext.gregs[REG(IP)] = (unsigned long) red->insn;
	}
}
#endif

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

	case DYNAMIC_FENTRY:
		result = patch_fentry_func(mdi, sym);
		break;

	case DYNAMIC_NONE:
		result = patch_normal_func(mdi, sym, disasm);
		if(result == INSTRUMENT_FAILED) {
			result = patch_unsupported_func(mdi, sym, disasm);
		}
		break;

	default:
		break;
	}
	return result;
}

#define INSN_CHECK_LEN  16

static void revert_normal_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			       struct mcount_disasm_engine *disasm)
{
	uint8_t jmp_insn[6] = { 0xff, 0x25, };
	void *addr = (void *)(uintptr_t)sym->addr + mdi->map->start;
	void *saved_insn;
	int i;

	saved_insn = mcount_find_code((uintptr_t)addr + CALL_INSN_SIZE);
	if (saved_insn == NULL)
		return;

	/* we don't the original copy size, find the jmp insn instead */
	for (i = CALL_INSN_SIZE; i < INSN_CHECK_LEN; i++) {
		if (!memcmp(saved_insn + i, jmp_insn, sizeof(jmp_insn)))
			break;
	}

	if (i == INSN_CHECK_LEN)
		pr_err_ns("cannot find original insn length\n");

	memcpy(addr, saved_insn, i);
	__builtin___clear_cache(addr, addr + i);
}

void mcount_arch_dynamic_recover(struct mcount_dynamic_info *mdi,
				 struct mcount_disasm_engine *disasm)
{
	struct arch_dynamic_info *adi = mdi->arch;
	struct dynamic_bad_symbol *badsym, *tmp;

	list_for_each_entry_safe(badsym, tmp, &adi->bad_targets, list) {
		revert_normal_func(mdi, badsym->sym, disasm);
		list_del(&badsym->list);
		free(badsym);
	}
}
