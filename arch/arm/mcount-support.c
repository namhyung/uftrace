#include <stdlib.h>
#include <assert.h>
#include <link.h>
#include <gelf.h>

#ifndef EF_ARM_ABI_FLOAT_HARD
# define EF_ARM_ABI_FLOAT_HARD  EF_ARM_VFP_FLOAT
#endif

#include "mcount-arch.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"
#include "utils/filter.h"

struct lr_offset {
	int           offset;  // 4-byte unit
	bool          pushed;
};

#define REG_SP  13

static struct rb_root offset_cache = RB_ROOT;
static bool use_hard_float = false;
static bool float_abi_checked = false;

struct offset_entry {
	struct rb_node node;
	unsigned long  addr;
	unsigned long  offset;
};

static struct offset_entry *lookup_cache(struct rb_root *root,
					 unsigned long addr, bool create)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct offset_entry *iter;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct offset_entry, node);

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

static unsigned rotate_right(unsigned val, unsigned bits, unsigned shift)
{
	return (val >> shift) | (val << (bits - shift));
}

/*
 * This function implements ThumbExpandImm() in ARM ARM A6.3.2
 * "Modified immediate constants in Thumb instructions".
 */
static unsigned expand_thumb_imm(unsigned short opcode1, unsigned short opcode2)
{
	unsigned imm_upper = ((opcode1 & 0x0400) >> 7) |
			     ((opcode2 & 0x7000) >> 12);
	unsigned imm_lower = opcode2 & 0xff;
	unsigned imm;

	if ((imm_upper & 0xc) == 0) {
		switch (imm_upper & 0x3) {
		case 0:
			imm = imm_lower;
			break;
		case 1:
			imm = (imm_lower << 16) | imm_lower;
			break;
		case 2:
			imm = (imm_lower << 24) | (imm_lower << 8);
			break;
		case 3:
			imm = (imm_lower << 24) | (imm_lower << 16) |
				(imm_lower << 8) | imm_lower;
			break;
		}
	}
	else {
		unsigned shift = (imm_upper << 1) | (imm_lower >> 7);

		imm = rotate_right(imm_lower | 0x80, 32, shift);
	}

	pr_dbg3("imm: %u (%x/%x)\n", imm, imm_upper, imm_lower);
	return imm;
}

static int analyze_mcount_insn(unsigned short *insn, struct lr_offset *lr)
{
	int bit_size = 16;
	unsigned short opcode = *insn;

	if (opcode >= 0xe800)
		bit_size = 32;

	if (opcode == 0xb500 && (((insn[1] & 0xf800) == 0xf000) &&
				 ((insn[2] & 0xc000) == 0xc000))) {
		/* PUSH $LR + BLX mcount */
		if (lr->pushed)
			lr->offset++;
		else
			lr->offset = 0;  /* tailcall (use LR directly)  */

		/* done! */
		return 0;
	}
	else if ((opcode & 0xfe00) == 0xb400) {
		/* PUSH (reg mask) */
		int i;

		if ((opcode & 0x100) || lr->pushed) {
			lr->pushed = true;

			for (i = 0; i < 8; i++) {
				if (opcode & (1 << i))
					lr->offset++;
			}
		}
	}
	else if (opcode == 0xe92d) {
		/* PUSH (reg mask) : 32 bit insn */
		int i;
		unsigned short opcode2 = insn[1];

		if ((opcode2 & 0x4000) || lr->pushed) {
			lr->pushed = true;

			for (i = 0; i < 13; i++) {
				if (opcode2 & (1 << i))
					lr->offset++;
			}
		}
	}
	else if ((opcode & 0xff80) == 0xb080) {
		/* SUB (SP - imm) */
		if (lr->pushed)
			lr->offset += opcode & 0x7f;
	}
	else if ((opcode & 0xfbef) == 0xf1ad) {
		/* SUB (SP - imm) : 32 bit insn */
		unsigned short opcode2 = insn[1];
		int target = (opcode2 & 0xf00) >> 8;

		if (lr->pushed && target == REG_SP) {
			unsigned imm = expand_thumb_imm(opcode, opcode2);

			lr->offset += imm >> 2;
		}
	}
	else if ((opcode & 0xfbff) == 0xf2ad) {
		/* SUB (SP - imm) : 32 bit insn */
		unsigned short opcode2 = insn[1];
		int target = (opcode2 & 0xf00) >> 8;

		if (lr->pushed && target == REG_SP) {
			unsigned imm = opcode2 & 0xff;

			imm |= (opcode2 & 0x7000) >> 4;
			imm |= (opcode & 0x400) << 1;
			lr->offset += imm >> 2;
		}
	}
	else if ((opcode & 0xf800) == 0xa800) {
		/* ADD (SP + imm) */
		int target = (opcode & 0x380) >> 7;

		if (lr->pushed && target == REG_SP)
			lr->offset -= opcode & 0xff;
	}
	else if ((opcode & 0xff80) == 0xb000) {
		/* ADD (SP + imm) */
		if (lr->pushed)
			lr->offset -= opcode & 0x3f;
	}
	else if ((opcode & 0xfbef) == 0xf10d) {
		/* ADD (SP + imm) : 32 bit insn */
		unsigned short opcode2 = insn[1];
		int target = (opcode & 0xf00) >> 8;

		if (lr->pushed && target == REG_SP) {
			unsigned imm = expand_thumb_imm(opcode, opcode2);

			lr->offset -= imm >> 2;
		}
	}
	else if (opcode == 0xf84d) {
		/* STR [SP + imm]! */
		unsigned short opcode2 = insn[1];

		if (lr->pushed && (opcode2 & 0xfff) == 0xd04)
			lr->offset++;
	}
	else if ((opcode & 0xffbf) == 0xed2d) {
		/* VPUSH (VFP/NEON reg list) */
		unsigned short opcode2 = insn[1];
		unsigned imm = opcode2 & 0xff;

		if (lr->pushed)
			lr->offset += imm;
	}
	else {
		pr_err_ns("cannot analyze insn: %hx\n", opcode);
	}

	return bit_size == 16 ? 1 : 2;
}

#define MAX_ANALYSIS_COUNT  16

static void analyze_mcount_instructions(unsigned short *insn, struct lr_offset *lr)
{
	int ret;
	int count = 0;

	do {
		ret = analyze_mcount_insn(insn, lr);
		insn += ret;
	}
	while (ret && count++ < MAX_ANALYSIS_COUNT);

	if (count > MAX_ANALYSIS_COUNT) {
		pr_dbg("stopping analysis on a long function prologue\n");
		return;
	}

	pr_dbg2("%s: return address offset = %+d\n", __func__, lr->offset);
}

/* This code is only meaningful on THUMB2 mode: @loc = $sp + 4 */
unsigned long *mcount_arch_parent_location(struct symtabs *symtabs,
					   unsigned long *parent_loc,
					   unsigned long child_ip)
{
	struct sym *sym;
	unsigned short buf[MAX_ANALYSIS_COUNT];
	struct lr_offset lr = {
		.offset = 0,
	};
	struct offset_entry *cache;

	sym = find_symtabs(symtabs, child_ip);
	if (sym == NULL)
		pr_err_ns("cannot find symbol for %lx\n", child_ip);

	// on ARM mode, return as is
	if ((sym->addr & 1) == 0)
		return parent_loc;

	cache = lookup_cache(&offset_cache, sym->addr, false);
	if (cache)
		return parent_loc + cache->offset;

	pr_dbg2("copying instructions of %s\n", sym->name);
	memcpy(buf, (void *)(long)(sym->addr & ~1), sizeof(buf));

	analyze_mcount_instructions(buf, &lr);

	cache = lookup_cache(&offset_cache, sym->addr, true);
	cache->offset = lr.offset;

	return parent_loc + lr.offset;
}

int check_float_abi_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	unsigned i;

	for (i = 0; i < info->dlpi_phnum; i++) {
		const Elf32_Phdr *phdr = info->dlpi_phdr + i;

		if (phdr->p_type == PT_LOAD) {
			Elf32_Ehdr *ehdr = (void *)phdr->p_vaddr;
			use_hard_float = ehdr->e_flags & EF_ARM_ABI_FLOAT_HARD;
			break;
		}
	}
	float_abi_checked = true;

	return 1;
}

void check_float_abi(void)
{
	dl_iterate_phdr(check_float_abi_cb, NULL);
}

int mcount_get_register_arg(struct mcount_arg_context *ctx,
			    struct uftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	int reg_idx;

	switch (spec->type) {
	case ARG_TYPE_REG:
		reg_idx = spec->reg_idx;
		break;
	case ARG_TYPE_FLOAT:
		if (use_hard_float) {
			if (spec->size <= 4)
				reg_idx = spec->idx + ARM_REG_FLOAT_BASE;
			else
				reg_idx = spec->idx + ARM_REG_DOUBLE_BASE;
			break;
		}
		/* fall through */
	case ARG_TYPE_INDEX:
		reg_idx = spec->idx; /* for integer arguments */
		if (spec->size == 8 && (reg_idx & 1) == 0)
			reg_idx++;
		break;
	case ARG_TYPE_STACK:
	default:
		return -1;
	}

	switch (reg_idx) {
	case ARM_REG_R0:
		ctx->val.i = ARG1(regs);
		if (spec->size == 8)
			ctx->val.ll.hi = ARG2(regs);
		break;
	case ARM_REG_R1:
		ctx->val.i = ARG2(regs);
		break;
	case ARM_REG_R2:
		ctx->val.i = ARG3(regs);
		if (spec->size == 8)
			ctx->val.ll.hi = ARG4(regs);
		break;
	case ARM_REG_R3:
		ctx->val.i = ARG4(regs);
		break;
	case ARM_REG_S0:
		asm volatile ("vstr %%s0, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S1:
		asm volatile ("vstr %%s1, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S2:
		asm volatile ("vstr %%s2, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S3:
		asm volatile ("vstr %%s3, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S4:
		asm volatile ("vstr %%s4, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S5:
		asm volatile ("vstr %%s5, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S6:
		asm volatile ("vstr %%s6, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S7:
		asm volatile ("vstr %%s7, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S8:
		asm volatile ("vstr %%s8, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S9:
		asm volatile ("vstr %%s9, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S10:
		asm volatile ("vstr %%s10, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S11:
		asm volatile ("vstr %%s11, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S12:
		asm volatile ("vstr %%s12, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S13:
		asm volatile ("vstr %%s13, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S14:
		asm volatile ("vstr %%s14, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_S15:
		asm volatile ("vstr %%s15, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_D0:
		asm volatile ("vstr %%d0, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_D1:
		asm volatile ("vstr %%d1, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_D2:
		asm volatile ("vstr %%d2, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_D3:
		asm volatile ("vstr %%d3, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_D4:
		asm volatile ("vstr %%d4, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_D5:
		asm volatile ("vstr %%d5, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_D6:
		asm volatile ("vstr %%d6, %0\n" : "=m" (ctx->val.v));
		break;
	case ARM_REG_D7:
		asm volatile ("vstr %%d7, %0\n" : "=m" (ctx->val.v));
		break;
	default:
		return -1;
	}

	return 0;
}

void mcount_get_stack_arg(struct mcount_arg_context *ctx,
			  struct uftrace_arg_spec *spec)
{
	int offset = 1;

	switch (spec->type) {
	case ARG_TYPE_STACK:
		offset = spec->stack_ofs;
		break;
	case ARG_TYPE_FLOAT:
		if (use_hard_float) {
			if (spec->size <= 4)
				offset = spec->idx - ARCH_MAX_FLOAT_REGS;
			else
				offset = (spec->idx - ARCH_MAX_DOUBLE_REGS) * 2 - 1;
			break;
		}
		/* fall through */
	case ARG_TYPE_INDEX:
		offset = spec->idx - ARCH_MAX_REG_ARGS;
		if (spec->size == 8 && (offset & 1) == 0)
			offset++;
		break;
	case ARG_TYPE_REG:
	default:
		/* should not reach here */
		pr_err_ns("invalid stack access for arguments\n");
		break;
	}

	if (offset < 1 || offset > 100)
		pr_dbg("invalid stack offset: %d\n", offset);

	memcpy(ctx->val.v, ctx->stack_base + offset, spec->size);
}

void mcount_arch_get_arg(struct mcount_arg_context *ctx,
			 struct uftrace_arg_spec *spec)
{
	if (!float_abi_checked)
		check_float_abi();

	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct uftrace_arg_spec *spec)
{
	if (!float_abi_checked)
		check_float_abi();

	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

	/* type of return value cannot be FLOAT, so check format instead */
	if (spec->fmt == ARG_FMT_FLOAT && use_hard_float) {
		if (spec->size <= 4)
			asm volatile ("vstr %%s0, %0\n" : "=m" (ctx->val.v));
		else
			asm volatile ("vstr %%d0, %0\n" : "=m" (ctx->val.v));
	}
	else
		memcpy(ctx->val.v, ctx->retval, spec->size);
}

int mcount_arch_undo_bindnow(Elf *elf, struct plthook_data *pd)
{
	size_t shstr_idx, dynstr_idx = 0;
	Elf_Scn *sec, *dynsym_sec, *relplt_sec;
	Elf_Data *dynsym_data, *relplt_data;
	unsigned long pltgot_addr = (unsigned long)pd->pltgot_ptr;
	unsigned long plt_addr = 0;
	unsigned idx, nr_rels = 0;
	int count = 0;
	const char *skip_syms[] = {
		"mcount", "__gnu_mcount_nc",
		"__cyg_profile_func_enter", "__cyg_profile_func_exit",
		"__cxa_finalize",  /* XXX: it caused segfault */
	};

	pr_dbg2("restore PLTGOT for bind-now\n");

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		return -1;

	sec = dynsym_sec = relplt_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *shstr;
		GElf_Shdr shdr;

		if (gelf_getshdr(sec, &shdr) == NULL)
			return -1;

		shstr = elf_strptr(elf, shstr_idx, shdr.sh_name);

		if (strcmp(shstr, ".dynsym") == 0) {
			dynsym_sec = sec;
			dynstr_idx = shdr.sh_link;
		}
		else if (strcmp(shstr, ".rel.plt") == 0) {
			relplt_sec = sec;
			nr_rels = shdr.sh_size / shdr.sh_entsize;
		}
		else if (strcmp(shstr, ".plt") == 0) {
			plt_addr = shdr.sh_addr + pd->base_addr;
		}
	}

	if (plt_addr == 0) {
		pr_dbg("cannot find PLT section\n");
		return -1;
	}

	relplt_data = elf_getdata(relplt_sec, NULL);
	dynsym_data = elf_getdata(dynsym_sec, NULL);
	if (relplt_data == NULL || dynsym_data == NULL)
		return -1;

	for (idx = 0; idx < nr_rels; idx++) {
		struct sym *sym;
		GElf_Sym esym;
		unsigned sym_idx;
		int got_idx;
		char *name;
		GElf_Rel rel;

		if (gelf_getrel(relplt_data, idx, &rel) == NULL)
			return -1;

		if (GELF_R_TYPE(rel.r_info) != R_ARM_JUMP_SLOT) {
			pr_dbg("invalid reloc type: %u\n",
			       GELF_R_TYPE(rel.r_info));
			return -1;
		}

		sym_idx = GELF_R_SYM(rel.r_info);

		gelf_getsym(dynsym_data, sym_idx, &esym);
		name = elf_strptr(elf, dynstr_idx, esym.st_name);

		sym = &pd->dsymtab.sym[idx];
		if (strcmp(name, sym->name)) {
			pr_dbg("symbol name mismatch (%s vs %s)\n",
			       name, sym->name);
			return -1;
		}

		for (sym_idx = 0; sym_idx < ARRAY_SIZE(skip_syms); sym_idx++) {
			if (!strcmp(sym->name, skip_syms[sym_idx]))
				break;
		}
		if (sym_idx != ARRAY_SIZE(skip_syms))
			continue;

		got_idx = (rel.r_offset + pd->base_addr - pltgot_addr) >> 2;
		setup_pltgot(pd, got_idx, idx, (void *)plt_addr);
		count++;

		pr_dbg3("restore GOT[%u] (%s) r_offset = %lx\n",
			got_idx, name, (unsigned long)rel.r_offset);
	}
	pr_dbg2("restored %d entries\n", count);

	return 0;
}

unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx)
{
	return pd->plt_addr;
}
