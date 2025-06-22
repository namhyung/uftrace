#include <elf.h>
#include <link.h>
#include <stdlib.h>

#ifndef EF_ARM_VFP_FLOAT
#define EF_ARM_VFP_FLOAT 0x400
#endif

#ifndef EF_ARM_ABI_FLOAT_HARD
#define EF_ARM_ABI_FLOAT_HARD EF_ARM_VFP_FLOAT
#endif

#include "libmcount/internal.h"
#include "utils/filter.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"
#include "utils/utils.h"

struct lr_offset {
	int offset; // 4-byte unit
	bool pushed;
};

#define REG_SP 13

/* whether current machine supports hardfp */
static bool use_hard_float = false;

#ifdef HAVE_ARM_HARDFP
/* need to check hardfp at runtime */
static bool float_abi_checked = false;
#else
/* disable hardfp as it's not supported */
static bool float_abi_checked = true;
#endif

struct offset_entry {
	struct rb_node node;
	unsigned long addr;
	unsigned long offset;
};

/* These functions are implemented in assembly */
extern void __gnu_mcount_nc(void);
extern void plt_hooker(void);
extern void mcount_return(void);
extern void plthook_return(void);

/* These functions are defined in the current file */
static unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx);

const struct mcount_arch_ops mcount_arch_ops = {
	.entry = {
		[UFT_ARCH_OPS_MCOUNT] = (unsigned long)__gnu_mcount_nc,
		[UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plt_hooker,
	},
	.exit = {
		[UFT_ARCH_OPS_MCOUNT] = (unsigned long)mcount_return,
		[UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plthook_return,
	},
	.plthook_addr = mcount_arch_plthook_addr,
};

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
	unsigned imm_upper = ((opcode1 & 0x0400) >> 7) | ((opcode2 & 0x7000) >> 12);
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
			imm = (imm_lower << 24) | (imm_lower << 16) | (imm_lower << 8) | imm_lower;
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

	if (opcode == 0xb500 &&
	    (((insn[1] & 0xf800) == 0xf000) && ((insn[2] & 0xc000) == 0xc000))) {
		/* PUSH $LR + BLX mcount */
		if (lr->pushed)
			lr->offset++;
		else
			lr->offset = 0; /* tailcall (use LR directly)  */

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
	else if ((opcode & 0xf800) == 0x4800) {
		/* LDR [PC + imm] */
	}
	else if ((opcode & 0xfff0) == 0xf8d0) {
		/* LDR.W (reg + imm) */
	}
	else {
		pr_err_ns("cannot analyze insn: %hx\n", opcode);
	}

	return bit_size == 16 ? 1 : 2;
}

#define MAX_ANALYSIS_COUNT 16

static void analyze_mcount_instructions(unsigned short *insn, struct lr_offset *lr)
{
	int ret;
	int count = 0;

	do {
		ret = analyze_mcount_insn(insn, lr);
		insn += ret;
	} while (ret && count++ < MAX_ANALYSIS_COUNT);

	if (count > MAX_ANALYSIS_COUNT) {
		pr_dbg("stopping analysis on a long function prologue\n");
		return;
	}

	pr_dbg2("%s: return address offset = %+d\n", __func__, lr->offset);
}

/* This code is only meaningful on THUMB2 mode: @loc = $sp + 4 */
unsigned long *mcount_arch_parent_location(struct uftrace_sym_info *symtabs,
					   unsigned long *parent_loc, unsigned long child_ip)
{
	struct uftrace_symbol *sym;
	unsigned short buf[MAX_ANALYSIS_COUNT];
	struct lr_offset lr = {
		.offset = 0,
	};
	struct uftrace_mmap *map;
	uint64_t map_start_addr = 0;
	uint64_t load_addr;

	sym = find_symtabs(symtabs, child_ip);
	if (sym == NULL) {
		pr_dbg("cannot find a child symbol for %lx\n", child_ip);
		return parent_loc;
	}

	/* on ARM mode, return as is */
	if ((sym->addr & 1) == 0)
		return parent_loc;

	map = find_map(symtabs, child_ip);
	if (map != NULL && map != MAP_KERNEL)
		map_start_addr = map->start;
	load_addr = sym->addr + map_start_addr;

	pr_dbg2("copying instructions of %s from %#x\n", sym->name, load_addr);
	memcpy(buf, (void *)(long)(load_addr & ~1), sizeof(buf));

	analyze_mcount_instructions(buf, &lr);

	return parent_loc + lr.offset;
}

int check_float_abi_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	unsigned i;

	for (i = 0; i < info->dlpi_phnum; i++) {
		const Elf32_Phdr *phdr = info->dlpi_phdr + i;

		if (phdr->p_type == PT_LOAD) {
			Elf32_Ehdr *ehdr = (void *)info->dlpi_addr + phdr->p_vaddr;
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

int mcount_get_register_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
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
				reg_idx = spec->idx + UFT_ARM_REG_FLOAT_BASE;
			else
				reg_idx = spec->idx + UFT_ARM_REG_DOUBLE_BASE;
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
	case UFT_ARM_REG_R0:
		ctx->val.i = ARG1(regs);
		if (spec->size == 8)
			ctx->val.ll.hi = ARG2(regs);
		break;
	case UFT_ARM_REG_R1:
		ctx->val.i = ARG2(regs);
		break;
	case UFT_ARM_REG_R2:
		ctx->val.i = ARG3(regs);
		if (spec->size == 8)
			ctx->val.ll.hi = ARG4(regs);
		break;
	case UFT_ARM_REG_R3:
		ctx->val.i = ARG4(regs);
		break;

#ifdef HAVE_ARM_HARDFP
	case UFT_ARM_REG_S0:
		asm volatile("vstr %%s0, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S1:
		asm volatile("vstr %%s1, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S2:
		asm volatile("vstr %%s2, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S3:
		asm volatile("vstr %%s3, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S4:
		asm volatile("vstr %%s4, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S5:
		asm volatile("vstr %%s5, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S6:
		asm volatile("vstr %%s6, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S7:
		asm volatile("vstr %%s7, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S8:
		asm volatile("vstr %%s8, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S9:
		asm volatile("vstr %%s9, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S10:
		asm volatile("vstr %%s10, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S11:
		asm volatile("vstr %%s11, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S12:
		asm volatile("vstr %%s12, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S13:
		asm volatile("vstr %%s13, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S14:
		asm volatile("vstr %%s14, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_S15:
		asm volatile("vstr %%s15, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_D0:
		asm volatile("vstr %%d0, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_D1:
		asm volatile("vstr %%d1, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_D2:
		asm volatile("vstr %%d2, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_D3:
		asm volatile("vstr %%d3, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_D4:
		asm volatile("vstr %%d4, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_D5:
		asm volatile("vstr %%d5, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_D6:
		asm volatile("vstr %%d6, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_ARM_REG_D7:
		asm volatile("vstr %%d7, %0\n" : "=m"(ctx->val.v));
		break;
#endif /* HAVE_ARM_HARDFP */

	default:
		return -1;
	}

	return 0;
}

void mcount_get_stack_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	int offset = 1;
	unsigned long *addr = ctx->stack_base;

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

	if (offset < 1 || offset > 100) {
		pr_dbg("invalid stack offset: %d\n", offset);
		memset(ctx->val.v, 0, sizeof(ctx->val));
		return;
	}

	addr += offset;

	if (check_mem_region(ctx, (unsigned long)addr))
		memcpy(ctx->val.v, addr, spec->size);
	else {
		pr_dbg("stack address is not allowed: %p\n", addr);
		memset(ctx->val.v, 0, sizeof(ctx->val));
	}
}

void mcount_arch_get_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	if (!float_abi_checked)
		check_float_abi();

	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	if (!float_abi_checked)
		check_float_abi();

	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

		/* type of return value cannot be FLOAT, so check format instead */
#ifdef HAVE_ARM_HARDFP
	if (spec->fmt == ARG_FMT_FLOAT && use_hard_float) {
		/* d0, d1 registers (64 bit) were saved below the r0 */
		long *float_retval = ctx->retval - 4;

		mcount_memcpy4(ctx->val.v, float_retval, spec->size);
	}
	else
#endif /* HAVE_ARM_HARDFP */
		memcpy(ctx->val.v, ctx->retval, spec->size);
}

static unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx)
{
	return pd->plt_addr;
}
