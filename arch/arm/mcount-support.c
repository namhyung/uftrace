#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
	memcpy(buf, (void *)(sym->addr & ~1), sizeof(buf));

	analyze_mcount_instructions(buf, &lr);

	cache = lookup_cache(&offset_cache, sym->addr, true);
	cache->offset = lr.offset;

	return parent_loc + lr.offset;
}

long mcount_arch_get_arg(struct mcount_arg_context *ctx,
			 struct ftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	long val;

	if (spec->idx <= ARCH_MAX_REG_ARGS) {
		switch (spec->idx) {
		case 1:
			val = ARG1(regs);
			break;
		case 2:
			val = ARG2(regs);
			break;
		case 3:
			val = ARG3(regs);
			break;
		case 4:
			val = ARG4(regs);
			break;
		default:
			/* cannot reach here */
			val = 0;
			break;
		}
	}
	else {
		/* TODO: limit max argument index */
		val = ctx->stack_base[spec->idx - ARCH_MAX_REG_ARGS];
	}

	/* XXX: this assumes little endian */
	memcpy(ctx->val.v, &val, spec->size);
}

long mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct ftrace_arg_spec *spec)
{
	memcpy(ctx->val.v, ctx->retval, spec->size);
}
