/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "mcount-arch.h"
#include "utils/utils.h"

#define REG_SP  13

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

int analyze_mcount_prolog(unsigned short *insn, struct lr_offset *lr)
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
