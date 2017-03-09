/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
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

#ifdef HAVE_LIBCAPSTONE

#include <capstone/capstone.h>
#include <capstone/platform.h>

void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
	/* TODO: handle CS_MODE_THUMB */
	if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &disasm->engine) != CS_ERR_OK) {
		pr_dbg("failed to init Capstone disasm engine\n");
		return;
	}

	if (cs_option(disasm->engine, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		pr_dbg("failed to set detail option\n");
}

void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
	cs_close(&disasm->engine);
}

static int check_instrumentable(struct mcount_disasm_engine *disasm,
				cs_insn *insn)
{
	int i, n;
	cs_arm *arm;
	cs_detail *detail;
	bool branch = false;
	int status = CODE_PATCH_NO;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (insn->detail == NULL)
		return CODE_PATCH_NO;

	detail = insn->detail;

	/* print the groups this instruction belong to */
	if (detail->groups_count > 0) {
		for (n = 0; n < detail->groups_count; n++) {
			if (detail->groups[n] == CS_GRP_CALL ||
			    detail->groups[n] == CS_GRP_JUMP) {
				branch = true;
			}
		}
	}

	arm = &insn->detail->arm;

	/* no operand */
	if (!arm->op_count)
		return CODE_PATCH_NO;

	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &arm->operands[i];

		switch((int)op->type) {
		case ARM_OP_REG:
			if (op->reg == ARM_REG_PC)
				return CODE_PATCH_NO;
			status = CODE_PATCH_OK;
			break;
		case ARM_OP_IMM:
			if (branch)
				return CODE_PATCH_NO;
			status = CODE_PATCH_OK;
			break;
		case ARM_OP_MEM:
			if (op->mem.base == ARM_REG_PC ||
			    op->mem.index == ARM_REG_PC)
				return CODE_PATCH_NO;

			status = CODE_PATCH_OK;
			break;
		case ARM_OP_FP:
			status = CODE_PATCH_OK;
			break;
		default:
			break;
		}
	}
	return status;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       uintptr_t addr, uint32_t size)
{
	cs_insn *insn;
	uint32_t code_size = 0;
	uint32_t count, i;
	int ret = INSTRUMENT_FAILED;

	count = cs_disasm(disasm->engine, (void *)addr, size, addr, 0, &insn);
	if (count < 2)
		goto out;

	for (i = 0; i < count; i++) {
		if (check_instrumentable(disasm, &insn[i]) == CODE_PATCH_NO) {
			pr_dbg3("instruction not supported: %s\t %s\n",
				insn[i].mnemonic, insn[i].op_str);
			goto out;
		}
	}
	ret = INSTRUMENT_SUCCESS;

out:
	if (count)
		cs_free(insn, count);

	return ret;
}

#else /* HAVE_LIBCAPSTONE */

#define FAIL_A32(type) \
	({ pr_dbg2("fail: %s insn: %08lx\n", type, insn); return -1; })

static int check_prolog_insn_arm(uint32_t insn)
{
	/*  unconditional special instructions */
	if ((insn & 0xf0000000) == 0xf0000000) {
		/* TODO: advanced SIMD insns */

		FAIL_A32("unconditional");
	}

	/* data processing and memory insns */
	if ((insn & 0x0c000000) == 0) {
		/* check register: Rn, Rd, Rm(   nd  m) */
		unsigned long regs = insn & 0x000ff00f;

		/* notation: s = cond, r = reg, i = imm, a-f = constant */

		/* misc ops */
		if ((insn & 0x0f900080) == 0x01000000) {
			/* allow CLZ and QADD/QSUB insns only */
			if ((insn & 0x0ff000f0) == 0x01600010 ||
			    (insn & 0x0f9000f0) == 0x01000050)
				return 0;

			FAIL_A32("misc");
		}

		/* synchronization ops - ignore Rm */
		/* LDREX:    (s19rrf9f) Rm = 15 */
		/* LDREXD:   (s1brrf9f) Rm = 15 */
		/* LDREXB:   (s1drrf9f) Rm = 15 */
		/* LDREXH:   (s1frrf9f) Rm = 15 */
		if ((insn & 0x0f800fff) == 0x01800f9f)
			regs &= ~0xf;

		/* extra memory ops - ignore Rm */
		/* STRH:     (sxxrribi) Rm = imm */
		/* LDRH:     (sxxrribi) Rm = imm */
		/* LDRD:     (sxxrridi) Rm = imm */
		/* LDRSB:    (sxxrridi) Rm = imm */
		if ((insn & 0x0e0000f0) == 0x000000b0 ||
		    (insn & 0x0e0000f0) == 0x000000d0) {
			regs &= ~0xf;
		}

		/* immediate ops - ignore Rm */
		if ((insn & 0x0e000000) == 0x02000000) {
			regs &= ~0xf;

			/* MOV.A2:   (s30iriii) Rn = imm */
			/* MOVT:     (s34iriii) Rn = imm */
			if ((insn & 0x0fb00000) == 0x03000000)
				regs &= ~0xf0000;
		}

		if (((regs & 0xf)     == 0xf)     || ((regs & 0xf)     == 0xc)    || /* Rm */
		    ((regs & 0xf000)  == 0xf000)  || ((regs & 0xf000)  == 0xc000) || /* Rd */
		    ((regs & 0xf0000) == 0xf0000) || ((regs & 0xf0000) == 0xc0000))  /* Rn */
			FAIL_A32("data processing");

		return 0;
	}

	/* memory insns: check Rn and Rd only */
	if ((insn & 0x0c000000) == 0x04000000) {
		unsigned long regs = insn & 0x000ff000;

		/* media insns: assumes OK */
		if ((insn & 0x0e000010) == 0x06000010) {
			/* XXX: BFI might have Rm = 15 ? */
			return 0;
		}

		if (((regs & 0xf000)  == 0xf000)  || ((regs & 0xf000)  == 0xc000) ||  /* Rd */
		    ((regs & 0xf0000) == 0xf0000) || ((regs & 0xf0000) == 0xc0000))   /* Rn */
			FAIL_A32("memory");

		return 0;
	}

	/* branch insns: unsupported */
	if ((insn & 0x0e000000) == 0x0a000000)
		FAIL_A32("branch");

	/* block data transfer insns */
	if ((insn & 0x0e000000) == 0x08000000) {
		unsigned long regmask = insn & 0xffff;

		/*
		 * note that PUSH and POP can handle a single reg in Rd,
		 * but using PC (15) will set the bit anyway.
		 */
		if (regmask & 0x8000)
			FAIL_A32("block transer");

		return 0;
	}

	/* coprocessor insns */
	if ((insn & 0x0c000000) == 0x0c000000) {
		/* advandced SIMD insns */
		if ((insn & 0x0c000e00) == 0x0c000a00)
			return 0;

		FAIL_A32("coprocessor");
	}

	FAIL_A32("unknown");
}

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       uintptr_t addr, uint32_t size)
{
	uint32_t *insn = (void *)addr;

	if (check_prolog_insn_arm(insn[0]) == 0 &&
	    check_prolog_insn_arm(insn[1]) == 0)
		return size;

	return INSTRUMENT_FAILED;
}

#endif /* HAVE_LIBCAPSTONE */
