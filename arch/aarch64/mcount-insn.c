#include "libmcount/dynamic.h"
#include "libmcount/internal.h"
#include "mcount-arch.h"

#define INSN_SIZE 8

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#include <capstone/platform.h>

void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &disasm->engine) != CS_ERR_OK) {
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

/* return 0 if it's ok, -1 if not supported, 1 if modifiable */
static int check_prologue(struct mcount_disasm_engine *disasm, cs_insn *insn)
{
	int i;
	cs_arm64 *arm64;
	cs_detail *detail;
	bool branch = false;
	int status = -1;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (insn->detail == NULL)
		return -1;

	/* try to fix some PC-relative instructions */
	if (insn->id == ARM64_INS_ADR || insn->id == ARM64_INS_ADRP)
		return 1;

	if (insn->id == ARM64_INS_LDR && (insn->bytes[3] & 0x3b) == 0x18)
		return -1;

	detail = insn->detail;

	for (i = 0; i < detail->groups_count; i++) {
		// BL instruction uses PC for return address */
		switch (detail->groups[i]) {
		case CS_GRP_JUMP:
			branch = true;
			break;
		case CS_GRP_CALL:
		case CS_GRP_RET:
		case CS_GRP_IRET:
#if CS_API_MAJOR >= 4
		case CS_GRP_BRANCH_RELATIVE:
#endif
			return -1;
		default:
			break;
		}
	}

	arm64 = &insn->detail->arm64;

	if (!arm64->op_count)
		return 0;

	for (i = 0; i < arm64->op_count; i++) {
		cs_arm64_op *op = &arm64->operands[i];

		switch (op->type) {
		case ARM64_OP_REG:
			status = 0;
			break;
		case ARM64_OP_IMM:
			if (branch)
				return -1;
			status = 0;
			break;
		case ARM64_OP_MEM:
			status = 0;
			break;
		default:
			break;
		}
	}
	return status;
}

/* return true if it's ok for dynamic tracing */
static bool check_body(struct mcount_disasm_engine *disasm, cs_insn *insn,
		       struct mcount_dynamic_info *mdi, struct mcount_disasm_info *info)
{
	int i;
	cs_arm64 *arm64;
	cs_detail *detail = insn->detail;
	unsigned long target;
	bool jump = false;

	/* we cannot investigate, not supported */
	if (detail == NULL)
		return false;

	detail = insn->detail;

	/* assume there's no call into the middle of function */
	for (i = 0; i < detail->groups_count; i++) {
		if (detail->groups[i] == CS_GRP_JUMP)
			jump = true;
	}

	if (!jump)
		return true;

	arm64 = &insn->detail->arm64;
	for (i = 0; i < arm64->op_count; i++) {
		cs_arm64_op *op = &arm64->operands[i];

		switch (op->type) {
		case ARM64_OP_IMM:
			/* capstone seems already calculate target address */
			target = op->imm;

			/* disallow (back) jump to the prologue */
			if (info->addr < target && target < info->addr + info->copy_size)
				return false;

			/* disallow jump to middle of other function */
			if (info->addr > target || target >= info->addr + info->sym->size) {
				/* also mark the target function as invalid */
				return !mcount_add_badsym(mdi, insn->address, target);
			}
			break;
		case ARM64_OP_MEM:
			/* indirect jumps are not allowed */
			return false;
		case ARM64_OP_REG:
			/*
			 * WARN: it should be disallowed too, but many of functions
			 * use branch with register so this would drop the success
			 * rate significantly.  Allowing it for now.
			 */
			return true;
		default:
			break;
		}
	}

	return true;
}

static int opnd_reg(int capstone_reg)
{
	const uint8_t arm64_regs[] = {
		ARM64_REG_X0,  ARM64_REG_X1,   ARM64_REG_X2,  ARM64_REG_X3,  ARM64_REG_X4,
		ARM64_REG_X5,  ARM64_REG_X6,   ARM64_REG_X7,  ARM64_REG_X8,  ARM64_REG_X9,
		ARM64_REG_X10, ARM64_REG_X11,  ARM64_REG_X12, ARM64_REG_X13, ARM64_REG_X14,
		ARM64_REG_X15, ARM64_REG_X16,  ARM64_REG_X17, ARM64_REG_X18, ARM64_REG_X19,
		ARM64_REG_X20, ARM64_REG_X21,  ARM64_REG_X22, ARM64_REG_X23, ARM64_REG_X24,
		ARM64_REG_X25, ARM64_REG_X26,  ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_X29,
		ARM64_REG_X30, ARM64_REG_NZCV,
	};
	size_t i;

	for (i = 0; i < sizeof(arm64_regs); i++) {
		if (capstone_reg == arm64_regs[i])
			return i;
	}
	return -1;
}

#define REG_SHIFT 5

static bool modify_instruction(struct mcount_disasm_engine *disasm, cs_insn *insn,
			       struct mcount_dynamic_info *mdi, struct mcount_disasm_info *info)
{
	if (insn->id == ARM64_INS_ADR || insn->id == ARM64_INS_ADRP) {
		uint32_t ldr_insn = 0x580000c0;
		uint64_t target_addr;
		cs_arm64_op *op1 = &insn->detail->arm64.operands[0];
		cs_arm64_op *op2 = &insn->detail->arm64.operands[1];

		/* handle the first ADRP instruction only (for simplicity) */
		if (info->copy_size != 0)
			return false;

		if (op1->type != ARM64_OP_REG || op2->type != ARM64_OP_IMM)
			return false;

		/*
		 * craft LDR instruction to load addr to op1->reg.
		 * the actual 'addr' is located after 24 byte from the insn.
		 */
		ldr_insn += opnd_reg(op1->reg);
		target_addr = op2->imm;

		memcpy(info->insns, &ldr_insn, sizeof(ldr_insn));
		/* 24 = 8 (orig_insn) + 16 (br insn + address) */
		memcpy(info->insns + 24, &target_addr, sizeof(target_addr));

		info->copy_size += sizeof(ldr_insn);
		info->modified = true;
		return true;
	}

	return false;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm, struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	cs_insn *insn = NULL;
	uint32_t count, i;
	int ret = INSTRUMENT_FAILED;
	struct dynamic_bad_symbol *badsym;

	badsym = mcount_find_badsym(mdi, info->addr);
	if (badsym != NULL) {
		badsym->reverted = true;
		return INSTRUMENT_FAILED;
	}

	count = cs_disasm(disasm->engine, (void *)info->addr, info->sym->size, info->addr, 0,
			  &insn);

	for (i = 0; i < count; i++) {
		int state = check_prologue(disasm, &insn[i]);

		if (state < 0) {
			pr_dbg3("instruction not supported: %s\t %s\n", insn[i].mnemonic,
				insn[i].op_str);
			goto out;
		}

		if (state) {
			if (!modify_instruction(disasm, &insn[i], mdi, info))
				goto out;
		}
		else {
			memcpy(info->insns + info->copy_size, insn[i].bytes, insn[i].size);
			info->copy_size += insn[i].size;
		}
		info->orig_size += insn[i].size;

		if (info->orig_size >= INSN_SIZE) {
			ret = INSTRUMENT_SUCCESS;
			break;
		}
	}

	while (++i < count) {
		if (!check_body(disasm, &insn[i], mdi, info)) {
			ret = INSTRUMENT_FAILED;
			break;
		}
	}

out:
	if (count)
		cs_free(insn, count);

	return ret;
}

#else /* HAVE_LIBCAPSTONE */

static bool disasm_check_insn(uint8_t *insn)
{
	// LDR (literal)
	if ((*insn & 0x3b) == 0x18)
		return false;

	// ADR or ADRP
	if ((*insn & 0x1f) == 0x10)
		return false;

	// Branch & system instructions
	if ((*insn & 0x1c) == 0x14)
		return false;

	return true;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm, struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	uint8_t *insn = (void *)info->addr;

	if (!disasm_check_insn(&insn[3]) || !disasm_check_insn(&insn[7]))
		return INSTRUMENT_FAILED;

	memcpy(info->insns, insn, INSN_SIZE);
	info->orig_size = INSN_SIZE;
	info->copy_size = INSN_SIZE;

	return INSTRUMENT_SUCCESS;
}

#endif /* HAVE_LIBCAPSTONE */
