#include "libmcount/internal.h"
#include "mcount-arch.h"

#define INSN_SIZE  8

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

/* return true if it's ok for dynamic tracing */
static bool check_prologue(struct mcount_disasm_engine *disasm, cs_insn *insn)
{
	int i;
	cs_arm64 *arm64;
	cs_detail *detail;
	bool branch = false;
	bool status = false;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (insn->detail == NULL)
		return false;

	/* disallow PC-relative instructions */
	if (insn->id == ARM64_INS_ADR || insn->id == ARM64_INS_ADRP)
		return false;

	if (insn->id == ARM64_INS_LDR && (insn->bytes[3] & 0x3b) == 0x18)
		return false;

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
			return false;
		default:
			break;
		}

	}

	arm64 = &insn->detail->arm64;

	if (!arm64->op_count)
		return true;

	for (i = 0; i < arm64->op_count; i++) {
		cs_arm64_op *op = &arm64->operands[i];

		switch((int)op->type) {
		case ARM64_OP_REG:
			status = true;
			break;
		case ARM64_OP_IMM:
			if (branch)
				return false;
			status = true;
			break;
		case ARM64_OP_MEM:
			status = true;
			break;
		default:
			break;
		}
	}
	return status;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	cs_insn *insn = NULL;
	uint32_t count, i;
	int ret = INSTRUMENT_FAILED;

	count = cs_disasm(disasm->engine, (void *)info->addr, INSN_SIZE,
			  info->addr, 0, &insn);

	for (i = 0; i < count; i++) {
		if (!check_prologue(disasm, &insn[i])) {
			pr_dbg3("instruction not supported: %s\t %s\n",
				insn[i].mnemonic, insn[i].op_str);
			break;
		}

		memcpy(info->insns + info->copy_size, insn[i].bytes, insn[i].size);
		info->copy_size += insn[i].size;

		if (i == 1) {
			ret = INSTRUMENT_SUCCESS;
			break;
		}
	}

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

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	uint8_t *insn = (void *)info->addr;

	if (!disasm_check_insn(&insn[3]) || !disasm_check_insn(&insn[7]))
		return INSTRUMENT_FAILED;

	memcpy(info->insns, insn, INSN_SIZE);
	info->copy_size = INSN_SIZE;

	return INSTRUMENT_SUCCESS;
}

#endif /* HAVE_LIBCAPSTONE */
