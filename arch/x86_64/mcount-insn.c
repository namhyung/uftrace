#include "libmcount/internal.h"
#include "mcount-arch.h"

#define CALL_INSN_SIZE  5

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#include <capstone/platform.h>

void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &disasm->engine) != CS_ERR_OK) {
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

/*
 * check whether the instruction can be executed regardless of its location.
 * returns false when instructions are not suitable for dynamic patch.
 *
 * TODO: this function is incomplete and need more classification.
 */
static bool check_instrumentable(struct mcount_disasm_engine *disasm,
				 cs_insn *insn)
{
	int i;
	cs_x86 *x86;
	cs_detail *detail;
	bool jmp_or_call = false;
	bool status = false;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (insn->detail == NULL)
		return false;

	detail = insn->detail;

	for (i = 0; i < detail->groups_count; i++) {
		if (detail->groups[i] == CS_GRP_CALL ||
		    detail->groups[i] == CS_GRP_JUMP) {
			jmp_or_call = true;
		}
	}

	x86 = &insn->detail->x86;
	if (x86->opcode[0] == 0x90 && x86->opcode[1] == 0) {
		/* allow NOP instruction to be patched */
		return true;
	}

	/* no operand: disallow just to be safer for now */
	if (!x86->op_count)
		return false;

	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &x86->operands[i];

		switch((int)op->type) {
		case X86_OP_REG:
			status = true;
			break;
		case X86_OP_IMM:
			if (jmp_or_call)
				return false;
			status = true;
			break;
		case X86_OP_MEM:
			if (op->mem.base == X86_REG_RIP ||
			    op->mem.index == X86_REG_RIP)
				return false;

			status = true;
			break;
		default:
			break;
		}
	}
	return status;
}

static bool check_unsupported(struct mcount_disasm_engine *disasm,
			      cs_insn *insn, uintptr_t addr, uint32_t size)
{
	int i;
	cs_x86 *x86;
	cs_detail *detail = insn->detail;
	unsigned long target;
	bool jump = false;

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

	x86 = &insn->detail->x86;
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &x86->operands[i];

		switch((int)op->type) {
		case X86_OP_IMM:
			/* capstone seems already calculate target address */
			target = op->imm;

			/* disallow (back) jump to the prologue */
			if (addr <= target && target < addr + size)
				return false;
			break;
		case X86_OP_MEM:
			/* TODO */
			break;
		default:
			break;
		}
	}

	return true;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       uintptr_t addr, uint32_t size)
{
	cs_insn *insn = NULL;
	uint32_t code_size = 0;
	uint32_t count, i;
	uint8_t endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
	int ret = INSTRUMENT_FAILED;

	count = cs_disasm(disasm->engine, (void *)addr, size, addr, 0, &insn);
	if (unlikely(count == 0) &&
	    !memcmp((void *)addr, endbr64, sizeof(endbr64))) {
		/* old version of capstone doesn't recognize ENDBR64 insn */
		addr += sizeof(endbr64);
		size -= sizeof(endbr64);
		code_size += sizeof(endbr64);

		count = cs_disasm(disasm->engine, (void *)addr, size, addr, 0,
				  &insn);
	}

	for (i = 0; i < count; i++) {
		if (!check_instrumentable(disasm, &insn[i])) {
			pr_dbg3("instruction not supported: %s\t %s\n",
				insn[i].mnemonic, insn[i].op_str);
			goto out;
		}

		code_size += insn[i].size;
		if (code_size >= CALL_INSN_SIZE) {
			ret = code_size;
			break;
		}
	}

	while (++i < count) {
		if (!check_unsupported(disasm, &insn[i], addr, code_size)) {
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

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       uintptr_t addr, uint32_t size)
{
	return INSTRUMENT_FAILED;
}

#endif /* HAVE_LIBCAPSTONE */
