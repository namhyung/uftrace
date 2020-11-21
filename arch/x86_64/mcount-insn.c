/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/internal.h"
#include "mcount-arch.h"
#include "utils/utils.h"

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#include <capstone/platform.h>

struct disasm_check_data {
	uintptr_t		addr;
	uint32_t		func_size;
	uint32_t		patch_size;
	uint32_t		copy_size;
	uint32_t		size;
};

void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &disasm->engine) != CS_ERR_OK) {
		pr_dbg("failed to init capstone disasm engine\n");
		return;
	}

	if (cs_option(disasm->engine, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		pr_dbg("failed to set detail option\n");
}

void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
	cs_close(&disasm->engine);
}

enum fail_reason {
	INSTRUMENT_FAIL_NODETAIL	= (1U << 0),
	INSTRUMENT_FAIL_NOOPRND		= (1U << 1),
	INSTRUMENT_FAIL_RELJMP		= (1U << 2),
	INSTRUMENT_FAIL_RELCALL		= (1U << 3),
	INSTRUMENT_FAIL_PICCODE		= (1U << 4),
};

enum branch_group {
	OP_GROUP_NOBRANCH = 0,
	OP_GROUP_JMP,
	OP_GROUP_CALL,
};

void print_instrument_fail_msg(int reason)
{
	if (reason & INSTRUMENT_FAIL_NOOPRND) {
		pr_dbg3("prologue has insn with no operand\n");
	}
	if (reason & INSTRUMENT_FAIL_RELJMP) {
		pr_dbg3("prologue has relative jump\n");
	}
	if (reason & INSTRUMENT_FAIL_RELCALL) {
		pr_dbg3("prologue has (relative) call\n");
	}
	if (reason & INSTRUMENT_FAIL_PICCODE) {
		pr_dbg3("prologue has PC-relative addressing\n");
	}
}

static int opnd_reg(int capstone_reg)
{
	uint8_t x86_regs[] = {
		X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX,
		X86_REG_RDI, X86_REG_RSI, X86_REG_RBP, X86_REG_RSP,
		X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
		X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
	};
	size_t i;

	for (i = 0; i < sizeof(x86_regs); i++) {
		if (capstone_reg == x86_regs[i])
			return i;
	}
	return -1;
}

/*
 * Handle relative conditional jumps and relative unconditional jumps.
 *
 * This function relocates jcc8 and jcc32 instructions by replacing them with a jcc8 
 * that has a null offset. The offset will be patched later when the code is saved
 * in the of line execution buffer. The new jcc8 will bounce (if condition is met)
 * on a trampoline that jumps to the target of the orginal instruction.
 *
 * The relocation of jmp8 and jmp32 is achieved by replacing them with an absolute 
 * indirect jump to the target.
 *
 */
static int handle_rel_jmp(cs_insn *insn, uint8_t insns[], struct mcount_disasm_info *info)
{
	cs_x86 *x86 = &insn->detail->x86;
	uint8_t relocated_insn[ARCH_TRAMPOLINE_SIZE] = { 0xff, 0x25,};
	uint8_t opcode = insn->bytes[0];
	uint64_t target;
	struct cond_branch_info *cbi;

#define JMP8_OPCODE 0xEB
#define JMP32_OPCODE 0xE9
#define IND_JMP_SIZE 6
#define OP   0
#define OFS	  1
	cs_x86_op *opnd = &x86->operands[0];

	if (x86->op_count != 1 || opnd->type != X86_OP_IMM)
		goto out;

	if ((opcode == JMP8_OPCODE || opcode == JMP32_OPCODE)) {
		if (strcmp(insn->mnemonic, "jmp") != 0)
			goto out;

		target = opnd->imm;

		memcpy(insns, relocated_insn, IND_JMP_SIZE);
		memcpy(insns + IND_JMP_SIZE, &target, sizeof(target));

		info->modified = true;
		/* 
		 * If this jump is the last insn in the prologue, we can ignore
		 * the one in patch_normal_func()
		 */
		if (info->orig_size + insn->size >= ARCH_JMP32_SIZE)
			info->has_jump = true;
		return IND_JMP_SIZE + sizeof(target);

	}/* Jump relative 8 if condition is met (except JCXZ, JECXZ and JRCXZ) */
	else if((opcode & 0xF0) == 0x70) {

		cbi = &info->branch_info[info->nr_branch++];
		cbi->insn_index = info->copy_size;
		cbi->branch_target = opnd->imm;
		cbi->insn_addr = insn->address;
		cbi->insn_size = insn->size;

		relocated_insn[OP] = opcode;
		relocated_insn[OFS] = 0x00;

		memcpy(insns, (void *)relocated_insn, ARCH_JCC8_SIZE);

		info->modified = true;
		return ARCH_JCC8_SIZE;

	}/* Jump relative 32 if condition is met */
	else if(opcode == 0x0F && (insn->bytes[1] & 0xF0) == 0x80) {

		cbi = &info->branch_info[info->nr_branch++];
		cbi->insn_index = info->copy_size;
		cbi->branch_target = opnd->imm;
		cbi->insn_addr = insn->address;
		cbi->insn_size = insn->size;

		/* We use the equivalent jcc8 of the original jcc32 */
		relocated_insn[OP] = insn->bytes[1] - 0x10;
		relocated_insn[OFS] = 0x00;

		memcpy(insns, (void *)relocated_insn, ARCH_JCC8_SIZE);
		
		info->modified = true;
		return ARCH_JCC8_SIZE;
	}

out:
	return -1;
}

/*
 *  handle PIC code.
 *  for currently, this function targeted specific type of instruction.
 *
 *  this function manipulate the instruction like below,
 *    lea rcx, qword ptr [rip + 0x8f3f85]
 *  to this.
 *    mov rcx, [calculated PC + 0x8f3f85]
 */
static int handle_pic(cs_insn *insn, uint8_t insns[],
		      struct mcount_disasm_info *info)
{
	cs_x86 *x86 = &insn->detail->x86;
	cs_x86_op *opnd1;
	cs_x86_op *opnd2;
	uint64_t PC_base;

#define REX   0
#define OPND  1
#define IMM   2

	/*
	 * array for mov instruction: REX + OPND + IMM(8-byte)
	 * ex) mov rbx, 0x555556d35690
	 */
	uint8_t mov_insns[10];

	const uint8_t mov_operands[] = {
	/*	rax,	rbx,	rcx,	rdx,	rdi,	rsi,	rbp,	rsp */
		0xb8,	0xbb,	0xb9,	0xba,	0xbf,	0xbe,	0xbd,	0xbc,
	/*	r8,	r9,	r10,	r11,	r12,	r13,	r14,	r15 */
		0xb8,	0xb9,	0xba,	0xbb,	0xbc,	0xbd,	0xbe,	0xbf,
	};

	/* for now, support LEA instruction only */
	if (strcmp(insn->mnemonic, "lea") != 0)
		goto out;

	/* according to intel manual, lea instruction takes 2 operand */
	opnd1 = &x86->operands[0];
	opnd2 = &x86->operands[1];

	/* check PC-relative addressing mode */
	if (opnd2->type != X86_OP_MEM || opnd2->mem.base != X86_REG_RIP)
		goto out;

	/* the SIB addressing is not supported yet */
	if (opnd2->mem.scale > 1 || opnd2->mem.disp == 0)
		goto out;

	if (X86_REG_RAX <= opnd1->reg && opnd1->reg <= X86_REG_RSP) {
		mov_insns[REX] = 0x48;
	}
	else if (X86_REG_R8 <= opnd1->reg && opnd1->reg <= X86_REG_R15) {
		mov_insns[REX] = 0x49;
	}
	else {
		goto out;
	}

	/* convert LEA to MOV instruction */
	mov_insns[OPND] = mov_operands[opnd_reg(opnd1->reg)];

	PC_base = insn->address + insn->size + opnd2->mem.disp;
	memcpy(&mov_insns[IMM], &PC_base, sizeof(PC_base));

	memcpy(insns, mov_insns, sizeof(mov_insns));
	info->modified = true;

	return sizeof(mov_insns);

out:
	return -1;
}

/*
 *  handle CALL instructions.
 *  it's basically PUSH + JMP instructions and we already add JMP
 *  at the end of copied instructions so reuse the JMP.
 *  But the pushed return address should be after the JMP instruction
 *  so it needs to change the offset in the instruction opcode.
 *  Therefore we added JMP here and ignore JMP in patch_normal_func().
 *  The info->has_jump indicates this situation.
 *
 *  this function manipulate the instruction like below,
 *    CALL <target>
 *  to this.
 *    PUSH <PC>+6  (return address : 6 = sizeof JMP)
 *    JMP  <PC>+8  (target address : 8 = sizeof RETURN-ADDR)
 *    <RETURN-ADDR>
 *    <TARGET-ADDR>
 */
static int handle_call(cs_insn *insn, uint8_t insns[],
		       struct mcount_disasm_info *info)
{
	cs_x86 *x86 = &insn->detail->x86;
	cs_x86_op *op = &x86->operands[0];
	uint8_t push[6] = { 0xff, 0x35, 0x06, };
	uint8_t jump[6] = { 0xff, 0x25, 0x08, };
	uint64_t ret_addr;
	uint64_t target;

	if (x86->op_count != 1 || op->type != X86_OP_IMM)
		return -1;

	target = op->imm;
	ret_addr = insn->address + insn->size;

	memcpy(&insns[0], push, sizeof(push));
	memcpy(&insns[6], jump, sizeof(jump));
	memcpy(&insns[12], &ret_addr, sizeof(ret_addr));
	memcpy(&insns[20], &target, sizeof(target));

	info->modified = true;
	info->has_jump = true;

	return sizeof(push) + sizeof(jump) + 16;
}

static int manipulate_insns(cs_insn *insn, uint8_t insns[], int* fail_reason,
			    struct mcount_disasm_info *info)
{
	int res = -1;

	pr_dbg3("manipulate instructions having PC-relative addressing.\n");

	switch (*fail_reason) {
	case INSTRUMENT_FAIL_RELJMP:
		res = handle_rel_jmp(insn, insns, info);
		if (res > 0)
			*fail_reason = 0;
		break;
	case INSTRUMENT_FAIL_PICCODE:
		res = handle_pic(insn, insns, info);
		if (res > 0)
			*fail_reason = 0;
		break;
	case INSTRUMENT_FAIL_RELCALL:
		res = handle_call(insn, insns, info);
		if (res > 0)
			*fail_reason = 0;
		break;
	default:
		break;
	}

	return res;
}

static int copy_insn_bytes(cs_insn *insn, uint8_t insns[])
{
	int res = insn->size;

	memcpy(insns, insn->bytes, res);
	return res;
}

/*
 * check whether the instruction can be executed regardless of its location.
 * returns false when instructions are not suitable for dynamic patch.
 *
 * TODO: this function is incomplete and need more classification.
 */
static int check_instrumentable(struct mcount_disasm_engine *disasm,
				 cs_insn *insn)
{
	int i;
	cs_x86 *x86;
	cs_detail *detail;
	int check_branch = OP_GROUP_NOBRANCH;
	int status = 0;

	/*
	 * 'detail' can be NULL on "data" instruction
	 * if SKIPDATA option is turned ON
	 */
	if (insn->detail == NULL) {
		status = INSTRUMENT_FAIL_NODETAIL;
		goto out;
	}

	detail = insn->detail;

	for (i = 0; i < detail->groups_count; i++) {
		if (detail->groups[i] == CS_GRP_CALL)
			check_branch = OP_GROUP_CALL;
		else if (detail->groups[i] == CS_GRP_JUMP)
			check_branch = OP_GROUP_JMP;
	}

	x86 = &insn->detail->x86;

	if (!x86->op_count)
		goto out;

	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &x86->operands[i];

		switch (op->type) {
		case X86_OP_REG:
			continue;

		case X86_OP_IMM:
			if (check_branch == OP_GROUP_NOBRANCH)
				continue;

			if (check_branch == OP_GROUP_CALL)
				status |= INSTRUMENT_FAIL_RELCALL;
			else if (check_branch == OP_GROUP_JMP)
				status |= INSTRUMENT_FAIL_RELJMP;

			goto out;

		case X86_OP_MEM:
			if (op->mem.base == X86_REG_RIP ||
			    op->mem.index == X86_REG_RIP) {
				status |= INSTRUMENT_FAIL_PICCODE;
				goto out;
			}
			continue;

		default:
			continue;
		}
	}

out:
	return status;
}

static bool check_unsupported(struct mcount_disasm_engine *disasm,
			      cs_insn *insn, struct mcount_dynamic_info *mdi,
			      struct mcount_disasm_info *info)
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
			if (info->addr < target &&
			    target < info->addr + info->orig_size) {
				pr_dbg4("jump to prologue: addr=%lx, target=%lx\n",
					insn->address - mdi->map->start,
					target - mdi->map->start);
				return false;
			}

			/* disallow jump to middle of other function */
			if (info->addr > target ||
			    target >= info->addr + info->sym->size) {
				/* also mark the target function as invalid */
				if (!mcount_add_badsym(mdi, insn->address,
						       target)) {
					/* it was actuall ok (like tail call) */
					return true;
				}

				pr_dbg4("jump to middle of function: addr=%lx, target=%lx\n",
					insn->address - mdi->map->start,
					target - mdi->map->start);
				return false;
			}
			break;
		case X86_OP_MEM:
		case X86_OP_REG:
			/* indirect jumps are not allowed */
			return false;
		default:
			break;
		}
	}

	return true;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	int status;
	cs_insn *insn = NULL;
	uint32_t count, i, size;
	uint8_t endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
	struct dynamic_bad_symbol *badsym;

	badsym = mcount_find_badsym(mdi, info->addr);
	if (badsym != NULL) {
		badsym->reverted = true;
		return INSTRUMENT_FAILED;
	}

	count = cs_disasm(disasm->engine, (void *)info->addr, info->sym->size,
			  info->addr, 0, &insn);
	if (count == 0 && !memcmp((void *)info->addr, endbr64, sizeof(endbr64))) {
		/* old version of capstone doesn't recognize ENDBR64 insn */
		unsigned long addr = info->addr + sizeof(endbr64);

		info->orig_size += sizeof(endbr64);
		info->copy_size += sizeof(endbr64);

		count = cs_disasm(disasm->engine, (void *)addr,
				  info->sym->size - sizeof(endbr64),
				  addr, 0, &insn);
	}

	for (i = 0; i < count; i++) {
		uint8_t insns_byte[32] = { 0, };

		status = check_instrumentable(disasm, &insn[i]);
		if (status > 0)
			size = manipulate_insns(&insn[i], insns_byte,
						&status, info);
		else
			size = copy_insn_bytes(&insn[i], insns_byte);

		if (status > 0) {
			print_instrument_fail_msg(status);
			status = INSTRUMENT_FAILED;
			goto out;
		}

		memcpy(info->insns + info->copy_size, insns_byte, size);
		info->copy_size += size;
		info->orig_size += insn[i].size;

		if (info->orig_size >= CALL_INSN_SIZE)
			break;
	}

	while (++i < count) {
		if (!check_unsupported(disasm, &insn[i], mdi, info)) {
			status = INSTRUMENT_FAILED;
			break;
		}
	}

out:
	if (count)
		cs_free(insn, count);

	return status;
}

#else /* HAVE_LIBCAPSTONE */

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	return INSTRUMENT_FAILED;
}

#endif /* HAVE_LIBCAPSTONE */
