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
	INSTRUMENT_FAIL_NO_DETAIL	= (1U << 0),
	INSTRUMENT_FAIL_RELJMP		= (1U << 1),
	INSTRUMENT_FAIL_RELCALL		= (1U << 2),
	INSTRUMENT_FAIL_PIC		= (1U << 3),
};

enum branch_group {
	OP_GROUP_NOBRANCH = 0,
	OP_GROUP_JMP,
	OP_GROUP_CALL,
};

void print_instrument_fail_msg(int reason)
{
	if (reason & INSTRUMENT_FAIL_RELJMP) {
		pr_dbg3("prologue has relative jump\n");
	}
	if (reason & INSTRUMENT_FAIL_RELCALL) {
		pr_dbg3("prologue has (relative) call\n");
	}
	if (reason & INSTRUMENT_FAIL_PIC) {
		pr_dbg3("prologue has PC-relative addressing\n");
	}
}

static int x86_reg_index(int capstone_reg)
{
	int x86_regs[] = {
		X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX,
		X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
		X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
		X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(x86_regs); i++) {
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
static int handle_rel_jmp(cs_insn *insn, uint8_t insns[],
			  struct mcount_dynamic_info *mdi,
			  struct mcount_disasm_info *info)
{
	cs_x86 *x86 = &insn->detail->x86;
	uint8_t relocated_insn[ARCH_TRAMPOLINE_SIZE] = { 0xff, 0x25, };
	uint8_t opcode = insn->bytes[0];
	uint64_t target;
	struct cond_branch_info *cbi;
	cs_x86_op *opnd = &x86->operands[0];

#define JMP8_OPCODE  0xEB
#define JMP32_OPCODE 0xE9
#define OP   0
#define OFS  1

	if (x86->op_count != 1 || opnd->type != X86_OP_IMM)
		goto out;

	target = opnd->imm;
	/* disallow jump to middle of other function */
	if (info->addr > target || target >= info->addr + info->sym->size) {
		/* also mark the target function as invalid */
		if (mcount_add_badsym(mdi, insn->address, target))
			goto out;
	}

	if (opcode == JMP8_OPCODE || opcode == JMP32_OPCODE) {
		if (strcmp(insn->mnemonic, "jmp") != 0)
			goto out;

		memcpy(insns, relocated_insn, JMP_INSN_SIZE);
		memcpy(insns + JMP_INSN_SIZE, &target, sizeof(target));

		info->modified = true;
		/* 
		 * If this jump is the last insn in the prologue, we can ignore
		 * the one in patch_normal_func()
		 */
		if (info->orig_size + insn->size >= JMP32_INSN_SIZE)
			info->has_jump = true;

		return JMP_INSN_SIZE + sizeof(target);
	}
	/* Jump relative 8 if condition is met (except JCXZ, JECXZ and JRCXZ) */
	else if ((opcode & 0xF0) == 0x70) {
		cbi = &info->branch_info[info->nr_branch++];
		cbi->insn_index = info->copy_size;
		cbi->branch_target = target;
		cbi->insn_addr = insn->address;
		cbi->insn_size = insn->size;

		relocated_insn[OP] = opcode;
		relocated_insn[OFS] = 0x00;

		memcpy(insns, (void *)relocated_insn, JCC8_INSN_SIZE);

		info->modified = true;
		return JCC8_INSN_SIZE;
	}
	/* Jump relative 32 if condition is met */
	else if (opcode == 0x0F && (insn->bytes[1] & 0xF0) == 0x80) {
		cbi = &info->branch_info[info->nr_branch++];
		cbi->insn_index = info->copy_size;
		cbi->branch_target = target;
		cbi->insn_addr = insn->address;
		cbi->insn_size = insn->size;

		/* We use the equivalent jcc8 of the original jcc32 */
		relocated_insn[OP] = insn->bytes[1] - 0x10;
		relocated_insn[OFS] = 0x00;

		memcpy(insns, (void *)relocated_insn, JCC8_INSN_SIZE);
		
		info->modified = true;
		return JCC8_INSN_SIZE;
	}

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

/*
 *  handle LEA instruction.
 *
 *  this function manipulate the instruction like below,
 *    lea rcx, qword ptr [rip + 0x8f3f85]
 *  to this.
 *    mov rcx, [calculated PC + 0x8f3f85]
 */
static int handle_lea(cs_insn *insn, uint8_t insns[],
		      struct mcount_disasm_info *info)
{
	cs_x86 *x86 = &insn->detail->x86;
	cs_x86_op *opnd1;
	cs_x86_op *opnd2;
	uint64_t target;
	/*
	 * array for mov instruction: REX + OPCODE + IMM(8-byte)
	 * ex) mov rbx, 0x555556d35690
	 */
	uint8_t mov_insns[MOV_INSN_SIZE] = { 0x48, 0xb8, };
	int reg;

#define REX   0
#define OPC   1
#define IMM   2

	/* according to intel manual, lea instruction takes 2 operand */
	opnd1 = &x86->operands[0];
	opnd2 = &x86->operands[1];

	/* check PC-relative addressing mode */
	if (opnd1->type != X86_OP_REG || opnd2->type != X86_OP_MEM ||
	    opnd2->mem.base != X86_REG_RIP)
		goto out;

	/* the SIB addressing is not supported yet */
	if (opnd2->mem.scale > 1 || opnd2->mem.disp == 0)
		goto out;

	reg = x86_reg_index(opnd1->reg);
	if (reg < 0)
		goto out;

	/* set register index (high bit) */
	if (reg >= ARCH_NUM_BASE_REGS)
		mov_insns[REX]++;

	/* set register index (least 3 bits only) */
	mov_insns[OPC] |= reg & (ARCH_NUM_BASE_REGS - 1);

	/* update target address (PC + disp) */
	target = insn->address + insn->size + opnd2->mem.disp;
	memcpy(&mov_insns[IMM], &target, sizeof(target));

	memcpy(insns, mov_insns, sizeof(mov_insns));
	info->modified = true;

	return sizeof(mov_insns);

out:
	return -1;
}

/*
 *  handle MOV instruction (LOAD).
 *
 *  this function changes addressing mode of the instruction to use 8-byte
 *  immediate value.  For now it handles the case when the destination is a
 *  64-bit register.  For example, it'd change the following instruction
 *
 *    MOV rdi, qword ptr [rip + 0x8f3f85]
 *
 *  to this.
 *
 *    MOV rdi, [calculated PC + 0x8f3f85]  (= LEA)
 *    MOV rdi, qword ptr [rdi]
 */
static int handle_mov(cs_insn *insn, uint8_t insns[],
		      struct mcount_disasm_info *info)
{
	cs_x86 *x86 = &insn->detail->x86;
	uint8_t mov_insn[3] = { 0x48, 0x8b };
	int insn_size = sizeof(mov_insn);
	int reg;

	if (x86->rex) {
		/* we only support it when the destination is a register like LEA */
		if (handle_lea(insn, insns, info) < 0)
			goto out;

		reg = x86_reg_index(x86->operands[0].reg);
		if (reg < 0)
			goto out;

		/* set register index (high bit) */
		if (reg >= ARCH_NUM_BASE_REGS)
			mov_insn[REX] += 5;

		/* now we only care about the lower 3 bits */
		reg &= ARCH_NUM_BASE_REGS - 1;

		/* not support RSP, RBP, R12 and R13 due to addressing mode constraints */
		if (reg == 4 || reg == 5)
			return -1;

		/* set register index */
		mov_insn[2] = (reg << 3) | reg;  /* modrm.{reg,rm}*/

		/* skip the part handle_lea() added (= MOV_INSN_SIZE) */
		memcpy(insns + MOV_INSN_SIZE, mov_insn, insn_size);
	}
	else {
		uint8_t opcode = insn->bytes[0];
		/* this is actually MOVABS but we can think as LEA */
		uint8_t lea_insns[MOV_INSN_SIZE] = { 0x48, 0xb8, };
		uint64_t target;

#define MOV8_OPCODE   0x8a
#define MOV32_OPCODE  0x8b

		/* ignore insns with prefixes */
		if (opcode != MOV8_OPCODE && opcode != MOV32_OPCODE)
			goto out;

		/* extract modrm.reg */
		reg = (insn->bytes[1] >> 3) & 7;

		/* not support ESP, EBP due to addressing mode constraints */
		if (reg == 4 || reg == 5)
			return -1;

		lea_insns[OPC] |= reg;

		/* update target address (PC + disp) */
		target = insn->address + insn->size + x86->operands[1].mem.disp;
		memcpy(&lea_insns[IMM], &target, sizeof(target));

		memcpy(insns, lea_insns, sizeof(lea_insns));

		/* skip REX prefix */
		insn_size--;

		mov_insn[1] = opcode;
		/* set register index */
		mov_insn[2] = (reg << 3) | reg;  /* modrm.{reg,rm}*/

		memcpy(insns + sizeof(lea_insns), &mov_insn[1], insn_size);
	}

	info->modified = true;

	return MOV_INSN_SIZE + insn_size;

out:
	return -1;
}

/* handle position independent code (PIC) */
static int handle_pic(cs_insn *insn, uint8_t insns[],
		      struct mcount_disasm_info *info)
{
	if (insn->id == X86_INS_LEA)
		return handle_lea(insn, insns, info);
	if (insn->id == X86_INS_MOV &&
	    insn->detail->x86.operands[0].type == X86_OP_REG)
		return handle_mov(insn, insns, info);

	return -1;
}

static int manipulate_insns(cs_insn *insn, uint8_t insns[], int* fail_reason,
			    struct mcount_dynamic_info *mdi,
			    struct mcount_disasm_info *info)
{
	int res;

	pr_dbg3("manipulate instructions having PC-relative addressing.\n");

	switch (*fail_reason) {
	case INSTRUMENT_FAIL_RELJMP:
		res = handle_rel_jmp(insn, insns, mdi, info);
		break;
	case INSTRUMENT_FAIL_RELCALL:
		res = handle_call(insn, insns, info);
		break;
	case INSTRUMENT_FAIL_PIC:
		res = handle_pic(insn, insns, info);
		break;
	default:
		res = -1;
		break;
	}

	if (res > 0)
		*fail_reason = 0;
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
		status = INSTRUMENT_FAIL_NO_DETAIL;
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
				status |= INSTRUMENT_FAIL_PIC;
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
	unsigned long addr = info->addr;

	badsym = mcount_find_badsym(mdi, info->addr);
	if (badsym != NULL) {
		badsym->reverted = true;
		return INSTRUMENT_FAILED;
	}

	/*
	 * some compilers split cold part of the code into a separate function
	 * and it's likely to have a jump into original function body.  We need
	 * to skip those functions and allow the original function.
	 */
	size = strlen(info->sym->name);
	if (size > 5 && !strcmp(info->sym->name + size - 5, ".cold"))
		return INSTRUMENT_SKIPPED;

	size = info->sym->size;
	if (!memcmp((void *)info->addr, endbr64, sizeof(endbr64))) {
		addr += sizeof(endbr64);
		size -= sizeof(endbr64);

		if (size <= CALL_INSN_SIZE)
			return INSTRUMENT_SKIPPED;

		info->has_intel_cet = true;
	}

	count = cs_disasm(disasm->engine, (void *)addr, size, addr, 0, &insn);
	if (count == 0)
		return INSTRUMENT_FAILED;

	for (i = 0; i < count; i++) {
		uint8_t insns_byte[32] = { 0, };

		status = check_instrumentable(disasm, &insn[i]);
		if (status > 0)
			size = manipulate_insns(&insn[i], insns_byte,
						&status, mdi, info);
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

#ifdef UNIT_TEST

#define ORIGINAL_BASE  0x111122220000
#define CODEPAGE_BASE  0x555566660000

TEST_CASE(dynamic_x86_handle_lea)
{
	struct sym sym = { .name = "abc", .addr = 0x3000, .size = 32, };
	struct mcount_disasm_engine disasm;
	struct mcount_disasm_info info = {
		.sym  = &sym,
		.addr = ORIGINAL_BASE + sym.addr,
	};
	int count;
	cs_insn *insn = NULL;
	cs_x86 *x86;
	uint8_t lea_insn[7] = { 0x48, 0x8d, 0x05, 0x60, };  /* lea 0x60(%rip),%rax */
	uint8_t new_insns[16];
	int new_size;

	mcount_disasm_init(&disasm);

	pr_dbg("running capstone disassemler for LEA instruction\n");
	count = cs_disasm(disasm.engine, lea_insn, sizeof(lea_insn),
			  info.addr, 0, &insn);
	TEST_EQ(count, 1);

	x86 = &insn->detail->x86;

	TEST_EQ(insn->id, X86_INS_LEA);
	TEST_EQ(insn->address, info.addr);
	TEST_EQ(x86->op_count, 2);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_RAX);
	TEST_EQ(x86->operands[1].type, X86_OP_MEM);
	TEST_EQ(x86->operands[1].mem.base, X86_REG_RIP);
	TEST_EQ(x86->operands[1].mem.disp, 0x60);

	pr_dbg("handling LEA instruction\n");
	new_size = handle_pic(insn, new_insns, &info);
	TEST_EQ(new_size, 10);

	cs_free(insn, count);

	pr_dbg("checking modified instruction\n");
	count = cs_disasm(disasm.engine, new_insns, new_size,
			  CODEPAGE_BASE, 0, &insn);
	TEST_EQ(count, 1);

	x86 = &insn->detail->x86;

	TEST_EQ(insn->id, X86_INS_MOVABS);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_RAX);
	TEST_EQ(x86->operands[1].type, X86_OP_IMM);
	TEST_EQ(x86->operands[1].imm, info.addr + sizeof(lea_insn) + 0x60);

	cs_free(insn, count);

	mcount_disasm_finish(&disasm);

	return TEST_OK;
}

TEST_CASE(dynamic_x86_handle_call)
{
	struct sym sym1 = { .name = "a", .addr = 0x3000, .size = 32, };
	struct sym sym2 = { .name = "b", .addr = 0x4000, .size = 32, };
	struct mcount_disasm_engine disasm;
	struct mcount_disasm_info info = {
		.sym  = &sym1,
		.addr = ORIGINAL_BASE + sym1.addr,
	};
	int count;
	cs_insn *insn = NULL;
	cs_x86 *x86;
	uint8_t call_insn[5] = { 0xe8, 0xfb, 0x0f, };  /* 0xffb + 5 = 0x1000 */
	uint8_t new_insns[32];
	int new_size;
	uint64_t target = ORIGINAL_BASE + sym2.addr;

	mcount_disasm_init(&disasm);

	pr_dbg("running capstone disassemler for CALL instruction\n");
	count = cs_disasm(disasm.engine, call_insn, sizeof(call_insn),
			  info.addr, 0, &insn);
	TEST_EQ(count, 1);

	x86 = &insn->detail->x86;

	TEST_EQ(insn->id, X86_INS_CALL);
	TEST_EQ(insn->address, info.addr);
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_IMM);
	TEST_EQ(x86->operands[0].imm, target);

	pr_dbg("handling CALL instruction\n");
	new_size = handle_call(insn, new_insns, &info);
	TEST_EQ(new_size, 28);

	cs_free(insn, count);

	pr_dbg("checking modified instruction\n");
	count = cs_disasm(disasm.engine, new_insns, 12 /* actual insn size */,
			  CODEPAGE_BASE, 0, &insn);
	TEST_EQ(count, 2);

	TEST_EQ(insn[0].id, X86_INS_PUSH);
	TEST_EQ(insn[0].address, CODEPAGE_BASE);
	x86 = &insn[0].detail->x86;
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_MEM);
	TEST_EQ(x86->operands[0].mem.base, X86_REG_RIP);
	TEST_EQ(x86->operands[0].mem.disp, 6);

	memcpy(&target, &new_insns[12], sizeof(target));
	TEST_EQ(target, info.addr + CALL_INSN_SIZE);

	TEST_EQ(insn[1].id, X86_INS_JMP);
	TEST_EQ(insn[1].address, CODEPAGE_BASE + 6);
	x86 = &insn[0].detail->x86;
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_MEM);
	TEST_EQ(x86->operands[0].mem.base, X86_REG_RIP);
	TEST_EQ(x86->operands[0].mem.disp, 6);

	memcpy(&target, &new_insns[20], sizeof(target));
	TEST_EQ(target, ORIGINAL_BASE + sym2.addr);

	cs_free(insn, count);

	mcount_disasm_finish(&disasm);

	return TEST_OK;
}

TEST_CASE(dynamic_x86_handle_jmp)
{
	struct sym sym = { .name = "a", .addr = 0x3000, .size = 32, };
	struct mcount_disasm_engine disasm;
	struct mcount_disasm_info info = {
		.sym  = &sym,
		.addr = ORIGINAL_BASE + sym.addr,
	};
	int count;
	cs_insn *insn = NULL;
	cs_x86 *x86;
	uint8_t jmp8_insn[2] = { 0xeb, 0x0e, };   /* 0xe + 2 = 0x10 */
	uint8_t jmp32_insn[5] = { 0xe9, 0x0b, };  /* 0xb + 5 = 0x10 */
	uint8_t new_insns[32];
	int new_size;
	uint64_t target = info.addr + 0x10;

	mcount_disasm_init(&disasm);

	pr_dbg("running capstone disassemler for JMP8 instruction\n");
	count = cs_disasm(disasm.engine, jmp8_insn, sizeof(jmp8_insn),
			  info.addr, 0, &insn);
	TEST_EQ(count, 1);

	x86 = &insn->detail->x86;

	TEST_EQ(insn->id, X86_INS_JMP);
	TEST_EQ(insn->address, info.addr);
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_IMM);
	TEST_EQ(x86->operands[0].imm, target);

	pr_dbg("handling JMP instruction\n");
	new_size = handle_rel_jmp(insn, new_insns, NULL, &info);
	TEST_EQ(new_size, 14);

	cs_free(insn, count);

	pr_dbg("checking modified instruction\n");
	count = cs_disasm(disasm.engine, new_insns, JMP_INSN_SIZE,
			  CODEPAGE_BASE, 0, &insn);
	TEST_EQ(count, 1);

	TEST_EQ(insn->id, X86_INS_JMP);
	TEST_EQ(insn->address, CODEPAGE_BASE);
	x86 = &insn->detail->x86;
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_MEM);
	TEST_EQ(x86->operands[0].mem.base, X86_REG_RIP);
	TEST_EQ(x86->operands[0].mem.disp, 0);

	memcpy(&target, &new_insns[6], sizeof(target));
	TEST_EQ(target, info.addr + 0x10);

	cs_free(insn, count);

	pr_dbg("running capstone disassemler for JMP32 instruction\n");
	count = cs_disasm(disasm.engine, jmp32_insn, sizeof(jmp32_insn),
			  info.addr, 0, &insn);
	TEST_EQ(count, 1);

	x86 = &insn->detail->x86;

	TEST_EQ(insn->id, X86_INS_JMP);
	TEST_EQ(insn->address, info.addr);
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_IMM);
	TEST_EQ(x86->operands[0].imm, target);

	pr_dbg("handling JMP instruction\n");
	new_size = handle_rel_jmp(insn, new_insns, NULL, &info);
	TEST_EQ(new_size, 14);

	cs_free(insn, count);

	pr_dbg("checking modified instruction\n");
	count = cs_disasm(disasm.engine, new_insns, JMP_INSN_SIZE,
			  CODEPAGE_BASE, 0, &insn);
	TEST_EQ(count, 1);

	TEST_EQ(insn->id, X86_INS_JMP);
	TEST_EQ(insn->address, CODEPAGE_BASE);
	x86 = &insn->detail->x86;
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_MEM);
	TEST_EQ(x86->operands[0].mem.base, X86_REG_RIP);
	TEST_EQ(x86->operands[0].mem.disp, 0);

	memcpy(&target, &new_insns[6], sizeof(target));
	TEST_EQ(target, info.addr + 0x10);

	cs_free(insn, count);

	mcount_disasm_finish(&disasm);

	return TEST_OK;
}

TEST_CASE(dynamic_x86_handle_jcc)
{
	struct sym sym = { .name = "a", .addr = 0x3000, .size = 32, };
	struct mcount_disasm_engine disasm;
	struct mcount_disasm_info info = {
		.sym  = &sym,
		.addr = ORIGINAL_BASE + sym.addr,
	};
	int count;
	cs_insn *insn = NULL;
	cs_x86 *x86;
	uint8_t jcc8_insn[2] = { 0x74, 0x0e, };         /* 0x0e + 2 = 0x10 */
	uint8_t jcc32_insn[6] = { 0x0f, 0x85, 0x0a, };  /* 0x0a + 6 = 0x10 */
	uint8_t new_insns[32];
	int new_size;
	uint64_t target = info.addr + 0x10;

	mcount_disasm_init(&disasm);

	pr_dbg("running capstone disassemler for Jcc8 instruction\n");
	count = cs_disasm(disasm.engine, jcc8_insn, sizeof(jcc8_insn),
			  info.addr, 0, &insn);
	TEST_EQ(count, 1);

	x86 = &insn->detail->x86;

	TEST_EQ(insn->id, X86_INS_JE);
	TEST_EQ(insn->address, info.addr);
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_IMM);
	TEST_EQ(x86->operands[0].imm, target);

	pr_dbg("handling JE instruction\n");
	new_size = handle_rel_jmp(insn, new_insns, NULL, &info);
	TEST_EQ(new_size, 2);

	cs_free(insn, count);

	pr_dbg("checking modified instruction\n");
	count = cs_disasm(disasm.engine, new_insns, 2,
			  CODEPAGE_BASE, 0, &insn);
	TEST_EQ(count, 1);

	TEST_EQ(insn->id, X86_INS_JE);
	TEST_EQ(insn->address, CODEPAGE_BASE);
	x86 = &insn->detail->x86;
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_IMM);
	TEST_EQ(x86->operands[0].imm, CODEPAGE_BASE + 2);

	TEST_EQ(info.nr_branch, 1);
	TEST_EQ(info.branch_info[0].insn_index, 0);
	TEST_EQ(info.branch_info[0].branch_target, target);
	TEST_EQ(info.branch_info[0].insn_addr, info.addr);
	TEST_EQ(info.branch_info[0].insn_size, sizeof(jcc8_insn));

	cs_free(insn, count);

	pr_dbg("running capstone disassemler for Jcc32 instruction\n");
	count = cs_disasm(disasm.engine, jcc32_insn, sizeof(jcc32_insn),
			  info.addr, 0, &insn);
	TEST_EQ(count, 1);

	x86 = &insn->detail->x86;

	TEST_EQ(insn->id, X86_INS_JNE);
	TEST_EQ(insn->address, info.addr);
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_IMM);
	TEST_EQ(x86->operands[0].imm, target);

	pr_dbg("handling JNE instruction\n");
	new_size = handle_rel_jmp(insn, new_insns, NULL, &info);
	TEST_EQ(new_size, 2);

	cs_free(insn, count);

	pr_dbg("checking modified instruction\n");
	count = cs_disasm(disasm.engine, new_insns, 2,
			  CODEPAGE_BASE, 0, &insn);
	TEST_EQ(count, 1);

	TEST_EQ(insn->id, X86_INS_JNE);
	TEST_EQ(insn->address, CODEPAGE_BASE);
	x86 = &insn->detail->x86;
	TEST_EQ(x86->op_count, 1);
	TEST_EQ(x86->operands[0].type, X86_OP_IMM);
	TEST_EQ(x86->operands[0].imm, CODEPAGE_BASE + 2);

	TEST_EQ(info.nr_branch, 2);
	TEST_EQ(info.branch_info[1].insn_index, 0);
	TEST_EQ(info.branch_info[1].branch_target, target);
	TEST_EQ(info.branch_info[1].insn_addr, info.addr);
	TEST_EQ(info.branch_info[1].insn_size, sizeof(jcc32_insn));

	cs_free(insn, count);

	mcount_disasm_finish(&disasm);

	return TEST_OK;
}

TEST_CASE(dynamic_x86_handle_mov_load)
{
	struct sym sym = { .name = "abc", .addr = 0x3000, .size = 32, };
	struct mcount_disasm_engine disasm;
	struct mcount_disasm_info info = {
		.sym  = &sym,
		.addr = ORIGINAL_BASE + sym.addr,
	};
	int count;
	cs_insn *insn = NULL;
	cs_x86 *x86;
	uint8_t mov64_insn[7] = { 0x48, 0x8b, 0x3d, 0x64 };  /* mov 0x64(%rip),%rdi */
	uint8_t mov32_insn[6] = { 0x8b, 0x0d, 0x32 };        /* mov 0x32(%rip),%ecx */
	uint8_t mov8_insn[6] = { 0x8a, 0x05, 0x08 };         /* mov 0x08(%rip),%al */
	uint8_t new_insns[16];
	int new_size;

	mcount_disasm_init(&disasm);

	/* 1. 64-bit MOV (with REX) */
	pr_dbg("running capstone disassemler for MOV instruction\n");
	count = cs_disasm(disasm.engine, mov64_insn, sizeof(mov64_insn),
			  info.addr, 0, &insn);
	TEST_EQ(count, 1);

	x86 = &insn->detail->x86;

	TEST_EQ(insn->id, X86_INS_MOV);
	TEST_EQ(insn->address, info.addr);
	TEST_EQ(x86->op_count, 2);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_RDI);
	TEST_EQ(x86->operands[1].type, X86_OP_MEM);
	TEST_EQ(x86->operands[1].mem.base, X86_REG_RIP);
	TEST_EQ(x86->operands[1].mem.disp, 0x64);

	pr_dbg("handling MOV instruction (64-bit load)\n");
	new_size = handle_pic(insn, new_insns, &info);
	TEST_EQ(new_size, 13);

	cs_free(insn, count);

	pr_dbg("checking modified instruction\n");
	count = cs_disasm(disasm.engine, new_insns, new_size,
			  CODEPAGE_BASE, 0, &insn);
	TEST_EQ(count, 2);

	x86 = &insn[0].detail->x86;

	TEST_EQ(insn[0].id, X86_INS_MOVABS);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_RDI);
	TEST_EQ(x86->operands[1].type, X86_OP_IMM);
	TEST_EQ(x86->operands[1].imm, info.addr + sizeof(mov64_insn) + 0x64);

	x86 = &insn[1].detail->x86;

	TEST_EQ(insn[1].id, X86_INS_MOV);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_RDI);
	TEST_EQ(x86->operands[1].type, X86_OP_MEM);
	TEST_EQ(x86->operands[1].mem.base, X86_REG_RDI);
	TEST_EQ(x86->operands[1].mem.disp, 0);

	cs_free(insn, count);

	/* 2. 32-bit MOV (without REX) */
	pr_dbg("running capstone disassemler for MOV instruction\n");
	count = cs_disasm(disasm.engine, mov32_insn, sizeof(mov32_insn),
			  info.addr, 0, &insn);
	TEST_EQ(count, 1);

	x86 = &insn->detail->x86;

	TEST_EQ(insn->id, X86_INS_MOV);
	TEST_EQ(insn->address, info.addr);
	TEST_EQ(x86->op_count, 2);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_ECX);
	TEST_EQ(x86->operands[1].type, X86_OP_MEM);
	TEST_EQ(x86->operands[1].mem.base, X86_REG_RIP);
	TEST_EQ(x86->operands[1].mem.disp, 0x32);

	pr_dbg("handling MOV instruction (32-bit load)\n");
	new_size = handle_pic(insn, new_insns, &info);
	TEST_EQ(new_size, 12);

	cs_free(insn, count);

	pr_dbg("checking modified instruction\n");
	count = cs_disasm(disasm.engine, new_insns, new_size,
			  CODEPAGE_BASE, 0, &insn);
	TEST_EQ(count, 2);

	x86 = &insn[0].detail->x86;

	TEST_EQ(insn[0].id, X86_INS_MOVABS);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_RCX);
	TEST_EQ(x86->operands[1].type, X86_OP_IMM);
	TEST_EQ(x86->operands[1].imm, info.addr + sizeof(mov32_insn) + 0x32);

	x86 = &insn[1].detail->x86;

	TEST_EQ(insn[1].id, X86_INS_MOV);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_ECX);
	TEST_EQ(x86->operands[1].type, X86_OP_MEM);
	TEST_EQ(x86->operands[1].mem.base, X86_REG_RCX);
	TEST_EQ(x86->operands[1].mem.disp, 0);

	cs_free(insn, count);

	/* 3. 8-bit MOV (with a different OPCODE) */
	pr_dbg("running capstone disassemler for MOV instruction\n");
	count = cs_disasm(disasm.engine, mov8_insn, sizeof(mov8_insn),
			  info.addr, 0, &insn);
	TEST_EQ(count, 1);

	x86 = &insn->detail->x86;

	TEST_EQ(insn->id, X86_INS_MOV);
	TEST_EQ(insn->address, info.addr);
	TEST_EQ(x86->op_count, 2);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_AL);
	TEST_EQ(x86->operands[1].type, X86_OP_MEM);
	TEST_EQ(x86->operands[1].mem.base, X86_REG_RIP);
	TEST_EQ(x86->operands[1].mem.disp, 0x8);

	pr_dbg("handling MOV instruction (8-bit load)\n");
	new_size = handle_pic(insn, new_insns, &info);
	TEST_EQ(new_size, 12);

	cs_free(insn, count);

	pr_dbg("checking modified instruction\n");
	count = cs_disasm(disasm.engine, new_insns, new_size,
			  CODEPAGE_BASE, 0, &insn);
	TEST_EQ(count, 2);

	x86 = &insn[0].detail->x86;

	TEST_EQ(insn[0].id, X86_INS_MOVABS);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_RAX);
	TEST_EQ(x86->operands[1].type, X86_OP_IMM);
	TEST_EQ(x86->operands[1].imm, info.addr + sizeof(mov8_insn) + 0x8);

	x86 = &insn[1].detail->x86;

	TEST_EQ(insn[1].id, X86_INS_MOV);
	TEST_EQ(x86->operands[0].type, X86_OP_REG);
	TEST_EQ(x86->operands[0].reg, X86_REG_AL);
	TEST_EQ(x86->operands[1].type, X86_OP_MEM);
	TEST_EQ(x86->operands[1].mem.base, X86_REG_RAX);
	TEST_EQ(x86->operands[1].mem.disp, 0);

	cs_free(insn, count);

	mcount_disasm_finish(&disasm);

	return TEST_OK;
}
#endif  /* UNIT_TEST */

#else /* HAVE_LIBCAPSTONE */

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	return INSTRUMENT_FAILED;
}

#endif /* HAVE_LIBCAPSTONE */
