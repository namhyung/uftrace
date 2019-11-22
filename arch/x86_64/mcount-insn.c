#include "libmcount/internal.h"
#include "mcount-arch.h"
#include "x64_modrm.h"

#define CALL_INSN_SIZE  5

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
		pr_dbg3("Not supported opcode without operand\n");
	}
	if (reason & INSTRUMENT_FAIL_RELJMP) {
		pr_dbg3("Not supported opcode that jump to relative address\n");
	}
	if (reason & INSTRUMENT_FAIL_RELCALL) {
		pr_dbg3("Not supported opcode that call to relative address\n");
	}
	if (reason & INSTRUMENT_FAIL_PICCODE) {
		pr_dbg3("Not supported Position Independent Code\n");
	}
}

/*
 *  Get Register order in modrm table from capstone register
 */
static int modrm_order(int capstone_reg)
{
	size_t i;

	uint8_t x86_regs[] = {
		X86_REG_EAX, X86_REG_ECX, X86_REG_EDX, X86_REG_EBX,
		X86_REG_ESP, X86_REG_EBP, X86_REG_ESI, X86_REG_EDI,
	};
	uint8_t x64_regs[] = {
		X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX,
		X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
	};
	uint8_t x64_expand_regs[] = {
		X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
		X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
	};


	if (X86_REG_EAX <= capstone_reg && capstone_reg <= X86_REG_ESP) {
		for (i = 0; i < sizeof(x86_regs); i++) {
			if (capstone_reg == x86_regs[i])
				return i;
		}
	}
	else if (X86_REG_RAX <= capstone_reg && capstone_reg <= X86_REG_RSP) {
		for (i = 0; i < sizeof(x64_regs); i++) {
			if (capstone_reg == x64_regs[i])
				return i;
		}
	}
	else if (X86_REG_R8 <= capstone_reg && capstone_reg <= X86_REG_R15) {
		for (i = 0; i < sizeof(x64_expand_regs); i++) {
			if (capstone_reg == x64_expand_regs[i])
				return i;
		}
	}

	return -1;
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
 *  handle PIC code.
 *  for currently, this function targeted specific type of instruction.
 *
 *  this function manipulate the instruction like below,
 *    lea rcx, qword ptr [rip + 0x8f3f85]
 *  to this.
 *    mov rcx, [calculated PC + 0x8f3f85]
 */
static int handle_pic_lea(cs_insn *insn, uint8_t insns[],
		      struct mcount_disasm_info *info)
{
	cs_x86 *x86 = &insn->detail->x86;
	static const int REX = 0;
	static const int OPND = 1;
	static const int IMM = 2;

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
	cs_x86_op *opnd1 = &x86->operands[0];
	cs_x86_op *opnd2 = &x86->operands[1];

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

	uint64_t PC_base = insn->address + insn->size + opnd2->mem.disp;
	memcpy(&mov_insns[IMM], &PC_base, sizeof(PC_base));

	memcpy(insns, mov_insns, sizeof(mov_insns));
	info->modified = true;

	return sizeof(mov_insns);

out:
	return -1;
}

/*
 *  handle PIC code for MOV instruction.
 *  this function manipulate the instruction.
 *
 *  for examples :
 *
 *  case LOAD:
 *	mov rcx, qword ptr [rip + 0x8f3f85]
 *  to manipulate like below:
 *	push rax
 *	mov rax, PC_BASE + 0x8f3f85
 *	mov rcx, [rax]
 *	pop rax
 *
 *  case STORE:
 *  	mov qword ptr [rip+0x8f3f85], rcx
 *  to manipulate like below:
 *	push rax
 *	mov rax, PC_BASE + 0x8f3f85
 *	mov [rax], rcx
 *	pop rax
 *
 *  exceptional case in LOAD :
 *  	mov rax, qword ptr [rip+0x8f3f85]
 *  this will change like below:
 * 	xchg rax, rcx
 *  	push rax
 *  	mov rax, PC_BASE + 0x8f3f85
 *  	mov rcx, [rax]
 *  	pop rax
 *  	xchg rax, rcx
 *
 *  exceptional case in STORE :
 *  	mov qword ptr [rip+0x8f3f85], rax
 *  to manipulate like below:
 *  	xchg rax, rcx
 *	push rax
 *	mov rax, PC_BASE + 0x8f3f85
 *	mov [rax], rcx
 *	pop rax
 *	xchg rax, rcx
 *
 */
static int handle_pic_mov(cs_insn *insn, uint8_t insns[],
		      struct mcount_disasm_info *info)
{
	struct MODRM modrm;
	int modrm_rows, modrm_cols;
	effect_t effect_opnd;
	uint64_t PC_base;

	cs_x86 *x86 = &insn->detail->x86;
	cs_x86_op *opnd1 = &x86->operands[0];
	cs_x86_op *opnd2 = &x86->operands[1];

	static const int NEED_XCHG = 0;
	static const int NON_XCHG = 2;
	static const int LOAD = 0;
	static const int STORE = 1;

	int adjust = NON_XCHG;
	int insns_type = LOAD;

	// typically instruction elements.
	uint8_t mov_insns[20] = {0xCC};
	int insns_size;
	enum mov_insn_map {
		XCHG_1 = 0,
		PUSH = 2,
		REX_P,
		OP,
		IMM,
		IMM_END = 12,
		REX_P2 = 13,
		PREFIX_P2 = 13,
		OP2,
		MODRM,
		POP = 16,
		XCHG_2,
	};

	/* support MOV instruction only */
	if (strcmp(insn->mnemonic, "mov") != 0)
		goto out;

	/* check PC-relative addressing mode */
	if (opnd1->type == X86_OP_MEM && opnd1->mem.base == X86_REG_RIP) {
		insns_type = STORE;
	}
	else if (opnd2->type == X86_OP_MEM && opnd2->mem.base == X86_REG_RIP) {
		insns_type = LOAD;
	}
	else
		goto out;

	/* the SIB addressing is not supported yet */
	if (opnd1->mem.scale > 1 || opnd2->mem.scale > 1)
		goto out;

	/* for handle exceptional case, */
	if (insns_type == LOAD) {
		/* for now, support only 64bit registere */
		if (!(X86_REG_RAX <= opnd1->reg && opnd1->reg <= X86_REG_R15))
			goto out;

		if (opnd1->reg == X86_REG_RAX)
			adjust = NEED_XCHG;

		PC_base = insn->address + insn->size + opnd2->mem.disp;

		if (X86_REG_RAX <= opnd1->reg && opnd1->reg <= X86_REG_RSP)
			mov_insns[REX_P2 - adjust] = 0x48;
		else if (X86_REG_R8 <= opnd1->reg && opnd1->reg <= X86_REG_R15)
			mov_insns[REX_P2 - adjust] = 0x4C;
		else
			goto out;

		mov_insns[OP2 - adjust] = 0x8b;
		modrm_cols = RAX;
		effect_opnd = effect_OP2;

		if (adjust == NEED_XCHG)
			modrm_rows = RCX;
		else
			modrm_rows = modrm_order(opnd1->reg);
	}
	else if (insns_type == STORE) {
		/* for now, support only 64bit registere */
		if (!(X86_REG_RAX <= opnd2->reg && opnd2->reg <= X86_REG_RSP))
			goto out;

		if (opnd2->reg == X86_REG_RAX)
			adjust = NEED_XCHG;

		PC_base = insn->address + insn->size + opnd1->mem.disp;

		if (X86_REG_RAX <= opnd2->reg && opnd2->reg <= X86_REG_RSP)
			mov_insns[REX_P2 - adjust] = 0x48;
		else if (X86_REG_R8 <= opnd2->reg && opnd2->reg <= X86_REG_R15)
			mov_insns[REX_P2 - adjust] = 0x4C;
		else
			goto out;

		mov_insns[OP2 - adjust] = 0x89;
		modrm_rows = RAX;
		effect_opnd = effect_OP1;

		if (adjust == NEED_XCHG)
			modrm_cols = RCX;
		else
			modrm_cols = modrm_order(opnd2->reg);

	}

	memcpy(&mov_insns[IMM - adjust], &PC_base, sizeof(PC_base));

	if (adjust == NEED_XCHG) {
		mov_insns[XCHG_1 - adjust] = 0x48;
		mov_insns[XCHG_1 - adjust + 1] = 0x91;
		mov_insns[XCHG_2 - adjust] = 0x48;
		mov_insns[XCHG_2 - adjust + 1] = 0x91;
	}

	/* build common instruction body */
	mov_insns[PUSH - adjust] = 0x50;
	mov_insns[POP - adjust] = 0x58;
	mov_insns[REX_P - adjust] = 0x48;
	mov_insns[OP - adjust] = 0xb8;

	calc_modrm_x64(modrm_rows, modrm_cols, effect_opnd, disp_none, &modrm);
	mov_insns[MODRM - adjust] = modrm_to_byte(modrm);
	info->modified = true;

	if (adjust == NEED_XCHG) {
		/* for xchg, need 2bytes */
		insns_size = XCHG_2 + 2;
		memcpy(insns, mov_insns, insns_size);
		return insns_size;
	} else if (adjust == NON_XCHG) {
		/* for pop, only 1byte needs. */
		insns_size = POP - adjust + 1;
		memcpy(insns, mov_insns, insns_size);
		return insns_size;
	}

out:
	return -1;
}


static int handle_pic(cs_insn *insn, uint8_t insns[],
		      struct mcount_disasm_info *info)
{
	/* for now, support LEA instruction only */
	if (strcmp(insn->mnemonic, "lea") == 0) {
		return handle_pic_lea(insn, insns, info);
	} else if (strcmp(insn->mnemonic, "mov") == 0) {
		return handle_pic_mov(insn, insns, info);
	}

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

	pr_dbg3("Manipulate instructions having PC-relative addressing.\n");

	switch (*fail_reason) {
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
	if (status > 0)
		print_instrument_fail_msg(status);

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
			    target < info->addr + info->orig_size)
				return false;

			/* disallow jump to middle of other function */
			if (info->addr > target ||
			    target >= info->addr + info->sym->size) {
				/* also mark the target function as invalid */
				return !mcount_add_badsym(mdi, insn->address,
							  target);
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
			status = INSTRUMENT_FAILED;
			pr_dbg3("not supported instruction found at %s : %s\t %s\n",
				info->sym->name, insn[i].mnemonic, insn[i].op_str);
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
