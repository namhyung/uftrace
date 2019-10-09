#include "libmcount/internal.h"
#include "mcount-arch.h"

#define CALL_INSN_SIZE  5

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#include <capstone/platform.h>

#define MAX_INSNS_BYTES			128

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
static int handle_pic(cs_insn *insn, uint8_t insns[])
{
	cs_x86 *x86 = &insn->detail->x86;

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
	*(uint64_t *)&mov_insns[IMM] = PC_base;

	memcpy(insns, (void *)mov_insns, sizeof(mov_insns));

	return sizeof(mov_insns);

out:
	return -1;
}

static int manipulate_insns(cs_insn *insn, uint8_t insns[], int* fail_reason)
{
	int res = -1;

	pr_dbg3("Try to instrument if instruction could be manipulate possibly.\n");

	switch (*fail_reason) {
		case INSTRUMENT_FAIL_PICCODE:
			res = handle_pic(insn, insns);
			if (res > 0) {
				*fail_reason ^= INSTRUMENT_FAIL_PICCODE;
			}
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

		switch((int)op->type) {
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

static bool check_unsupported(struct mcount_disasm_engine *disasm, cs_insn *insn,
			      struct mcount_dynamic_info *mdi,
			      struct disasm_check_data *insn_check)
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
			if (insn_check->addr <= target &&
			    target < insn_check->addr + insn_check->copy_size)
				return false;

			/* disallow jump to middle of other function */
			if (insn_check->addr > target ||
			    target >= insn_check->addr + insn_check->func_size) {
				/* also mark the target function as invalid */
				return !add_bad_jump(mdi, insn->address, target);
			}
			break;
		case X86_OP_MEM:
			/* indirect jumps are not allowed */
			return false;
		case X86_OP_REG:
			return false;
		default:
			break;
		}
	}

	return true;
}


struct mcount_instrument_info *
disasm_check_insns(struct mcount_disasm_engine *disasm,
		   struct mcount_dynamic_info *mdi, struct sym *sym)
{
	cs_insn *insn = NULL;
	int status;
	uint32_t count, i, insns_size;
	uint8_t insns_byte[MAX_INSNS_BYTES] = {0, };
	uint8_t endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
	struct disasm_check_data insn_check = {
		.addr		= sym->addr + mdi->map->start,
		.func_size	= sym->size,
	};
	struct dynamic_bad_symbol *badsym;
	struct mcount_instrument_info *info = xzalloc(sizeof(*info));

	info->addr = sym->addr + mdi->map->start;
	info->func_size = sym->size;

	badsym = find_bad_jump(mdi, insn_check.addr);
	if (badsym != NULL) {
		list_del(&badsym->list);
		free(badsym);
		info->size = INSTRUMENT_FAILED;
		return info;
	}

	count = cs_disasm(disasm->engine, (void *)insn_check.addr, sym->size,
			  insn_check.addr, 0, &insn);
	if (unlikely(count == 0) &&
	    !memcmp((void *)insn_check.addr, endbr64, sizeof(endbr64))) {
		/* old version of capstone doesn't recognize ENDBR64 insn */
		insn_check.addr += sizeof(endbr64);
		insn_check.func_size -= sizeof(endbr64);
		insn_check.copy_size += sizeof(endbr64);

		count = cs_disasm(disasm->engine, (void *)insn_check.addr,
				  insn_check.func_size, insn_check.addr,
				  insn_check.addr, &insn);
	}

	for (i = 0; i < count; i++) {
		memset(insns_byte, 0, MAX_INSNS_BYTES);
		status = check_instrumentable(disasm, &insn[i]);

		if (status > 0)
			insns_size = manipulate_insns(&insn[i], insns_byte, &status);
		else
			insns_size = copy_insn_bytes(&insn[i], insns_byte);

		if (status > 0) {
			info->size = INSTRUMENT_FAILED;
			pr_dbg3("not supported instruction found at %s : %s\t %s\n",
				sym->name, insn[i].mnemonic, insn[i].op_str);
			goto out;
		}

		info->insns = xrealloc(info->insns,
				       info->insns_size + insns_size);
		memcpy(info->insns + info->insns_size, insns_byte, insns_size);
		info->insns_size += insns_size;
		insn_check.copy_size += insn[i].size;
		info->size += insn[i].size;

		if (insn_check.copy_size >= CALL_INSN_SIZE)
			break;
	}

	while (++i < count) {
		if (!check_unsupported(disasm, &insn[i], mdi, &insn_check)) {
			info->size = INSTRUMENT_FAILED;
			break;
		}
	}

out:
	if (count)
		cs_free(insn, count);

	return info;
}

#else /* HAVE_LIBCAPSTONE */

struct mcount_instrument_info *
disasm_check_insns(struct mcount_disasm_engine *disasm,
		   struct mcount_dynamic_info *mdi, struct sym *sym)
{
	struct mcount_instrument_info *info = xzalloc(sizeof(*info));

	info->size = INSTRUMENT_FAILED;
	return info;
}

#endif /* HAVE_LIBCAPSTONE */
