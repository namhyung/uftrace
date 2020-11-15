#include "libmcount/internal.h"
#include "mcount-arch.h"

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

static int opnd_orig_reg(int capstone_reg)
{

#define PADDING X86_REG_ENDING + 1
#define COLUMN_SIZE 5

	uint8_t x86_regs[] = {
		X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_EAX, X86_REG_RAX,
		X86_REG_CH, X86_REG_CL, X86_REG_CX, X86_REG_ECX, X86_REG_RCX,
		X86_REG_DH, X86_REG_DL, X86_REG_DX, X86_REG_EDX, X86_REG_RDX,
		X86_REG_BH, X86_REG_BL, X86_REG_BX, X86_REG_EBX, X86_REG_RBX,
		X86_REG_SPL, X86_REG_SP, X86_REG_ESP, X86_REG_RSP, PADDING,
		X86_REG_BPL, X86_REG_BP, X86_REG_EBP, X86_REG_RBP, PADDING,
		X86_REG_SIL, X86_REG_SI, X86_REG_ESI, X86_REG_RSI, PADDING,
		X86_REG_DIL, X86_REG_DI, X86_REG_EDI, X86_REG_RDI, PADDING,
	};
	size_t i;

	for (i = 0; i < sizeof(x86_regs); i++) {
		if (capstone_reg == x86_regs[i])
			return i / COLUMN_SIZE;
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
 * We should be careful as some instructions implicitly use registers.
 * For instance, cmpxchg implicitly use ax. Using ax as a scratch register
 * when relocating cmpxchg will most probably alter the program's execution
 * flow.
 */
static uint8_t find_scratch_register(const cs_insn* insn)
{
	cs_x86 *x86 = &insn->detail->x86;
	bool implicitly_used;
	int reg;
	uint8_t i;
	uint8_t j;

	struct candidate_reg {
		bool available;
		const char* implicit_users[15];
		const uint8_t count;
	};

	/*
	 * Instructions that implicity use registers:
	 *
	 * mulx:
	 *   EDX, RDX => dx
	 * div/idiv/mul/imul:
	 *   AX, DX, EDX, EAX, RDX, RAX => ax, dx
	 * cmpxchg:
	 *   AL, AX, EAX, RAX => ax
	 * cmpxchg8b/cmpxchg16b:
	 *   EAX, EDX, ECX, EBX, RAX, RDX, RCX, RBX => ax, bx, cx, dx
	 * pop:
	 *   RSP
	 *
	 * TODO: add more instructions.
	 */
	struct candidate_reg regs[8]={
		{true, {"idiv", "imul", "mul", "div", "cmpxchg",
				"cmpxchg8b","cmpxchg16b"}, 7}, /* ax */
		{true, {"cmpxchg8b", "cmpxchg16b", }, 2}, /* cx */
		{true, {"idiv", "imul", "mul", "div", "cmpxchg8b",
				"cmpxchg16b", "mulx"}, 7}, /* dx */
		{true, {"cmpxchg8b", "cmpxchg16b"}, 2}, /* bx */
		{true, {"push", "pop", "call"}, 3}, /* sp */
		{true, {}, }, /* bp */
		{true, {}, }, /* si */
		{true, {}, }, /* di */
	};

	/* Look for unavailable scratch registers that are used by the insn */
	for (i = 0; i < x86->op_count; i++) {
		if (x86->operands[i].type == X86_OP_REG) {
			reg = opnd_orig_reg(x86->operands[i].reg);
			if(reg >= 0)
				regs[reg].available = false;

		} else if (x86->operands[i].type == X86_OP_MEM) {
			reg = opnd_orig_reg(x86->operands[i].mem.base);
			if(reg >= 0)
				regs[reg].available = false;

			reg = opnd_orig_reg(x86->operands[i].mem.index);
			if(reg >= 0)
				regs[reg].available = false;
		}
	}

	/* Find an available and implicitly unused scratch register  */
	for (i = 0; i < sizeof(regs) / sizeof(struct candidate_reg); i++) {
		if (regs[i].available) {
			implicitly_used = false;

			for (j = 0; j < regs[i].count; j++) {
				if (!strcmp(regs[i].implicit_users[j], insn->mnemonic)) {
					implicitly_used = true;
					break;
				}
			}

			if(implicitly_used)
				continue;
			else
				return i;
		}
	}

	return 255;
}

/* FIXME: using same function name from Linux code. I'am wondering if it's okay IANAL :/ */
static inline int insn_offset_rex_prefix(cs_insn *insn)
{
	cs_x86 *x86 = &insn->detail->x86;
	int count = 0;

#define IRRELEVANT_PREFIX 0
#define PREFIX_LENGTH 4

	for(uint8_t i = 0; i < PREFIX_LENGTH; i++) {
		count += x86->prefix[i] != IRRELEVANT_PREFIX ? 1 : 0;
	}

	return count;
}

static inline int insn_offset_opcode(cs_insn *insn)
{
#define IRRELEVANT_PREFIX 0
	return insn_offset_rex_prefix(insn) + (insn->detail->x86.rex != IRRELEVANT_PREFIX ? 1 : 0);
}

static inline int insn_offset_modrm(cs_insn *insn)
{
	cs_x86 *x86 = &insn->detail->x86;
	int count = 0;

#define IRRELEVANT_OPCODE 0
#define OPCODE_LENGTH 4

	for(uint8_t i = 0; i < OPCODE_LENGTH; i++)
		count += x86->opcode[i] != IRRELEVANT_OPCODE ? 1 : 0;

	return insn_offset_opcode(insn) + count;
}

static inline int insn_offset_sib(cs_insn *insn)
{
#define MODRM_SIZE 1
	return insn_offset_modrm(insn) + MODRM_SIZE;
}

static inline int insn_offset_displacement(cs_insn *insn)
{
#define IRRELEVANT_SIB 0
	return insn_offset_sib(insn) + (insn->detail->x86.sib != IRRELEVANT_SIB ? 1 : 0);
}

/*
 *  handle PIC code.
 *  Generically, this function handle all PIC instructions.
 *
 *  this function manipulate any RIP-relative insns like below,
 *    lea rcx, qword ptr [rip + 0x8f3f85]
 *  to this.
 *    push reg
 *    mov [calculated PC + 0x8f3f85], reg
 *    lea rcx, reg
 *    pop reg
 *
 *  To achieve its goal, the function change modrm (and REX)
 *  to keep the same instruction, but forces it to use a
 *  scratch register. The scratch register will hold the
 *  computed [RIP + disp] address.
 *
 *  The function looks for a scratch register that won't
 *  alter the relocated instruction when used as an operand.
 *
 *  To avoid clobbering reg, we need to save it before
 *  executing the insn and restore it after.
 */
static int handle_pic_modrm(cs_insn *insn, uint8_t insns[],
		      struct mcount_disasm_info *info)
{
	int insns_size = 0;
	uint8_t reg_id;
	uint8_t modrm_index;
	uint8_t disp_index;
	uint64_t target;
	uint8_t *offset;
	uint8_t relocated_insn[15];
	/* PUSH + reg_id */
	uint8_t push = 0x50;
	/* MOV + reg_id */
	uint8_t mov[10] = { 0x48 /* REX.w for 8-byte imm */, 0xb8, };
	/* POP + reg_id */
	uint8_t pop = 0x58;

	/* RIP-relative insn always have a displacement of 4 bytes */
#define DISP_SIZE   4
#define IRRELEVANT_REX   0

	/* Look for an valid scratch register */
	reg_id = find_scratch_register(insn);
	if (reg_id == 255)
		goto out;

	/* Setup and write PUSH reg */
	push += reg_id;
	memcpy(&insns[0], &push, sizeof(push));

	/* Setup MOV imm, reg */
	mov[1] += reg_id;
	disp_index = insn_offset_displacement(insn);
	/* Compute operand address [RIP + disp] */
	target = insn->address + insn->size + *(int32_t*)(insn->bytes + disp_index);
	memcpy(&mov[2], &target, sizeof(target));

	/* Write MOV imm, reg */
	memcpy(&insns[1], &mov, sizeof(mov));

	/* Setup relocated insn */
	memcpy(relocated_insn, insn->bytes, insn->size);
	/*
	 * Clear REX.b bit (LSB). Insns may set it to extend r/m. Since RIP-relative
	 * will always use RIP instead of r8+, this bit is ignored.
	 */
	if (insn->detail->x86.rex != IRRELEVANT_REX) {
		offset = relocated_insn + insn_offset_rex_prefix(insn);
		*offset &= 0xfe;
	}

	/* We only check mdorm because RIP-relative insns never use SIB */
	modrm_index = insn_offset_modrm(insn);
	offset = relocated_insn + modrm_index;
	/* Change modrm from "00 reg 101" to "10 reg reg_id" */
	*offset = (reg_id & 0b00000111) | (*offset & 0b00111000);

	insns_size = sizeof(push) + sizeof(mov);

	/* Write prefixes, REX and opcode */
	memcpy(&insns[insns_size], &relocated_insn, modrm_index);
	insns_size += modrm_index;

	/* Write modrm byte */
	memcpy(&insns[insns_size], &relocated_insn[modrm_index], 1);
	insns_size += 1;

	/* Write imm (skip disp) */
	memcpy(&insns[insns_size], &relocated_insn[disp_index + DISP_SIZE],
			insn->size - DISP_SIZE - (modrm_index + 1));
	insns_size += insn->size - DISP_SIZE - (modrm_index + 1);

	/* Write POP reg */
	pop += reg_id;
	memcpy(&insns[insns_size], &pop, sizeof(pop));
	insns_size += sizeof(pop);

	return insns_size;

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

	pr_dbg3("Manipulate instructions having PC-relative addressing.\n");

	switch (*fail_reason) {
	case INSTRUMENT_FAIL_PICCODE:
		res = handle_pic_modrm(insn, insns, info);
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
