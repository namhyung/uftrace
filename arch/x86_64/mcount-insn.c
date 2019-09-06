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

/*
 *  handle PIC code.
 *  for currently, this function targeted specific type of instruction.
 *
 *  this function manipulate the instruction like below,
 *  => lea rcx, qword ptr [rip + 0x8f3f85]
 *  to this.
 *  => mov rcx, [address where instruction located actually]
 *  => lea rcx, qword ptr [rcx + 0x8f3f85]
 */
static int handle_pic(cs_insn *insn, uint8_t insns[])
{
	cs_x86 *x86;
	x86 = &insn->detail->x86;

	/*
	 * array for mov instruction.
	 * ex) mov rbx, 0x555556d35690
	 */
	uint8_t mov_insns[] = {
		0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	int mov_rex_offset = 0;
	int mov_opnd_offset = 1;
	int mov_imm64_offset = 2;

	/*
	 * array for lea instruction.
	 * ex) lea rbx, [rbx+0x8f3f85]
	 */
	uint8_t lea_insns[] = {
		0x48, 0x8d, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	int lea_rex_offset = 0;
	int lea_insn_offset = 1;
	int lea_opnd_offset = 2;
	int lea_disp_offset = 3;

	// REX.48 operands
	uint8_t mov_opnd_48[] = {
		//rax,	rbx,	rcx,	rdx,	rdi,	rsi,	rbp,	rsp
		0xb8,	0xbb,	0xb9,	0xba,	0xbf,	0xbe,	0xbd,	0xbc
	};

	// REX.49 operands
	uint8_t mov_opnd_49[] = {
		//r8,	r9,	r10,	r11,	r12,	r13,	r14,	r15
		0xb8,	0xb9,	0xba,	0xbb,	0xbc,	0xbd,	0xbe,	0xbf
	};

	// REX.48 operands,
	uint8_t lea_opnd_48[] = {
		//rax,	rbx,	rcx,	rdx,	rdi,	rsi,	rbp,	rsp
		0x80,	0x9b,	0x89,	0x92,	0xbf,	0xb6,	0xad,	0xa4
	};

	// REX.4D operands,
	uint8_t lea_opnd_4D[] = {
		//r8,	r9,	r10,	r11,	r12,	r13,	r14,	r15
		0x80,	0x89,	0x92,	0x9b,	0xa4,	0xad,	0xb6,	0xbf
	};

	// for currently, support LEA instruction only.
	if (strncmp(insn->mnemonic, "lea", 3) != 0)
		goto out;

	// according to intel manual, lea instruction takes 2 operand only.
	cs_x86_op *opnd1 = &(x86->operands[0]);
	cs_x86_op *opnd2 = &(x86->operands[1]);

	// get the register from opnd1 to load rip address
	if (X86_REG_RAX <= opnd1->reg && opnd1->reg <= X86_REG_RSP) {
		mov_insns[mov_rex_offset] = 0x48;
		lea_insns[lea_rex_offset] = 0x48;
	}
	else if (X86_REG_R8 <= opnd1->reg && opnd1->reg <= X86_REG_R15) {
		mov_insns[mov_rex_offset] = 0x49;
		lea_insns[lea_rex_offset] = 0x4D;
	}
	else
		goto out;

	switch(opnd1->reg) {
	// REX.48
	case X86_REG_RAX:
		mov_insns[mov_opnd_offset] = mov_opnd_48[0];
		break;
	case X86_REG_RBX:
		mov_insns[mov_opnd_offset] = mov_opnd_48[1];
		break;
	case X86_REG_RCX:
		mov_insns[mov_opnd_offset] = mov_opnd_48[2];
		break;
	case X86_REG_RDX:
		mov_insns[mov_opnd_offset] = mov_opnd_48[3];
		break;
	case X86_REG_RDI:
		mov_insns[mov_opnd_offset] = mov_opnd_48[4];
		break;
	case X86_REG_RSI:
		mov_insns[mov_opnd_offset] = mov_opnd_48[5];
		break;
	case X86_REG_RBP:
		mov_insns[mov_opnd_offset] = mov_opnd_48[6];
		break;
	case X86_REG_RSP:
		mov_insns[mov_opnd_offset] = mov_opnd_48[7];
		break;

	// REX.49
	case X86_REG_R8:
		mov_insns[mov_opnd_offset] = mov_opnd_49[0];
		break;
	case X86_REG_R9:
		mov_insns[mov_opnd_offset] = mov_opnd_49[1];
		break;
	case X86_REG_R10:
		mov_insns[mov_opnd_offset] = mov_opnd_49[2];
		break;
	case X86_REG_R11:
		mov_insns[mov_opnd_offset] = mov_opnd_49[3];
		break;
	case X86_REG_R12:
		mov_insns[mov_opnd_offset] = mov_opnd_49[4];
		break;
	case X86_REG_R13:
		mov_insns[mov_opnd_offset] = mov_opnd_49[5];
		break;
	case X86_REG_R14:
		mov_insns[mov_opnd_offset] = mov_opnd_49[6];
		break;
	case X86_REG_R15:
		mov_insns[mov_opnd_offset] = mov_opnd_49[7];
		break;
	default:
		goto out;
	}

	uint64_t PIC_base = insn->address;
	PIC_base += insn->size;
	*(uint64_t *)(mov_insns + mov_imm64_offset) = PIC_base;

	// handling the SIB not supported yet.
	if (opnd2->mem.scale > 1 || opnd2->mem.disp == 0)
		return -1;

	switch (opnd1->reg) {
	//rax,	rbx,	rcx,	rdx,	rdi,	rsi,	rbp,	rsp
	case X86_REG_RAX:
		lea_insns[lea_opnd_offset] = lea_opnd_48[0];
		break;
	case X86_REG_RBX:
		lea_insns[lea_opnd_offset] = lea_opnd_48[1];
		break;
	case X86_REG_RCX:
		lea_insns[lea_opnd_offset] = lea_opnd_48[2];
		break;
	case X86_REG_RDX:
		lea_insns[lea_opnd_offset] = lea_opnd_48[3];
		break;
	case X86_REG_RDI:
		lea_insns[lea_opnd_offset] = lea_opnd_48[4];
		break;
	case X86_REG_RSI:
		lea_insns[lea_opnd_offset] = lea_opnd_48[5];
		break;
	case X86_REG_RBP:
		lea_insns[lea_opnd_offset] = lea_opnd_48[6];
		break;
	case X86_REG_RSP:
		/*
		 * could not handling this case yet because
		 * need to add SIB for handling this case.
		 */
		goto out;

	// REX.4D
	case X86_REG_R8:
		lea_insns[lea_opnd_offset] = lea_opnd_4D[0];
		break;
	case X86_REG_R9:
		lea_insns[lea_opnd_offset] = lea_opnd_4D[1];
		break;
	case X86_REG_R10:
		lea_insns[lea_opnd_offset] = lea_opnd_4D[2];
		break;
	case X86_REG_R11:
		lea_insns[lea_opnd_offset] = lea_opnd_4D[3];
		break;
	case X86_REG_R12:
		/*
		 * could not handling this case yet because
		 * need to add SIB for handling this case.
		 */
		goto out;
	case X86_REG_R13:
		lea_insns[lea_opnd_offset] = lea_opnd_4D[5];
		break;
	case X86_REG_R14:
		lea_insns[lea_opnd_offset] = lea_opnd_4D[6];
		break;
	case X86_REG_R15:
		lea_insns[lea_opnd_offset] = lea_opnd_4D[7];
		break;
	default:
		goto out;
	}

	// according to rule of modR/M in intel, disp has 32bit size maximum.
	int32_t disp = (int32_t)opnd2->mem.disp;
	*(uint32_t *)(lea_insns + lea_disp_offset) = disp;

	memcpy(insns, (void *)mov_insns, sizeof(mov_insns));
	memcpy(insns + sizeof(mov_insns), (void *)lea_insns, sizeof(lea_insns));

	return sizeof(mov_insns) + sizeof(lea_insns);

out:
	return -1;
}

static int manipulate_insns(cs_insn *insn, uint8_t insns[], int* fail_reason)
{
	int res = -1;

	pr_dbg3("Try to instrument if instruction could be manipulate possibly.\n");
	switch(*fail_reason) {
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
			break;
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
	struct mcount_instrument_info *info = xmalloc(sizeof(*info));

	info->addr = sym->addr + mdi->map->start;
	info->size = INSTRUMENT_FAILED;
	info->insns = NULL;
	info->insns_size = 0;
	info->func_size = sym->size;

	badsym = find_bad_jump(mdi, insn_check.addr);
	if (badsym != NULL) {
		list_del(&badsym->list);
		free(badsym);
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
		insns_size = 0;
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

		if (info->insns == NULL) {
			info->insns = xzalloc(insns_size);
			info->size = 0;
		}
		else {
			info->insns = xrealloc(info->insns, insns_size);
		}
		memcpy(info->insns + info->insns_size, (void *)insns_byte, insns_size);
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

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi, struct sym *sym)
{
	return INSTRUMENT_FAILED;
}

#endif /* HAVE_LIBCAPSTONE */
