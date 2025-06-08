#ifndef MCOUNT_ARCH_H
#define MCOUNT_ARCH_H

#include "utils/arch.h"
#include "utils/list.h"

#define mcount_regs mcount_regs

struct mcount_regs {
	unsigned long r9;
	unsigned long r8;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
};

#define ARG1(a) ((a)->rdi)
#define ARG2(a) ((a)->rsi)
#define ARG3(a) ((a)->rdx)
#define ARG4(a) ((a)->rcx)
#define ARG5(a) ((a)->r8)
#define ARG6(a) ((a)->r9)

#define ARCH_MAX_REG_ARGS 6
#define ARCH_MAX_FLOAT_ARGS 8
#define ARCH_NUM_BASE_REGS 8

#define HAVE_MCOUNT_ARCH_CONTEXT
struct mcount_arch_context {
	double xmm[ARCH_MAX_FLOAT_ARGS];
};

#define ARCH_PLT0_SIZE 16
#define ARCH_PLTHOOK_ADDR_OFFSET 6

/* index of module-ID in the PLTGOT table */
#define ARCH_PLTGOT_MOD_ID 1
/* index of resolver address in the PLTGOT table */
#define ARCH_PLTGOT_RESOLVE 2
/* number of reserved entries in the PLTGOT table */
#define ARCH_PLTGOT_OFFSET 3

#define ARCH_SUPPORT_AUTO_RECOVER 1
#define ARCH_CAN_RESTORE_PLTHOOK 1

#define ARCH_TRAMPOLINE_SIZE 16
#define ARCH_BRANCH_ENTRY_SIZE ARCH_TRAMPOLINE_SIZE

struct plthook_arch_context {
	bool has_plt_sec;
};

struct mcount_disasm_engine;
struct mcount_dynamic_info;
struct mcount_disasm_info;

#define CALL_INSN_SIZE 5
#define JMP_INSN_SIZE 6 /* indirect jump */
#define JCC8_INSN_SIZE 2
#define JMP32_INSN_SIZE 5
#define MOV_INSN_SIZE 10 /* move 8-byte immediate to reg */
#define ENDBR_INSN_SIZE 4
#define CET_JMP_INSN_SIZE 7 /* indirect jump + prefix */
#define NOP_INSN_SIZE 1

int disasm_check_insns(struct mcount_disasm_engine *disasm, struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info);

unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx);

#endif /* MCOUNT_ARCH_H */
