#ifndef MCOUNT_ARCH_H
#define MCOUNT_ARCH_H

#define mcount_regs mcount_regs

struct mcount_regs {
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
};

#define ARG1(x) ((x)->a0)
#define ARG2(x) ((x)->a1)
#define ARG3(x) ((x)->a2)
#define ARG4(x) ((x)->a3)
#define ARG5(x) ((x)->a4)
#define ARG6(x) ((x)->a5)
#define ARG7(x) ((x)->a6)
#define ARG8(x) ((x)->a7)

#define ARCH_MAX_REG_ARGS 8
#define ARCH_MAX_FLOAT_REGS 8

#define HAVE_MCOUNT_ARCH_CONTEXT
struct mcount_arch_context {
	double f[ARCH_MAX_FLOAT_REGS];
};

#if defined(__riscv_compressed)
#define NOP_INSN_SIZE 2
#else
#define NOP_INSN_SIZE 4
#endif

#define ARCH_PLT0_SIZE 32
#define ARCH_PLTHOOK_ADDR_OFFSET 0

/* index of module-ID in the PLTGOT table */
#define ARCH_PLTGOT_MOD_ID 1
/* index of resolver address in the PLTGOT table */
#define ARCH_PLTGOT_RESOLVE 0
/* number of reserved entries in the PLTGOT table */
#define ARCH_PLTGOT_OFFSET 2

/* TODO: not implemented yet (Start) */
struct mcount_disasm_engine;
struct mcount_dynamic_info;
struct mcount_disasm_info;

int disasm_check_insns(struct mcount_disasm_engine *disasm, struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info);
/* TODO: not implemented yet (End) */

#endif /* MCOUNT_ARCH_H */
