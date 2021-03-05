#ifndef MCOUNT_ARCH_H
#define MCOUNT_ARCH_H

#define mcount_regs  mcount_regs

struct mcount_regs {
	unsigned long  x0;
	unsigned long  x1;
	unsigned long  x2;
	unsigned long  x3;
	unsigned long  x4;
	unsigned long  x5;
	unsigned long  x6;
	unsigned long  x7;
};

#define  ARG1(a)  ((a)->x0)
#define  ARG2(a)  ((a)->x1)
#define  ARG3(a)  ((a)->x2)
#define  ARG4(a)  ((a)->x3)
#define  ARG5(a)  ((a)->x4)
#define  ARG6(a)  ((a)->x5)
#define  ARG7(a)  ((a)->x6)
#define  ARG8(a)  ((a)->x7)

#define ARCH_MAX_REG_ARGS  8
#define ARCH_MAX_FLOAT_REGS  8

#define HAVE_MCOUNT_ARCH_CONTEXT
struct mcount_arch_context {
	double d[ARCH_MAX_FLOAT_REGS];
};

#define ARCH_PLT0_SIZE  32
#define ARCH_PLTHOOK_ADDR_OFFSET  0

struct mcount_disasm_engine;
struct mcount_dynamic_info;
struct mcount_disasm_info;

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info);

#endif /* MCOUNT_ARCH_H */
