#ifndef MCOUNT_ARCH_H
#define MCOUNT_ARCH_H

#define mcount_regs  mcount_regs

struct mcount_regs {
	unsigned long  r0;
	unsigned long  r1;
	unsigned long  r2;
	unsigned long  r3;
};

#define  ARG1(a)  ((a)->r0)
#define  ARG2(a)  ((a)->r1)
#define  ARG3(a)  ((a)->r2)
#define  ARG4(a)  ((a)->r3)

#define ARCH_MAX_REG_ARGS  4
#define ARCH_MAX_FLOAT_REGS  16
#define ARCH_MAX_DOUBLE_REGS  8

enum arm_reg_index {
	ARM_REG_INT_BASE = 0,
	/* integer registers */
	ARM_REG_R0,
	ARM_REG_R1,
	ARM_REG_R2,
	ARM_REG_R3,

	ARM_REG_FLOAT_BASE = 100,
	/* (single-precision) floating-point registers */
	ARM_REG_S0,
	ARM_REG_S1,
	ARM_REG_S2,
	ARM_REG_S3,
	ARM_REG_S4,
	ARM_REG_S5,
	ARM_REG_S6,
	ARM_REG_S7,
	ARM_REG_S8,
	ARM_REG_S9,
	ARM_REG_S10,
	ARM_REG_S11,
	ARM_REG_S12,
	ARM_REG_S13,
	ARM_REG_S14,
	ARM_REG_S15,
	/* double-precision registers */
	ARM_REG_DOUBLE_BASE = 200,
	ARM_REG_D0,
	ARM_REG_D1,
	ARM_REG_D2,
	ARM_REG_D3,
	ARM_REG_D4,
	ARM_REG_D5,
	ARM_REG_D6,
	ARM_REG_D7,
};

struct mcount_arch_context {
};

struct symtabs;

#define FIX_PARENT_LOC
unsigned long * mcount_arch_parent_location(struct symtabs *symtabs,
					    unsigned long *parent_loc,
					    unsigned long child_ip);

#define ARCH_PLT0_SIZE  20
#define ARCH_PLTHOOK_ADDR_OFFSET  0

#endif /* MCOUNT_ARCH_H */
