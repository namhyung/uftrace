#ifndef MCOUNT_ARCH_H
#define MCOUNT_ARCH_H

#define mcount_regs  mcount_regs

struct mcount_regs {
	unsigned long  r0;
	unsigned long  r1;
	unsigned long  r2;
	unsigned long  r3;
	unsigned long  r4;
	unsigned long  r5;
	unsigned long  r6;
	unsigned long  r7;
};

#define  ARG1(a)  ((a)->r0)
#define  ARG2(a)  ((a)->r1)
#define  ARG3(a)  ((a)->r2)
#define  ARG4(a)  ((a)->r3)
#define  ARG5(a)  ((a)->r4)
#define  ARG6(a)  ((a)->r5)
#define  ARG7(a)  ((a)->r6)
#define  ARG8(a)  ((a)->r7)

#define ARCH_MAX_REG_ARGS  8
#define ARCH_MAX_FLOAT_REGS  8

enum arm_reg_index {
	AARCH64_REG_INT_BASE = 0,
	/* integer registers */
	AARCH64_REG_R0,
	AARCH64_REG_R1,
	AARCH64_REG_R2,
	AARCH64_REG_R3,
	AARCH64_REG_R4,
	AARCH64_REG_R5,
	AARCH64_REG_R6,
	AARCH64_REG_R7,

	AARCH64_REG_FLOAT_BASE = 100,
	/* (single-precision) floating-point registers */
	AARCH64_REG_S0,
	AARCH64_REG_S1,
	AARCH64_REG_S2,
	AARCH64_REG_S3,
	AARCH64_REG_S4,
	AARCH64_REG_S5,
	AARCH64_REG_S6,
	AARCH64_REG_S7,

	AARCH64_REG_DOUBLE_BASE = 200,
	/* (double-precision) floating-point registers */
	AARCH64_REG_D0,
	AARCH64_REG_D1,
	AARCH64_REG_D2,
	AARCH64_REG_D3,
	AARCH64_REG_D4,
	AARCH64_REG_D5,
	AARCH64_REG_D6,
	AARCH64_REG_D7,
};

struct mcount_arch_context {
};

#define ARCH_PLT0_SIZE  32
#define ARCH_PLTHOOK_ADDR_OFFSET  0

#endif /* MCOUNT_ARCH_H */
