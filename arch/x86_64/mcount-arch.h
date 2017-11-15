#ifndef MCOUNT_ARCH_H
#define MCOUNT_ARCH_H

#define mcount_regs  mcount_regs

struct mcount_regs {
	unsigned long  r9;
	unsigned long  r8;
	unsigned long  rcx;
	unsigned long  rdx;
	unsigned long  rsi;
	unsigned long  rdi;
};

#define  ARG1(a)  ((a)->rdi)
#define  ARG2(a)  ((a)->rsi)
#define  ARG3(a)  ((a)->rdx)
#define  ARG4(a)  ((a)->rcx)
#define  ARG5(a)  ((a)->r8)
#define  ARG6(a)  ((a)->r9)

#define ARCH_MAX_REG_ARGS  6
#define ARCH_MAX_FLOAT_REGS  8

enum x86_reg_index {
	X86_REG_INT_BASE = 0,
	/* integer registers */
	X86_REG_RDI,
	X86_REG_RSI,
	X86_REG_RDX,
	X86_REG_RCX,
	X86_REG_R8,
	X86_REG_R9,

	X86_REG_FLOAT_BASE = 100,
	/* floating-point registers */
	X86_REG_XMM0,
	X86_REG_XMM1,
	X86_REG_XMM2,
	X86_REG_XMM3,
	X86_REG_XMM4,
	X86_REG_XMM5,
	X86_REG_XMM6,
	X86_REG_XMM7,
};

#define HAVE_MCOUNT_ARCH_CONTEXT
struct mcount_arch_context {
	double xmm[ARCH_MAX_FLOAT_REGS];
};

#define ARCH_PLT0_SIZE  16
#define ARCH_PLTHOOK_ADDR_OFFSET  6

#endif /* MCOUNT_ARCH_H */
