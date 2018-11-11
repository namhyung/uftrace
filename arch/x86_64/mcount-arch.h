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
	UFT_X86_REG_INT_BASE = 0,
	/* integer registers */
	UFT_X86_REG_RDI,
	UFT_X86_REG_RSI,
	UFT_X86_REG_RDX,
	UFT_X86_REG_RCX,
	UFT_X86_REG_R8,
	UFT_X86_REG_R9,

	UFT_X86_REG_FLOAT_BASE = 100,
	/* floating-point registers */
	UFT_X86_REG_XMM0,
	UFT_X86_REG_XMM1,
	UFT_X86_REG_XMM2,
	UFT_X86_REG_XMM3,
	UFT_X86_REG_XMM4,
	UFT_X86_REG_XMM5,
	UFT_X86_REG_XMM6,
	UFT_X86_REG_XMM7,
};

#define HAVE_MCOUNT_ARCH_CONTEXT
struct mcount_arch_context {
	double xmm[ARCH_MAX_FLOAT_REGS];
};

#define ARCH_PLT0_SIZE  16
#define ARCH_PLTHOOK_ADDR_OFFSET  6

#define ARCH_SUPPORT_AUTO_RECOVER  1

#endif /* MCOUNT_ARCH_H */
