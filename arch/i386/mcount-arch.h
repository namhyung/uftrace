#include "../../utils/symbol.h"
#ifndef __MCOUNT_ARCH_H__
#define __MCOUNT_ARCH_H__

#define mcount_regs  mcount_regs

struct mcount_regs {
	unsigned long stack1;
	unsigned long ecx;
	unsigned long edx;
};

#define  ARG1(a)      ((a)->stack1)
#define  ARG_REG1(a)  ((a)->ecx)
#define  ARG_REG2(a)  ((a)->edx)

#define ARCH_MAX_REG_ARGS  3
#define ARCH_MAX_FLOAT_REGS  8

enum x86_reg_index {
	X86_REG_INT_BASE = 0,
	/* integer registers */
	X86_REG_ECX,
	X86_REG_EDX,

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

#define FIX_PARENT_LOC
unsigned long * mcount_arch_parent_location(struct symtabs *symtabs,
					    unsigned long *parent_loc,
					    unsigned long child_ip);
#define ARCH_PLT0_SIZE  16
#define ARCH_PLTHOOK_ADDR_OFFSET  6

#endif /* __MCOUNT_ARCH_H__ */
