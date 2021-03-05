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
