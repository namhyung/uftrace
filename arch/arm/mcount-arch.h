#ifndef __MCOUNT_ARCH_H__
#define __MCOUNT_ARCH_H__

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

struct ftrace_arg_spec;

long mcount_get_arg(struct mcount_regs *regs, struct ftrace_arg_spec *spec);

#endif /* __MCOUNT_ARCH_H__ */
