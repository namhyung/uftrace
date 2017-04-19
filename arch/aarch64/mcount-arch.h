#ifndef __MCOUNT_ARCH_H__
#define __MCOUNT_ARCH_H__

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

#endif /* __MCOUNT_ARCH_H__ */

