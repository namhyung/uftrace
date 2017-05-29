#ifndef __UFTRACE_ASM_H__
#define __UFTRACE_ASM_H__

#define GLOBAL(sym)				\
	.global sym;				\
	.type sym, %function;			\
sym:

#define ENTRY(sym)				\
	.global sym;				\
	.hidden sym;				\
	.type sym, %function;			\
sym:

#define END(sym)				\
	.size sym, .-sym;

#endif /* __UFTRACE_ASM_H__ */
