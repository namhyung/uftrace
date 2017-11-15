#ifndef UFTRACE_ASM_H
#define UFTRACE_ASM_H

#define GLOBAL(sym)				\
	.global sym;				\
	.type sym, %function;			\
sym:						\
	.global uftrace_ ## sym;		\
	.hidden uftrace_ ## sym;		\
	.type uftrace_ ## sym, %function;	\
uftrace_ ## sym:

#define ENTRY(sym)				\
	.global sym;				\
	.hidden sym;				\
	.type sym, %function;			\
sym:

#define END(sym)				\
	.size sym, .-sym;

#endif /* UFTRACE_ASM_H */
