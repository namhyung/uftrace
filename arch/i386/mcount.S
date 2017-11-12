/* in i386, generally used stack for argument passing. */
/* use register for return : %eax */
/* no need save registers */
/* stack frame (with -pg): parent addr = 4(%ebp) */
/* child addr = (%esp) */

#include "utils/asm.h"

GLOBAL(mcount)
	sub $32, %esp
	/* save registers */
	movl %edx, 28(%esp)
	movl %ecx, 24(%esp)	
	movl %eax, 20(%esp)
	movl $0, 16(%esp)
	/* parent location */
	leal 4(%ebp), %eax
	movl %eax, 0(%esp)
	/* child addr */
	movl 32(%esp), %eax
	movl %eax, 4(%esp)
	/*  mcount_regs */
	leal 16(%esp), %eax
	movl %eax, 8(%esp)

	call mcount_entry

	/* restore registers */
	movl 20(%esp), %eax
	movl 24(%esp), %ecx
	movl 28(%esp), %edx
	add $32, %esp
	ret
END(mcount)


ENTRY(mcount_return)
	sub $16, %esp
	movl %edx, 8(%esp)
	movl %eax, 4(%esp)
	leal 4(%esp), %eax
	movl %eax, 0(%esp)

	/* returns original parent address */
	call mcount_exit
	movl %eax, 12(%esp)

	movl 4(%esp), %eax
	movl 8(%esp), %edx
	add $12, %esp
	ret
END(mcount_return)
