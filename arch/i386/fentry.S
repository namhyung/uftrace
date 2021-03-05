#include "utils/asm.h"

GLOBAL(__fentry__)
	sub $32, %esp
	movl %edx, 28(%esp)
	movl %ecx, 24(%esp)
	movl %eax, 20(%esp)
	movl $0, 16(%esp)
	/* parent location */
	leal 36(%esp), %eax
	movl %eax, 0(%esp)
	/* child addr */
	movl 32(%esp), %eax
	movl %eax, 4(%esp)
	/* mcount_args */
	leal 16(%esp), %eax
	movl %eax, 8(%esp)
	call mcount_entry
	cmpl $0, %eax
	jne 1f

	/* hijack return address */
	call get_pc_thunk
	addl $_GLOBAL_OFFSET_TABLE_, %eax
	addl $fentry_return@GOTOFF, %eax
	movl %eax, 36(%esp)
1:
	movl 20(%esp), %eax
	movl 24(%esp), %ecx
	movl 28(%esp), %edx
	add $32, %esp
	ret
END(__fentry__)


ENTRY(fentry_return)
	sub  $16, %esp
	movl %edx, 8(%esp)
	movl %eax, 4(%esp)
	leal 4(%esp), %eax
	movl %eax, 0(%esp)

	call mcount_exit
	movl %eax, 12(%esp)

	movl 4(%esp), %eax
	movl 8(%esp), %edx
	add  $12, %esp
	ret
END(fentry_return)
