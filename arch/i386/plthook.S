#include "utils/asm.h"

.hidden plthook_resolver_addr

ENTRY(plt_hooker)
	sub $32, %esp
	/* save registers */
	movl %edx, 24(%esp)
	movl %ecx, 20(%esp)
	/* this is for ARG1 that using in jmp */
	movl 44(%esp), %eax
	movl %eax, 16(%esp)

	/* stack address contain parent location */
	leal 40(%esp), %eax
	movl %eax, 0(%esp)

	/* child_idx */
	movl 36(%esp), %eax
	movl %eax, 4(%esp)
	
	/* module_id */
	movl 32(%esp), %eax
	movl %eax, 8(%esp)

	/* mcount_args */
	leal 16(%esp), %eax
	movl %eax, 12(%esp)

	call plthook_entry

	/* restore registers */
	movl 20(%esp), %ecx
	movl 24(%esp), %edx
	add $32, %esp

	cmpl $0, %eax
	jnz 1f
	/* get address of plthook_resolver_addr */
	call get_pc_thunk
	addl $_GLOBAL_OFFSET_TABLE_, %eax
	leal plthook_resolver_addr@GOTOFF(%eax), %eax
	movl (%eax), %eax
	jmp *%eax
1:
	add $8, %esp
	jmp *%eax
END(plt_hooker)


ENTRY(plthook_return)
	sub $16, %esp
	movl %edx, 8(%esp)
	movl %eax, 4(%esp)
	leal 4(%esp), %eax
	movl %eax, 0(%esp)

	call plthook_exit
	movl %eax, 12(%esp)

	movl 4(%esp), %eax
	movl 8(%esp), %edx
	add $12, %esp
	ret
END(plthook_return)
