#include "utils/asm.h"

.hidden plthook_resolver_addr

ENTRY(plt_hooker)
	.cfi_startproc
	/* PLT code already pushed symbol and module indices */
	.cfi_adjust_cfa_offset 16
	sub $56, %rsp
	.cfi_adjust_cfa_offset 56
	movq %rdi, 48(%rsp)
	.cfi_offset rdi, -24
	movq %rsi, 40(%rsp)
	.cfi_offset rsi, -32
	movq %rdx, 32(%rsp)
	.cfi_offset rdx, -40
	movq %rcx, 24(%rsp)
	.cfi_offset rcx, -48
	movq %r8, 16(%rsp)
	.cfi_offset r8, -56
	movq %r9, 8(%rsp)
	.cfi_offset r9, -64
	movq %rax, 0(%rsp)
	.cfi_offset rax, -72

	/* child idx */
	movq 64(%rsp), %rsi
	/* address of parent ip */
	lea 72(%rsp), %rdi
	/* module id */
	movq 56(%rsp), %rdx
	/* mcount_args */
	lea 8(%rsp), %rcx

	call plthook_entry
	movq %rax, %r11

	movq 0(%rsp), %rax
	movq 8(%rsp), %r9
	movq 16(%rsp), %r8
	movq 24(%rsp), %rcx
	movq 32(%rsp), %rdx
	movq 40(%rsp), %rsi
	movq 48(%rsp), %rdi
	add $56, %rsp
	.cfi_adjust_cfa_offset -56

	cmpq $0, %r11
	cmovz plthook_resolver_addr(%rip), %r11
	jz 1f

	add $16, %rsp /* resolver function needs 2 entries on stack */
	.cfi_adjust_cfa_offset -16
1:
	jmp *%r11
	.cfi_endproc
END(plt_hooker)


ENTRY(plthook_return)
	.cfi_startproc
	sub $48, %rsp
	.cfi_def_cfa_offset 48

	movdqu %xmm0, 16(%rsp)
	movq %rdx, 8(%rsp)
	.cfi_offset rdx, -24
	movq %rax, 0(%rsp)
	.cfi_offset rax, -32

	/* set the first argument of plthook_exit as pointer to return values */
	movq %rsp, %rdi

	call plthook_exit
	movq %rax, 40(%rsp)

	movq 0(%rsp), %rax
	movq 8(%rsp), %rdx
	movdqu 16(%rsp), %xmm0

	add $40, %rsp
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc
END(plthook_return)
