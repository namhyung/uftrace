#include "utils/asm.h"

.hidden plthook_resolver_addr

ENTRY(plt_hooker)
	.cfi_startproc
	/* PLT code already pushed symbol and module indices */
	.cfi_adjust_cfa_offset 16
	sub $48, %rsp
	.cfi_adjust_cfa_offset 48

	/* save register arguments in mcount_args */
	movq %rdi, 40(%rsp)
	movq %rsi, 32(%rsp)
	movq %rdx, 24(%rsp)
	movq %rcx, 16(%rsp)
	movq %r8,   8(%rsp)
	movq %r9,   0(%rsp)

	/* module id */
	movq 48(%rsp), %rdx

	/* child idx */
	movq 56(%rsp), %rsi

	/* parent location */
	leaq 64(%rsp), %rdi

	/* mcount_args */
	movq %rsp, %rcx
	.cfi_def_cfa_register rcx

	/* align stack pointer to 16-byte */
	andq $0xfffffffffffffff0, %rsp
	push %rcx

	/* save rax (implicit argument for variadic functions) */
	push %rax

	call plthook_entry
	movq %rax, %r11

	pop  %rax

	/* restore original stack pointer */
	pop  %rcx
	movq %rcx, %rsp
	.cfi_def_cfa_register rsp

	/* restore mcount_args */
	movq  0(%rsp), %r9
	movq  8(%rsp), %r8
	movq 16(%rsp), %rcx
	movq 24(%rsp), %rdx
	movq 32(%rsp), %rsi
	movq 40(%rsp), %rdi

	add $48, %rsp
	.cfi_adjust_cfa_offset -48

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
	sub $56, %rsp
	.cfi_def_cfa_offset 56

	movq   %rdi,  32(%rsp)
	movdqu %xmm0, 16(%rsp)
	movq   %rdx,   8(%rsp)
	movq   %rax,   0(%rsp)

	/* set the first argument of plthook_exit as pointer to return values */
	movq   %rsp, %rdi

	/* align stack pointer to 16-byte */
	andq   $0xfffffffffffffff0, %rsp
	sub    $16,   %rsp
	/* save original stack pointer */
	movq   %rdi,  0(%rsp)

	call plthook_exit

	/* restore original stack pointer */
	movq   0(%rsp),  %rsp

	/* restore original return address in parent */
	movq   %rax, 48(%rsp)

	movq    0(%rsp), %rax
	movq    8(%rsp), %rdx
	movdqu 16(%rsp), %xmm0
	movq   32(%rsp), %rdi

	add $48, %rsp
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc
END(plthook_return)
