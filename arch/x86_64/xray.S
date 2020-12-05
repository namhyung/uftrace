/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame: child addr = 0(%rsp), return addr = 8(%rbp) */

#include "utils/asm.h"

GLOBAL(__xray_entry)
	.cfi_startproc
	sub $48, %rsp
	.cfi_adjust_cfa_offset 48

	movq %rdi, 40(%rsp)
	movq %rsi, 32(%rsp)
	movq %rdx, 24(%rsp)
	movq %rcx, 16(%rsp)
	movq %r8,   8(%rsp)
	movq %r9,   0(%rsp)

	/* child ip */
	movq 48(%rsp), %rsi

	/* parent location */
	lea 56(%rsp), %rdi

	/* mcount_args */
	movq %rsp, %rdx
	.cfi_def_cfa_register rdx

	/* align stack pointer to 16-byte */
	andq $0xfffffffffffffff0, %rsp
	push %rdx

	/* save rax (implicit argument for variadic functions) */
	push %rax

	call xray_entry

	pop  %rax

	/* restore original stack pointer */
	pop  %rdx
	movq %rdx, %rsp
	.cfi_def_cfa_register rsp

	/* restore mcount_args */
	movq 0(%rsp), %r9
	movq 8(%rsp), %r8
	movq 16(%rsp), %rcx
	movq 24(%rsp), %rdx
	movq 32(%rsp), %rsi
	movq 40(%rsp), %rdi

	add $48, %rsp
	.cfi_adjust_cfa_offset -48
	retq
	.cfi_endproc
END(__xray_entry)


ENTRY(__xray_exit)
	.cfi_startproc
	sub $40, %rsp  /* return address already consume 8 byte */
	.cfi_def_cfa_offset 40

	movq   %rdi,  32(%rsp)
	/* save original return values */
	movdqu %xmm0, 16(%rsp)
	movq   %rdx,   8(%rsp)
	movq   %rax,   0(%rsp)

	/* set the first argument of mcount_exit as pointer to return values */
	movq   %rsp, %rdi

	/* align stack pointer to 16-byte */
	andq   $0xfffffffffffffff0, %rsp
	sub    $16,  %rsp
	/* save original stack pointer */
	movq   %rdi, (%rsp)

	call xray_exit

	/* restore original stack pointer */
	movq    0(%rsp), %rsp

	/* restore return values */
	movq    0(%rsp), %rax
	movq    8(%rsp), %rdx
	movdqu 16(%rsp), %xmm0
	movq   32(%rsp), %rdi

	add $40, %rsp

	retq
	.cfi_endproc
END(__xray_exit)
