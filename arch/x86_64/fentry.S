/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame (with -pg -mfentry): parent addr = 8(%rsp), child addr = (%rsp) */
/*
 * For example:

   Parent(caller): main()
   Child(callee): hello()

   Dump of assembler code for function main:
                   0x00000000004006bc <+0>:	callq  0x400550 <__fentry__@plt>
                   0x00000000004006c1 <+5>:	push   %rbp
                   0x00000000004006c2 <+6>:	mov    %rsp,%rbp
                   0x00000000004006c5 <+9>:	mov    $0x0,%eax
                   0x00000000004006ca <+14>:	callq  0x4006a6 <hello>
    parent addr => 0x00000000004006cf <+19>:	nop
                   0x00000000004006d0 <+20>:	pop    %rbp
                   0x00000000004006d1 <+21>:	retq

   Dump of assembler code for function hello:
                   0x00000000004006a6 <+0>:	callq  0x400550 <__fentry__@plt>
     child addr => 0x00000000004006ab <+5>:	push   %rbp
                   0x00000000004006ac <+6>:	mov    %rsp,%rbp
 */

#include "utils/asm.h"

GLOBAL(__fentry__)
	.cfi_startproc
	sub $48, %rsp
	.cfi_adjust_cfa_offset 48

	/* save register arguments in mcount_args */
	movq %rdi, 40(%rsp)
	movq %rsi, 32(%rsp)
	movq %rdx, 24(%rsp)
	movq %rcx, 16(%rsp)
	movq %r8,   8(%rsp)
	movq %r9,   0(%rsp)

	/* child addr */
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

	call mcount_entry

	pop  %rax

	/* restore original stack pointer */
	pop  %rdx
	movq %rdx, %rsp
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
	retq
	.cfi_endproc
END(__fentry__)
