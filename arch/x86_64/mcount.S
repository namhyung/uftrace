/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame (with -pg): parent addr = 8(%rbp), child addr = (%rsp) */
/*
 * For example:

   Parent(caller): main()
   Child(callee): hello()

   Dump of assembler code for function main:
                   0x00000000004006b1 <+0>:	push   %rbp
                   0x00000000004006b2 <+1>:	mov    %rsp,%rbp
                   0x00000000004006b5 <+4>:	callq  0x400520 <mcount@plt>
                   0x00000000004006ba <+9>:	mov    $0x0,%eax
                   0x00000000004006bf <+14>:	callq  0x400686 <hello>
    parent addr => 0x00000000004006c4 <+19>:	nop
                   0x00000000004006c5 <+20>:	pop    %rbp
                   0x00000000004006c6 <+21>:	retq

   Dump of assembler code for function hello:
                   0x0000000000400686 <+0>:	push   %rbp
                   0x0000000000400687 <+1>:	mov    %rsp,%rbp
                   0x000000000040068a <+4>:	sub    $0x10,%rsp
                   0x000000000040068e <+8>:	callq  0x400520 <mcount@plt>
     child addr => 0x0000000000400693 <+13>:	movl   $0x1,-0x4(%rbp)
 */

#include "utils/asm.h"

GLOBAL(mcount)
	.cfi_startproc
	/*
	 * 56 is needed because of the 16-byte
	 * stack alignment required from GCC7
	 */
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

	/* child addr */
	movq 56(%rsp), %rsi

	/* parent location */
	lea 8(%rbp), %rdi

	/* mcount_args */
	lea 8(%rsp), %rdx

	call mcount_entry

	movq 0(%rsp), %rax
	movq 8(%rsp), %r9
	movq 16(%rsp), %r8
	movq 24(%rsp), %rcx
	movq 32(%rsp), %rdx
	movq 40(%rsp), %rsi
	movq 48(%rsp), %rdi
	add $56, %rsp
	.cfi_adjust_cfa_offset -56
	retq
	.cfi_endproc
END(mcount)


ENTRY(mcount_return)
	.cfi_startproc
	sub $48, %rsp
	.cfi_def_cfa_offset 48

	movdqu %xmm0, 16(%rsp)
	movq %rdx, 8(%rsp)
	.cfi_offset rdx, -24
	movq %rax, 0(%rsp)
	.cfi_offset rax, -32

	/* set the first argument of mcount_exit as pointer to return values */
	movq %rsp, %rdi

	/* returns original parent address */
	call mcount_exit
	movq %rax, 40(%rsp)

	movq 0(%rsp), %rax
	movq 8(%rsp), %rdx
	movdqu 16(%rsp), %xmm0

	add $40, %rsp
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc
END(mcount_return)
