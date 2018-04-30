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
	/*
	 * 48 is needed because of the 16-byte
	 * stack alignment required from GCC7
	 */
	sub $48, %rsp
	.cfi_adjust_cfa_offset 48

	movq %rdi, 40(%rsp)
	.cfi_offset rdi, -24
	movq %rsi, 32(%rsp)
	.cfi_offset rsi, -32
	movq %rdx, 24(%rsp)
	.cfi_offset rdx, -40
	movq %rcx, 16(%rsp)
	.cfi_offset rcx, -48
	movq %r8, 8(%rsp)
	.cfi_offset r8, -56
	movq %r9, 0(%rsp)
	.cfi_offset r9, -64

	/* child addr */
	movq 48(%rsp), %rsi
	/* parent location */
	lea 56(%rsp), %rdi

	/* mcount_args */
	movq %rsp, %rdx

	call mcount_entry
	cmpq $0, %rax
	jne 1f

	/* hijack return address */
	movabs $fentry_return@GOTOFF, %rdx
	lea _GLOBAL_OFFSET_TABLE_(%rip), %rcx
	add %rcx, %rdx
	movq %rdx, 56(%rsp)
1:
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
END(__fentry__)


ENTRY(fentry_return)
	.cfi_startproc
	sub  $48, %rsp  /* ensure 16-byte alignment */
	.cfi_def_cfa_offset 48

	movdqu %xmm0, 16(%rsp)
	movq   %rdx, 8(%rsp)
	movq   %rax, 0(%rsp)

	/* set the first argument of mcount_exit as pointer to return values */
	movq %rsp, %rdi

	/* returns original parent address */
	call mcount_exit
	movq %rax, 40(%rsp)

	movq   0(%rsp), %rax
	movq   8(%rsp), %rdx
	movdqu 16(%rsp), %xmm0

	add  $40, %rsp
	.cfi_def_cfa_offset 40

	retq
	.cfi_endproc
END(fentry_return)
