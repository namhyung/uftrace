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
#ifdef ENABLE_LTTNG
    sub $112, %rsp
	.cfi_adjust_cfa_offset 112

    vmovdqu %ymm0, 80(%rsp)
    vmovdqu %ymm1, 48(%rsp)
#else
	sub $48, %rsp
	.cfi_adjust_cfa_offset 48
#endif // ENABLE_LTTNG

	/* save register arguments in mcount_args */
	movq %rdi, 40(%rsp)
	movq %rsi, 32(%rsp)
	movq %rdx, 24(%rsp)
	movq %rcx, 16(%rsp)
	movq %r8,   8(%rsp)
	movq %r9,   0(%rsp)

	/* child addr */
#ifdef ENABLE_LTTNG
    movq 112(%rsp), %rsi
#else
	movq 48(%rsp), %rsi
#endif // ENABLE_LTTNG

	/* parent location */
	lea 8(%rbp), %rdi

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
#ifdef ENABLE_LTTNG
    vmovdqu 48(%rsp), %ymm1
    vmovdqu 80(%rsp), %ymm0

    add $112, %rsp
	.cfi_adjust_cfa_offset -112
#else
	add $48, %rsp
	.cfi_adjust_cfa_offset -48
#endif // ENABLE_LTTNG
	retq
	.cfi_endproc
END(mcount)

/*
 * Now, we are just returned from the child, RSP points to the right above the
 * stack address containing the return address (now it is mcount_return), but we
 * should restore the original address and the RSP to return.
 */
ENTRY(mcount_return)
	.cfi_startproc
#ifdef ENABLE_LTTNG
    sub $96, %rsp
	.cfi_def_cfa_offset 96

    vmovdqu %ymm0, 56(%rsp)
    vmovdqu %ymm1, 24(%rsp)
    movq    %rdi,  16(%rsp)
#else
	sub $48, %rsp
	.cfi_def_cfa_offset 48

	movq   %rdi,  32(%rsp)
	movdqu %xmm0, 16(%rsp)
#endif // ENABLE_LTTNG
	movq   %rdx,   8(%rsp)
	movq   %rax,   0(%rsp)

	/* set the first argument of mcount_exit as pointer to return values */
	movq   %rsp, %rdi
	.cfi_def_cfa_register rdi

	/* align stack pointer to 16-byte */
	andq   $0xfffffffffffffff0, %rsp
	sub    $16,  %rsp
	/* save original stack pointer */
	movq   %rdi, (%rsp)

	/* returns original parent address */
	call mcount_exit

	/* restore original stack pointer */
	movq    0(%rsp), %rsp

	/* restore original return address in parent */
#ifdef ENABLE_LTTNG
    movq    %rax, 88(%rsp)
#else
	movq    %rax, 40(%rsp)
#endif // ENABLE_LTTNG

	movq    0(%rsp), %rax
	movq    8(%rsp), %rdx
#ifdef ENABLE_LTTNG
    movq    16(%rsp), %rdi
    vmovdqu 24(%rsp), %ymm1
    vmovdqu 56(%rsp), %ymm0

    add $88, %rsp
#else
	movdqu 16(%rsp), %xmm0
	movq   32(%rsp), %rdi

	add $40, %rsp
#endif // ENABLE_LTTNG
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc
END(mcount_return)
