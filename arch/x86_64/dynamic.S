/*
 *         argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9
 *
 *         if %rax have value bigger than 0, it means return address
 *         to the function have patched for dynamic tracing.
 *         otherwise, it must be 0 that means error occurred.
 *         stack frame : parent addr = 8(%rsp), child addr = (%rsp)
 *
 *         For example:
 *
 *         Parent(caller): main()
 *         Child(callee): Hello()
 *
 *         Dump of assembler code for function main:
 *            0x00000000004005b6 <+0>:     callq  *0x20043c(%rip)        # 0x6009f8
 *            0x00000000004005bc <+6>:     nop
 *            0x00000000004005bd <+7>:     nop
 *            0x00000000004005be <+8>:     nop
 *            0x00000000004005bf <+9>:     mov    $0x400678,%edi
 *            0x00000000004005c4 <+14>:    callq  0x4004a0 <dlopen@plt>
 *            0x00000000004005c9 <+19>:    mov    $0x0,%eax
 *            0x00000000004005ce <+24>:    callq  0x400597 <Hello>
 * parent  => 0x00000000004005d3 <+29>:    mov    $0x0,%eax
 *            0x00000000004005d8 <+34>:    pop    %rbp
 *            0x00000000004005d9 <+35>:    retq
 *
 *         Dump of assembler code for function Hello:
 *            0x0000000000400597 <+0>:     callq  *0x20045b(%rip)        # 0x6009f8
 * child   => 0x000000000040059d <+6>:     nop
 *            0x000000000040059e <+7>:     nop
 *            0x000000000040059f <+8>:     movq   $0x400668,-0x8(%rbp)
 *            0x00000000004005a7 <+16>:    mov    -0x8(%rbp),%rax
 *            0x00000000004005ab <+20>:    mov    %rax,%rdi
 *            0x00000000004005ae <+23>:    callq  0x400480 <puts@plt>
 *            0x00000000004005b3 <+28>:    nop
 *            0x00000000004005b4 <+29>:    leaveq
 *            0x00000000004005b5 <+30>:    retq
 *
 */

#include "utils/asm.h"

GLOBAL(__dentry__)
	.cfi_startproc
	sub $48, %rsp
	.cfi_adjust_cfa_offset 48

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

	/* save scratch registers due to -fipa-ra */
	push %r10
	push %r11

	call mcount_entry

	/* original stack pointer */
	movq 24(%rsp), %rdx

	/* child addr */
	movq 48(%rdx), %rdi

	/* find location that has the original code */
	call mcount_find_code

	/* original stack pointer */
	movq 24(%rsp), %rdx

	/* overwrite return address */
	movq %rax, 48(%rdx)

	pop  %r11
	pop  %r10
	pop  %rax

	movq %rdx, %rsp

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
END(__dentry__)


ENTRY(dynamic_return)
	.cfi_startproc
	sub    $96, %rsp
	.cfi_def_cfa_offset 96

	/* save all caller-saved registers due to -fipa-ra */
	movq   %r11,  80(%rsp)
	movq   %r10,  72(%rsp)
	movq   %r9,   64(%rsp)
	movq   %r8,   56(%rsp)
	movq   %rdi,  48(%rsp)
	movq   %rsi,  40(%rsp)
	movq   %rcx,  32(%rsp)

	/* below are used to carry return value */
	movdqu %xmm0, 16(%rsp)
	movq   %rdx,   8(%rsp)
	movq   %rax,   0(%rsp)

	/* set the first argument of mcount_exit as pointer to return values */
	movq   %rsp,   %rdi

	/* align stack pointer to 16-byte */
	andq   $0xfffffffffffffff0, %rsp
	sub    $16,    %rsp
	/* save original stack pointer */
	movq   %rdi,   (%rsp)

	/* returns original parent address */
	call   mcount_exit

	/* restore original stack pointer */
	movq   (%rsp), %rsp

	/* restore orignal return address in parent */
	movq   %rax,   88(%rsp)

	movq    0(%rsp), %rax
	movq    8(%rsp), %rdx
	movdqu 16(%rsp), %xmm0

	movq   32(%rsp), %rcx
	movq   40(%rsp), %rsi
	movq   48(%rsp), %rdi
	movq   56(%rsp), %r8
	movq   64(%rsp), %r9
	movq   72(%rsp), %r10
	movq   80(%rsp), %r11

	add    $88, %rsp
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc
END(dynamic_return)
