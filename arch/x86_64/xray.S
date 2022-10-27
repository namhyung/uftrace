/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame: child addr = 0(%rsp), return addr = 8(%rbp) */

#include "utils/asm.h"

GLOBAL(__xray_entry)
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

	movq %rdi, 40(%rsp)
	movq %rsi, 32(%rsp)
	movq %rdx, 24(%rsp)
	movq %rcx, 16(%rsp)
	movq %r8,   8(%rsp)
	movq %r9,   0(%rsp)

	/* child ip */
#ifdef ENABLE_LTTNG
	movq 112(%rsp), %rsi
#else
	movq 48(%rsp), %rsi
#endif // ENABLE_LTTNG

	/* parent location */
#ifdef ENABLE_LTTNG
	lea 120(%rsp), %rdi
#else
	lea 56(%rsp), %rdi
#endif // ENABLE_LTTNG

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
END(__xray_entry)


ENTRY(__xray_exit)
	.cfi_startproc
#ifdef ENABLE_LTTNG
	sub $88, %rsp  /* return address already consume 8 byte */
	.cfi_def_cfa_offset 88

	vmovdqu %ymm0, 56(%rsp)
    vmovdqu %ymm1, 24(%rsp)
	movq    %rdi,  16(%rsp)
#else
	sub $40, %rsp  /* return address already consume 8 byte */
	.cfi_def_cfa_offset 40

	movq   %rdi,  32(%rsp)
	/* save original return values */
	movdqu %xmm0, 16(%rsp)
#endif // ENABLE_LTTNG
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
#ifdef ENABLE_LTTNG
	movq    16(%rsp), %rdi
    vmovdqu 24(%rsp), %ymm1
    vmovdqu 56(%rsp), %ymm0

    add $88, %rsp
#else

	add $40, %rsp
#endif // ENABLE_LTTNG

	retq
	.cfi_endproc
END(__xray_exit)
