#include "utils/asm.h"

.hidden plthook_resolver_addr

ENTRY(plt_hooker)
	.cfi_startproc
	/* PLT code already pushed symbol and module indices */
	.cfi_adjust_cfa_offset 16
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

	/* module id */
#ifdef ENABLE_LTTNG
	movq 112(%rsp), %rdx
#else
	movq 48(%rsp), %rdx
#endif // ENABLE_LTTNG

	/* child idx */
#ifdef ENABLE_LTTNG
	movq 120(%rsp), %rsi
#else
	movq 56(%rsp), %rsi
#endif // ENABLE_LTTNG

	/* parent location */
#ifdef ENABLE_LTTNG
	leaq 128(%rsp), %rdi
#else
	leaq 64(%rsp), %rdi
#endif // ENABLE_LTTNG

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
#ifdef ENABLE_LTTNG
	vmovdqu 48(%rsp), %ymm1
    vmovdqu 80(%rsp), %ymm0

	add $112, %rsp
	.cfi_adjust_cfa_offset -112
#else
	add $48, %rsp
	.cfi_adjust_cfa_offset -48
#endif // ENABLE_LTTNG

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
#ifdef ENABLE_LTTNG
	sub $104, %rsp
	.cfi_def_cfa_offset 104

	vmovdqu %ymm0, 56(%rsp)
    vmovdqu %ymm1, 24(%rsp)
	movq    %rdi,  16(%rsp)
#else
	sub $56, %rsp
	.cfi_def_cfa_offset 56

	movq   %rdi,  32(%rsp)
	movdqu %xmm0, 16(%rsp)
#endif // ENABLE_LTTNG
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
#ifdef ENABLE_LTTNG
	movq   %rax, 96(%rsp)
#else
	movq   %rax, 48(%rsp)
#endif // ENABLE_LTTNG

	movq    0(%rsp), %rax
	movq    8(%rsp), %rdx
#ifdef ENABLE_LTTNG
	movq    16(%rsp), %rdi
    vmovdqu 24(%rsp), %ymm1
    vmovdqu 56(%rsp), %ymm0

    add $96, %rsp
#else
	movdqu 16(%rsp), %xmm0
	movq   32(%rsp), %rdi

	add $48, %rsp
#endif // ENABLE_LTTNG
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc
END(plthook_return)
