/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame (with -pg): return addr = 8(%rbp), prev fp = 0(%rbp) */
/* stack frame (with -fentry): return addr = (%rsp), prev fp = 8(%rsp) */

.global __fentry__
.type __fentry__, @function
__fentry__:
	.cfi_startproc
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

	/* child ip */
	movq 48(%rsp), %rsi
	/* parent ip */
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

.size __fentry__, .-__fentry__


.global fentry_return
.type fentry_return, @function
fentry_return:
	.cfi_startproc
	sub  $24, %rsp
	.cfi_def_cfa_offset 24

	movq %rdx, 8(%rsp)
	.cfi_offset rdx, -16
	movq %rax, 0(%rsp)
	.cfi_offset rax, -24

	/* set the first argument of mcount_exit as pointer to return values */
	movq %rsp, %rdi

	/* returns original parent address */
	call mcount_exit
	movq %rax, 16(%rsp)

	movq 0(%rsp), %rax
	movq 8(%rsp), %rdx

	add  $16, %rsp
	.cfi_def_cfa_offset 16

	retq
	.cfi_endproc

.size fentry_return, .-fentry_return
