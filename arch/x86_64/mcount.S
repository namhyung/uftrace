/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame (with -pg): return addr = 8(%rbp), prev fp = 0(%rbp) */
/* stack frame (with -fentry): return addr = (%rsp), prev fp = %rbp */

.globl mcount
mcount:
	.cfi_startproc
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

	/* child ip */
	movq 56(%rsp), %rsi
	sub $9, %rsi

	/* parent location */
	lea 8(%rbp), %rdi

	/* mcount_args */
	lea 8(%rsp), %rdx

	call mcount_entry
	cmpq $0, %rax

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

.type mcount, @function
.size mcount, .-mcount


.globl mcount_return
mcount_return:
	.cfi_startproc
	sub $24, %rsp
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
	add $16, %rsp
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc

.type mcount_return, @function
.size mcount_return, .-mcount_return
