/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame: child addr = 0(%rsp), return addr = 8(%rbp) */

.global __xray_entry
.type __xray_entry, @function
__xray_entry:
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

	call xray_entry

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

.size __xray_entry, .-__xray_entry


.global __xray_exit
.type __xray_exit, @function
__xray_exit:
	.cfi_startproc
	sub $24, %rsp
	.cfi_def_cfa_offset 24

	movq %rdx, 8(%rsp)
	.cfi_offset rdx, -16
	movq %rax, 0(%rsp)
	.cfi_offset rax, -24

	/* set the first argument of mcount_exit as pointer to return values */
	movq %rsp, %rdi

	call xray_exit

	movq 0(%rsp), %rax
	movq 8(%rsp), %rdx

	add $24, %rsp
	.cfi_def_cfa_offset 24

	retq
	.cfi_endproc

.size __xray_exit, .-__xray_exit
