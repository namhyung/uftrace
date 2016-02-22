.globl plt_hooker
plt_hooker:
	.cfi_startproc
	/* PLT code already pushed symbol and module indices */
	.cfi_adjust_cfa_offset 16
	sub $48, %rsp
	.cfi_adjust_cfa_offset 48
	movq %rdi, 40(%rsp)
	.cfi_offset rdi, -32
	movq %rsi, 32(%rsp)
	.cfi_offset rsi, -40
	movq %rdx, 24(%rsp)
	.cfi_offset rdx, -48
	movq %rcx, 16(%rsp)
	.cfi_offset rcx, -56
	movq %r8, 8(%rsp)
	.cfi_offset r8, -64
	movq %r9, 0(%rsp)
	.cfi_offset r9, -72

	/* child idx */
	movq 56(%rsp), %rsi
	/* address of parent ip */
	lea 64(%rsp), %rdi
	/* module id */
	movq 48(%rsp), %rdx
	/* mcount_args */
	movq %rsp, %rcx

	call plthook_entry

	movq 0(%rsp), %r9
	movq 8(%rsp), %r8
	movq 16(%rsp), %rcx
	movq 24(%rsp), %rdx
	movq 32(%rsp), %rsi
	movq 40(%rsp), %rdi
	add $48, %rsp
	.cfi_adjust_cfa_offset -48

	cmpq $0, %rax
	cmovz plthook_resolver_addr(%rip), %rax
	jz 1f

	add $16, %rsp /* resolver function needs 2 entries on stack */
	.cfi_adjust_cfa_offset -16
1:
	jmp *%rax
	.cfi_endproc
	
.type plt_hooker, @function
.size plt_hooker, .-plt_hooker
.hidden plthook_resolver_addr


.globl plthook_return
plthook_return:
	.cfi_startproc
	sub $24, %rsp
	.cfi_def_cfa_offset 24
	movq %rdx, 8(%rsp)
	.cfi_offset rdx, -16
	movq %rax, 0(%rsp)
	.cfi_offset rax, -24

	call plthook_exit
	movq %rax, 16(%rsp)

	movq 0(%rsp), %rax
	movq 8(%rsp), %rdx
	add $16, %rsp
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc

.type plthook_return, @function
.size plthook_return, .-plthook_return
