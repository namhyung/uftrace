.globl plt_hooker
.type plt_hooker, @function
plt_hooker:
	.cfi_startproc
	/* PLT code already pushed symbol and module indices */
	.cfi_adjust_cfa_offset 16
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

	/* check stack alignment before calling plthook_entry() */
	lea (%rsp), %rdi
	callq is_aligned
	cmpq $0, %rax

	/* child idx */
	movq 64(%rsp), %rsi
	/* address of parent ip */
	lea 72(%rsp), %rdi
	/* module id */
	movq 56(%rsp), %rdx
	/* mcount_args */
	lea 8(%rsp), %rcx
	jne .L1
	call plthook_entry
	jmp .L2
.L1:
	/* For the 16-byte stack alignment */
	sub $8, %rsp
	call plthook_entry
	add $8, %rsp
.L2:
	movq 8(%rsp), %r9
	movq 16(%rsp), %r8
	movq 24(%rsp), %rcx
	movq 32(%rsp), %rdx
	movq 40(%rsp), %rsi
	movq 48(%rsp), %rdi
	add $56, %rsp
	.cfi_adjust_cfa_offset -56

	cmpq $0, %rax
	cmovz plthook_resolver_addr(%rip), %rax
	jz 1f

	add $16, %rsp /* resolver function needs 2 entries on stack */
	.cfi_adjust_cfa_offset -16
1:
	jmp *%rax
	.cfi_endproc
	
.size plt_hooker, .-plt_hooker
.hidden plthook_resolver_addr


.globl plthook_return
.type plthook_return, @function
plthook_return:
	.cfi_startproc
	sub $32, %rsp
	.cfi_def_cfa_offset 32
	movq %rdx, 8(%rsp)
	.cfi_offset rdx, -24
	movq %rax, 0(%rsp)
	.cfi_offset rax, -32

	/* set the first argument of plthook_exit as pointer to return values */
	movq %rsp, %rdi

	call plthook_exit
	movq %rax, 24(%rsp)

	movq 0(%rsp), %rax
	movq 8(%rsp), %rdx
	add $24, %rsp
	.cfi_def_cfa_offset 8
	retq
	.cfi_endproc

.size plthook_return, .-plthook_return
