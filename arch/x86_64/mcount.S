/* argument passing: %rdi, %rsi, %rdx, %rcx, %r8, %r9 */
/* return value: %rax */
/* callee saved: %rbx, %rbp, %rsp, %r12-r15 */
/* stack frame (with -pg): return addr = 8(%rbp), prev fp = 0(%rbp) */
/* stack frame (with -fentry): return addr = (%rsp), prev fp = %rbp */

.globl mcount
mcount:
	sub $56, %rsp
	movq %rdi, 48(%rsp)
	movq %rsi, 40(%rsp)
	movq %rdx, 32(%rsp)
	movq %rcx, 24(%rsp)
	movq %r8, 16(%rsp)
	movq %r9, 8(%rsp)
	movq %rax, 0(%rsp)

	/* child ip */
	movq 56(%rsp), %rsi
	sub $9, %rsi

	/* parent ip */
	lea 8(%rbp), %rdi

	call mcount_entry
	cmpq $0, %rax
	jne 1f

	/* hijack return address */
	movabs $mcount_return@GOTOFF, %rdx
	lea _GLOBAL_OFFSET_TABLE_(%rip), %rcx
	add %rcx, %rdx
	movq %rdx, 8(%rbp)
1:
	movq 0(%rsp), %rax
	movq 8(%rsp), %r9
	movq 16(%rsp), %r8
	movq 24(%rsp), %rcx
	movq 32(%rsp), %rdx
	movq 40(%rsp), %rsi
	movq 48(%rsp), %rdi
	add $56, %rsp
	retq

.type mcount, @function
.size mcount, .-mcount


.globl mcount_return
mcount_return:
	sub $24, %rsp
	movq %rdx, 8(%rsp)
	movq %rax, 0(%rsp)

	/* returns original parent address */
	call mcount_exit
	movq %rax, 16(%rsp)

	movq 0(%rsp), %rax
	movq 8(%rsp), %rdx
	add $16, %rsp
	retq

.type mcount_return, @function
.size mcount_return, .-mcount_return
