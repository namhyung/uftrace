.globl plt_hooker
plt_hooker:
	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	pushq %r8
	pushq %r9

	/* child idx */
	movq 56(%rsp), %rsi
	/* address of parent ip */
	lea 64(%rsp), %rdi

	call plthook_entry
	cmpq $0, %rax
	cmovz plthook_resolver_addr(%rip), %rax

	popq %r9
	popq %r8
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi

	jz 1f

	add $16, %rsp /* resolver function needs 2 entries on stack */
1:
	jmp *%rax
	
.type plt_hooker, @function
.size plt_hooker, .-plt_hooker
.hidden plthook_resolver_addr


.globl plthook_return
plthook_return:
	pushq %rax
	pushq %rax

	call plthook_exit

	movq %rax, 8(%rsp)
	popq %rax
	retq
.type plthook_return, @function
.size plthook_return, .-plthook_return
