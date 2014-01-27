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
	/* parent ip */
	movq 64(%rsp), %rdi

	call plthook_entry
	cmpq $0, %rax
	jne 1f

	/* hijack return address */
	movabs $plthook_return@GOTOFF, %rdx
	lea _GLOBAL_OFFSET_TABLE_(%rip), %rcx
	add %rcx, %rdx
	movq %rdx, 64(%rsp)
1:
	movq plthook_resolver_addr(%rip), %rax

	popq %r9
	popq %r8
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi

	jmp *%rax /* original resolver function */
	
.type plt_hooker, @function
.size plt_hooker, .-plt_hooker
.hidden plthook_resolver_addr

plthook_return:
	pushq %rax
	pushq %rax

	call plthook_exit

	movq %rax, 8(%rsp)
	popq %rax
	retq
.type plthook_return, @function
.size plthook_return, .-plthook_return
