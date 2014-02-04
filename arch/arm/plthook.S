/*
 * Based on glibc/ports/sysdeps/arm/dl-trampoline.S
 */
	.text
	.globl plt_hooker
	.type plt_hooker, #function
	.align 2
plt_hooker:
	@ we get called with
	@	stack[0] contains the return address from this call
	@	ip contains &GOT[n+3] (pointer to function)
	@	lr points to &GOT[2]

	push {r0-r4,ip,lr}
	ldr r0 [sp, #24]
	sub r2, ip, lr
	sub r2, r2, #4
	lsr r1, r2, #2
	bl plthook_entry
	/* check return value and setup plt_exit */
	pop {r0-r4,ip,lr}
	bx plthook_resolver_addr
