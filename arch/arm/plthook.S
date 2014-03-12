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

	push {r0-r4,ip,lr,pc}
	add r0, sp, #32
	sub r2, ip, lr
	sub r2, r2, #4
	lsr r1, r2, #2
	ldr r2, [lr, #-4]
	bl plthook_entry

	cmp r0, $0
	beq 1f

	/*
	 * if we skip the resolver, we also need to pop stack[0]
	 * which saves the original 'lr'.
	 */
	str r0, [sp, #28]
	pop {r0-r4,ip,lr}
	add sp, sp, #8
	ldr lr, [sp, #-4]
	ldr pc, [sp, #-8] /* return */
	
1:
	ldr r2, .L2
.LPIC0:
	add r2, pc, r2
	ldr r3, .L2+4
	ldr r1, [r2, r3]
	ldr r2, [r1]
	str r2, [sp, #28]
	pop {r0-r4,ip,lr,pc}

.L3:
	.align 2
.L2:
	.word _GLOBAL_OFFSET_TABLE_-(.LPIC0+8)
	.word plthook_resolver_addr(GOT)

	.size plt_hooker, .-plt_hooker


	.globl plthook_return
	.type plthook_return, #function
plthook_return:
	push {r0-r4,lr,pc}
	bl plthook_exit
	str r0, [sp, #24]
	pop {r0-r4,lr,pc}

