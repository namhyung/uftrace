/*
 * Based on glibc/ports/sysdeps/arm/dl-trampoline.S
 */

#include "utils/asm.h"

	.text
	.align 2

ENTRY(plt_hooker)
	@ we get called with
	@	stack[0] contains the return address from this call
	@	ip contains &GOT[n+3] (pointer to function)
	@	lr points to &GOT[2]

	push {r0-r3,ip,lr,pc}
	add r0, sp, #28
	sub r2, ip, lr
	sub r2, r2, #4
	lsr r1, r2, #2
	ldr r2, [lr, #-4]
	mov r3, sp
	bl plthook_entry

	cmp r0, $0
	beq 1f

	/*
	 * if we skip the resolver, we also need to pop stack[0]
	 * which saves the original 'lr'.
	 */
	str r0, [sp, #24]
	pop {r0-r3,ip,lr}
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
	str r2, [sp, #24]
	pop {r0-r3,ip,lr,pc}

.L3:
	.align 2
.L2:
	.word _GLOBAL_OFFSET_TABLE_-(.LPIC0+8)
	.word plthook_resolver_addr(GOT)
END(plt_hooker)


ENTRY(plthook_return)
	push {r0-r3, lr, pc}  /* ensure 8-byte alignment */
	mov r0, sp
#ifdef HAVE_ARM_HARDFP
	vpush {d0-d1}
#endif

	bl plthook_exit

#ifdef HAVE_ARM_HARDFP
	vpop {d0-d1}
#endif
	/* update return address (pc) in the stack */
	str r0, [sp, #20]
	pop {r0-r3, lr, pc}
END(plthook_return)
