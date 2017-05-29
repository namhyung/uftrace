/* Shamelessly copied from linux/arch/arm/kernel/entry-common.S */
/*
 * When compiling with -pg, gcc inserts a call to the mcount routine at the
 * start of every function.  In mcount, apart from the function's address (in
 * lr), we need to get hold of the function's caller's address.
 *
 * Older GCCs (pre-4.4) inserted a call to a routine called mcount like this:
 *
 *	bl	mcount
 *
 * These versions have the limitation that in order for the mcount routine to
 * be able to determine the function's caller's address, an APCS-style frame
 * pointer (which is set up with something like the code below) is required.
 *
 *	mov     ip, sp
 *	push    {fp, ip, lr, pc}
 *	sub     fp, ip, #4
 *
 * With EABI, these frame pointers are not available unless -mapcs-frame is
 * specified, and if building as Thumb-2, not even then.
 *
 * Newer GCCs (4.4+) solve this problem by introducing a new version of mcount,
 * with call sites like:
 *
 *	push	{lr}
 *	bl	__gnu_mcount_nc
 *
 * With these compilers, frame pointers are not necessary.
 *
 * mcount can be thought of as a function called in the middle of a subroutine
 * call.  As such, it needs to be transparent for both the caller and the
 * callee: the original lr needs to be restored when leaving mcount, and no
 * registers should be clobbered.  (In the __gnu_mcount_nc implementation, we
 * clobber the ip register.  This is OK because the ARM calling convention
 * allows it to be clobbered in subroutines and doesn't use it to hold
 * parameters.)
 */

#include "utils/asm.h"

	.text
	.align 2

GLOBAL(__gnu_mcount_nc)
	push 	{r0-r3, lr}
	ands	r3, lr, #1  /* check lr for ARM/THUMB detection */
	add	r0, sp, #20 /* r0 points to pushed LR  */
	bne	1f
	ldr	r1, [fp]    /* fp (=r11) might point to return address on ARM */
	ldr	r2, [r0]
	cmp	r1, r2
	moveq	r0, fp
1:
	mov 	r1, lr      /* child ip */
	mov	r2, sp      /* mcount_args */

	bl 	mcount_entry

	pop 	{r0-r3, ip, lr}
	bx	ip
END(__gnu_mcount_nc)


ENTRY(mcount_return)
	push 	{r0-r3, lr}

	/* set the first argument of mcount_exit as pointer to return values */
	mov	r0, sp

	bl 	mcount_exit
	mov 	ip, r0
	pop 	{r0-r3, lr}
	bx	ip
END(mcount_return)
