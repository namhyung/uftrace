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
 *
 * Also recent clang generates following code to call mcount.  It saves the
 * fp and lr registers before calling the function:
 *
 *	push	{fp, lr}
 *	mov	fp, sp
 *	sub	sp, sp, #8
 *	bl	mcount
 *
 * I'm not sure subtracting sp by 8 is guaranteed, but anyway it could use
 * fp register to find the return address (lr) of the parent function.
 *
 */

#include "utils/asm.h"

	.text
	.align 2

GLOBAL(__gnu_mcount_nc)
	push 	{r0-r3, lr}  /* note that caller already pushed lr */
	ands	r3, lr, #1  /* check lr for ARM/THUMB detection */
	add	r0, sp, #20 /* r0 points to pushed LR  */
	bne	1f
	ldr	r1, [fp]    /* fp (=r11) might point to return address on THUMB */
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


GLOBAL(mcount)
	push 	{r0-r3, fp, lr}  /* ensure 8-byte alignment */
	ands	r3, lr, #1  /* check lr for ARM/THUMB detection */
	add	r0, fp, #4  /* r0 points to pushed LR  */
	bne	1f
	ldr	r1, [fp]    /* fp (=r11) might point to return address on THUMB */
	ldr	r2, [r0]
	cmp	r1, r2
	moveq	r0, lr
1:
	mov 	r1, lr      /* child ip */
	mov	r2, sp      /* mcount_args */

	bl 	mcount_entry

	pop 	{r0-r3, fp, lr}
	bx	lr
END(mcount)


ENTRY(mcount_return)
	push 	{r0-r3, lr, pc}  /* ensure 8-byte alignment */
	mov	r0, sp
#ifdef HAVE_ARM_HARDFP
	vpush	{d0-d1}
#endif

	bl 	mcount_exit

#if HAVE_ARM_HARDFP
	vpop	{d0-d1}
#endif
	/* update return address (pc) in the stack */
	str 	r0, [sp, #20]
	pop 	{r0-r3, lr, pc}
END(mcount_return)
