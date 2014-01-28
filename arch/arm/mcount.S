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

.globl __gnu_mcount_nc
__gnu_mcount_nc:
	push 	{r0-r3, lr}
	mov 	r1, lr
	ldr 	r0, [sp, #20]
	bl 	mcount_entry
	cmp 	r0, #0
	bne	1f
	adr 	r3, mcount_return
	add 	r0, sp, #20
	ldr 	r1, [r0]
	ldr 	r2, [r0, #8]
	cmp 	r1, r2		/* leaf function might not push the lr */
	addeq	r0, #8
	str	r3, [r0]
1:
	pop 	{r0-r3, lr}
	mov	ip, lr
	pop	{ lr }
	bx	ip

.type __gnu_mcount_nc, %function
.size __gnu_mcount_nc, .-__gnu_mcount_nc


mcount_return:
	push 	{r0-r3, lr}
	bl 	mcount_exit
	mov 	ip, r0
	pop 	{r0-r3, lr}
	bx	ip
.type mcount_return, %function
.size mcount_return, .-mcount_return
