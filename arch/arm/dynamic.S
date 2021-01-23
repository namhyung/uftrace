#include "utils/asm.h"

	.text
	.align 2

/* universal stack constraint: (SP mod 16) == 0 */
/* frame pointer was saved in the trampoline : push {fp, lr} */
GLOBAL(__dentry__)
	/* save original child address for mcount_find_code */
	push	{lr}

	/* save arguments */
	push 	{r0-r3}

	add	r0, sp, #24 /* r0 points to pushed LR (parent_loc) */
	mov 	r1, lr      /* child ip */
	mov	r2, sp      /* mcount_args */

	bl 	mcount_entry

	/* child addr */
	ldr	r0, [sp, #16]

	/* find location that has the original code */
	bl	mcount_find_code

	/* overwrite return address */
	str	r0, [sp, #16]

	/* restore arguments */
	pop 	{r0-r3}

	/* actual return address from mcount_find_code() */
	pop	{ip}

	/* restore fp and lr registers*/
	pop	{fp, lr}

	/* jump to the save insn */
	bx	ip
END(__dentry__)


ENTRY(dynamic_return)
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
END(dynamic_return)
