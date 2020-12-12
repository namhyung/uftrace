#include "utils/asm.h"

.text

/* universal stack constraint: (SP mod 16) == 0 */
GLOBAL(_mcount)
	/* setup frame pointer */
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp

        /* save indirect result location */
	stp	x8, x18, [sp, #-16]!

	/* save arguments */
	stp	x6, x7, [sp, #-16]!
	stp	x4, x5, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!
	stp	x0, x1, [sp, #-16]!

	ldr	x0, [x29]
	add	x0, x0, #8
	mov	x1, x30
	mov	x2, sp
	bl	mcount_entry

	/* restore arguments */
	ldp	x0, x1, [sp], #16
	ldp	x2, x3, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x6, x7, [sp], #16

        /* restore indirect result location */
	ldp	x8, x18, [sp], #16

	/* restore frame pointer */
	ldp	x29, x30, [sp], #16
	ret
END(_mcount)


ENTRY(mcount_return)
	/* setup frame pointer */
	stp	x29, x30, [sp, #-16]!

	/* save return values */
	stp	x0, x1, [sp, #-16]!
	str	q0, [sp, #-16]!

	/*
	 * save indirect result location register
	 * used in C++ for returning non-trivial objects
	 */
	stp	x8, x18, [sp, #-16]!

	add	x0, sp, #32

	bl	mcount_exit
	mov	x16, x0

	/* restore indirect result location register */
	ldp	x8, x18, [sp], #16

	/* restore return values */
	ldr	q0, [sp], #16
	ldp	x0, x1, [sp], #16

	/* restore frame pointer */
	ldp	x29, x30, [sp], #16

	br	x16
END(mcount_return)
