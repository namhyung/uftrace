#include "utils/asm.h"

.text

GLOBAL(_mcount)
	/* setup frame pointer */
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp

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

	/* restore frame pointer */
	ldp	x29, x30, [sp], #16
	ret
END(_mcount)


ENTRY(mcount_return)
	/* setup frame pointer */
	stp	x29, x30, [sp, #-16]!

	/* save arguments */
	stp	x6, x7, [sp, #-16]!
	stp	x4, x5, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!
	stp	x0, x1, [sp, #-16]!

	mov	x0, sp
	bl	mcount_exit
	mov	x16, x0

	/* restore arguments */
	ldp	x0, x1, [sp], #16
	ldp	x2, x3, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x6, x7, [sp], #16

	/* restore frame pointer */
	ldp	x29, x30, [sp], #16

	br	x16
END(mcount_return)

