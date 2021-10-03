#include "utils/asm.h"

.text

/* universal stack constraint: (SP mod 16) == 0 */
/* frame pointer was saved in the trampoline */
GLOBAL(__fentry__)
	/* save all caller-saved registers due to -fipa-ra */
	stp	x14, x15, [sp, #-16]!
	stp	x12, x13, [sp, #-16]!
	stp	x10, x11, [sp, #-16]!

	/* platform register and/or scratch registers */
	stp	x8, x9, [sp, #-16]!

	/* also save original child address */
	stp	x29, x30, [sp, #-16]!

	/* save arguments */
	stp	x6, x7, [sp, #-16]!
	stp	x4, x5, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!
	stp	x0, x1, [sp, #-16]!

	stp	d0, d1, [sp, #-16]!

	add	x0, x29, #8
	mov	x1, x30
	add	x2, sp, #16
	bl	mcount_entry

	ldp	d0, d1, [sp], #16

	/* restore arguments */
	ldp	x0, x1, [sp], #16
	ldp	x2, x3, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x6, x7, [sp], #16

	/* actual return address */
	ldp	x16, x17, [sp], #16

	ldp	x8, x9, [sp], #16

	/* caller-saved registers */
	ldp	x10, x11, [sp], #16
	ldp	x12, x13, [sp], #16
	ldp	x14, x15, [sp], #16

	/* restore frame pointer */
	ldp	x29, x30, [sp], #16

	/* jump to the saved insn */
	br	x17
END(__fentry__)
