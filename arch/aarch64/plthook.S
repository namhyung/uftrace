/*
 * Based on glibc/ports/sysdeps/aarch64/dl-trampoline.S
 */

#include "utils/asm.h"

.text
.align 2

.macro save_args
	stp	x8, x18, [sp, #-16]!
	stp	x6, x7, [sp, #-16]!
	stp	x4, x5, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!
	stp	x0, x1, [sp, #-16]!
.endm

.macro restore_args
	ldp	x0, x1, [sp], #16
	ldp	x2, x3, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x6, x7, [sp], #16
	ldp	x8, x18, [sp], #16
.endm

ENTRY(plt_hooker)
	/*
	 * it gets called with:
	 *  [sp, #8] :   lr
	 *  [sp, #0] :   &PLTGOT[n]
	 *  x16 (ip0):   &PLTGOT[2]
	 *  x17 (ip1):   address of dl resolver
	 */

	stp	x16, x17, [sp, #-16]!
	save_args	/* sp -= 80 */

	add	x0, sp, #104
	ldr	x1, [sp, #96]
	sub	x1, x1, x16
	lsr	x1, x1, #3
	sub	x1, x1, #1
	ldr	x2, [x16, #-8]
	mov	x3, sp
	bl	plthook_entry

	cmp	x0, #0
	b.eq	.L1

	mov	x16, x0

	restore_args

	/* if we skip the resolver, it also needs to pop stacks */
	add	sp, sp, #32

	/* restore original LR */
	ldr	x30, [sp, #-8]

	br	x16

.L1:
	restore_args
	/* restore original stack layout */
	add	sp, sp, #16

	adrp	x17, plthook_resolver_addr
	ldr	x17, [x17, #:lo12:plthook_resolver_addr]

	/* restore original contents */
	ldr	x16, [sp, #-16]
	ldr	x30, [sp, #8]

	br	x17
END(plt_hooker)


ENTRY(plthook_return)
	/* setup frame pointer */
	stp	x29, x30, [sp, #-16]!

	/* save return values */
	stp	x0, x1, [sp, #-16]!
	stp	d0, d1, [sp, #-16]!

	/*
	 * save indirect result location register
	 * used in C++ for returning non-trivial objects
	 */
	stp	x8, x18, [sp, #-16]!

	add	x0, sp, #32

	bl	plthook_exit
	mov	x16, x0

	/* restore indirect result location register */
	ldp	x8, x18, [sp], #16

	/* restore return values */
	ldp	d0, d1, [sp], #16
	ldp	x0, x1, [sp], #16

	/* restore frame pointer */
	ldp	x29, x30, [sp], #16

	br	x16
END(plthook_return)
