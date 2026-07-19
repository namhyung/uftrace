#include "utils/asm.h"

/*
Integer registers
  The AArch64 architecture supports 32 integer registers:

    Regster  |   Volatile?  | Role
  -----------+--------------+---------------------------------------------------
    x0       |     Volatile | Parameter/scratch register 1, result register
    x1 - x7  |     Volatile | Parameter/scratch register 2-8
    x8 - x15 |     Volatile | Scratch registers
   x16 - x17 |     Volatile | Intra-procedure-call scratch registers
   x18       | Non-Volatile | Platform register: in kernel mode, points to KPCR
             |              | for the current processor; in user mode, points to TEB
   x19 - x28 | Non-Volatile | Scratch registers
   x29 / fp  | Non-Volatile | Frame pointer
   x30 / lr  | Non-Volatile | Link register

Floating-point/SIMD registers
  The AArch64 architecture also supports 32 floating-point/SIMD registers:

    Regster  |   Volatile?  | Role
  -----------+--------------+---------------------------------------------------
    v0       |     Volatile | Parameter/scratch register 1, result register
    v1 - v7  |     Volatile | Parameter/scratch registers 2-8
    v8 - v15 | Non-Volatile | Scratch registers (only the low 64 bits are non-volatile)
   v16 - v31 |     Volatile | Scratch registers
*/

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
