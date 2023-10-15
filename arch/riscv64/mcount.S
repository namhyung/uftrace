#include "utils/asm.h"

.text

GLOBAL(_mcount)
	/* setup frame pointer & return address */
	addi sp, sp, -80
	sd ra, 72(sp)
	sd fp, 64(sp)
	addi fp, sp, 80

	/* save arguments */
	sd a7, 56(sp)
	sd a6, 48(sp)
	sd a5, 40(sp)
	sd a4, 32(sp)
	sd a3, 24(sp)
	sd a2, 16(sp)
	sd a1, 8(sp)
	sd a0, 0(sp)

	/* parent location */
	ld t1, 64(sp)
	addi t1, t1, -8
	mv a0, t1

	/* child addr */
	mv a1, ra

	/* mcount_args */
	mv a2, sp

	/* call mcount_entry func */
	call mcount_entry

	/* restore argunents */
	ld a0, 0(sp)
	ld a1, 8(sp)
	ld a2, 16(sp)
	ld a3, 24(sp)
	ld a4, 32(sp)
	ld a5, 40(sp)
	ld a6, 48(sp)
	ld a7, 56(sp)

	/* restore frame pointer */
	ld fp, 64(sp)
	ld ra, 72(sp)

	addi sp, sp, 80

	ret
END(_mcount)

ENTRY(mcount_return)
	/* setup frame pointer & return address */
	addi sp, sp, -48
	sd ra, 40(sp)
	sd fp, 32(sp)
	addi fp, sp, 48

	/* save return values */
	fsd fa0, 16(sp)
	sd a1, 8(sp)
	sd a0, 0(sp)

	/* set the first argument of mcount_exit as pointer to return values */
	addi a0, sp, 0

	/* call mcount_exit func */
	call mcount_exit

	mv t1, a0

	/* restore return values */
	ld a0, 0(sp)
	ld a1, 8(sp)
	fld fa0, 16(sp)

	/* restore frame pointer */
	ld fp, 32(sp)
	ld ra, 40(sp)

	addi sp, sp, 48

	/* call return address */
	jr t1
END(mcount_return)
