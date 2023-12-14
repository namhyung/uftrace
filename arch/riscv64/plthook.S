#include "utils/asm.h"

.text

/*
 * it gets called with:
 *  t0: module id
 *  t1: PLT index * 8
 */
ENTRY(plt_hooker)
	/* setup frame pointer & return address */
	addi sp, sp, -96
	sd ra, 88(sp)
	sd fp, 80(sp)
	addi fp, sp, 96

	/* temporary registers.. maybe t2, t3 too? */
	sd t0, 72(sp)
	sd t1, 64(sp)

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
	addi a0, sp, 88

	/* child_index */
	srli a1, t1, 3

	/* module_id */
	mv a2, t0

	/* arguments */
	mv a3, sp

	/* call mcount_entry func */
	call plthook_entry

	/* save the actual function address */
	mv t3, a0

	/* restore argunents */
	ld a0, 0(sp)
	ld a1, 8(sp)
	ld a2, 16(sp)
	ld a3, 24(sp)
	ld a4, 32(sp)
	ld a5, 40(sp)
	ld a6, 48(sp)
	ld a7, 56(sp)

	/* restore temp registers */
	ld t1, 64(sp)
	ld t0, 72(sp)

	/* restore frame pointer */
	ld fp, 80(sp)
	ld ra, 88(sp)

	addi sp, sp, 96

	/* if plthook_entry returns 0, call the resolver */
	bne t3, x0, .L1
	la t3, plthook_resolver_addr
	ld t3, 0(t3)

.L1:
	jr t3
END(plt_hooker)

ENTRY(plthook_return)
	/* setup frame pointer & return address */
	addi sp, sp, -48
	sd ra, 40(sp)
	sd fp, 32(sp)
	addi fp, sp, 48

	/* save return values */
	fsd fa0, 16(sp)
	sd a1, 8(sp)
	sd a0, 0(sp)

	/* pass the return values */
	mv a0, sp

	/* call plthook_exit func */
	call plthook_exit

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
END(plthook_return)
