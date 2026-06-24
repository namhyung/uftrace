#include "utils/asm.h"

.text

/*
 * Dynamic tracing entry trampoline (for -fpatchable-function-entry).
 *
 * A patched function entry is turned into:
 *     auipc t0, %pcrel_hi(module_trampoline)
 *     jalr  t0, %pcrel_lo(module_trampoline)(t0)
 * Note the link register is t0 (not ra), so the caller's return address in
 * 'ra' is preserved.  After the jalr:
 *     ra : the function's own return address (to its caller)
 *     t0 : where to resume in the patched function (= func_entry + 8)
 *     a0-a7, fa0-fa7 : the function's arguments
 *
 * The per-module trampoline loads the absolute address of __dentry__ and
 * jumps here.  We spill 'ra' so that mcount_entry() can hijack the return
 * address (replacing it with the dynamic return trampoline), then resume the
 * function via t0.
 */
GLOBAL(__dentry__)
	addi	sp, sp, -80

	/* save resume address (t0) and the real return address (ra) */
	sd	t0, 72(sp)
	sd	ra, 64(sp)

	/* save integer arguments (mcount_regs layout: a0..a7 at 0..56) */
	sd	a0, 0(sp)
	sd	a1, 8(sp)
	sd	a2, 16(sp)
	sd	a3, 24(sp)
	sd	a4, 32(sp)
	sd	a5, 40(sp)
	sd	a6, 48(sp)
	sd	a7, 56(sp)

	/* parent_loc = &saved_ra (mcount_entry hijacks the return here) */
	addi	a0, sp, 64
	/* child = function entry = resume(t0) - 8 */
	addi	a1, t0, -8
	/* regs = &saved arguments */
	mv	a2, sp

	call	mcount_entry

	/* reload the (possibly hijacked) return address into ra */
	ld	ra, 64(sp)

	/* restore arguments */
	ld	a0, 0(sp)
	ld	a1, 8(sp)
	ld	a2, 16(sp)
	ld	a3, 24(sp)
	ld	a4, 32(sp)
	ld	a5, 40(sp)
	ld	a6, 48(sp)
	ld	a7, 56(sp)

	/* restore resume address */
	ld	t0, 72(sp)

	addi	sp, sp, 80

	/* resume the patched function body */
	jr	t0
END(__dentry__)
