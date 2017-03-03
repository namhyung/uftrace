#include "utils/asm.h"

	.text
	.align 2

/*
 * This function assumes {r0-r3,lr} regsiters are pushed already.
 */
GLOBAL(__dentry__)
	push 	{lr}

	add	r0, sp, #20  /* parent loc */
	mov	r1, lr       /* child ip */
	add	r2, sp, #4   /* mcount_args */
	bl 	mcount_entry

	ldr	r0, [sp]
	bl	mcount_find_code
	mov	ip, r0

	pop	{lr}

	pop 	{r0-r3, lr}
	bx	ip
END(__dentry__)
