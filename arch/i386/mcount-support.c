/*
 * basic i386 support for uftrace
 *
 * Copyright (C) 2017. Hanbum Park <kese111@gmail.com>
 *
 * Released under the GPL v2.
 */

#include <string.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "mcount"
#define PR_DOMAIN DBG_MCOUNT

// a max number that retrieves the stack to find the location of
// the real return address of the main function for i386.
#define MAX_SEARCH_STACK 5

#include "libmcount/internal.h"
#include "utils/filter.h"

static bool search_main_ret = false;

/* These functions are implemented in assembly */
extern void mcount(void);
extern void plt_hooker(void);
extern void __fentry__(void);
extern void mcount_return(void);
extern void plthook_return(void);
extern void fentry_return(void);

/* These functions are defined in the current file */
static unsigned long mcount_arch_child_idx(unsigned long child_idx);

const struct mcount_arch_ops mcount_arch_ops = {
	.entry = {
		[UFT_ARCH_OPS_MCOUNT] = (unsigned long)mcount,
		[UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plt_hooker,
		[UFT_ARCH_OPS_FENTRY] = (unsigned long)__fentry__,
	},
	.exit = {
		[UFT_ARCH_OPS_MCOUNT] = (unsigned long)mcount_return,
		[UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plthook_return,
		[UFT_ARCH_OPS_FENTRY] = (unsigned long)fentry_return,
	},
	.child_idx = mcount_arch_child_idx,
};

int mcount_get_register_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	int reg_idx;

	switch (spec->type) {
	case ARG_TYPE_REG:
		reg_idx = spec->reg_idx;
		break;
	default:
		return -1;
	}

	switch (reg_idx) {
	case UFT_I386_REG_ECX:
		ctx->val.i = ARG_REG1(regs);
		break;
	case UFT_I386_REG_EDX:
		ctx->val.i = ARG_REG2(regs);
		break;
	case UFT_I386_REG_XMM0:
		asm volatile("movsd %%xmm0, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_I386_REG_XMM1:
		asm volatile("movsd %%xmm1, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_I386_REG_XMM2:
		asm volatile("movsd %%xmm2, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_I386_REG_XMM3:
		asm volatile("movsd %%xmm3, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_I386_REG_XMM4:
		asm volatile("movsd %%xmm4, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_I386_REG_XMM5:
		asm volatile("movsd %%xmm5, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_I386_REG_XMM6:
		asm volatile("movsd %%xmm6, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_I386_REG_XMM7:
		asm volatile("movsd %%xmm7, %0\n" : "=m"(ctx->val.v));
		break;
	default:
		/* should not reach here */
		pr_err_ns("invalid register access for arguments\n");
		break;
	}

	return 0;
}

void mcount_get_stack_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	int offset;
	unsigned long *addr = ctx->stack_base;

	switch (spec->type) {
	case ARG_TYPE_STACK:
		offset = spec->stack_ofs;
		break;
	case ARG_TYPE_INDEX:
		offset = spec->idx;
		break;
	case ARG_TYPE_FLOAT:
		offset = spec->idx;
		break;
	default:
		/* should not reach here */
		pr_err_ns("invalid stack access for arguments\n");
		break;
	}

	if (offset < 1 || offset > 100) {
		pr_dbg("invalid stack offset: %d\n", offset);
		memset(ctx->val.v, 0, sizeof(ctx->val));
		return;
	}

	addr += offset;

	if (check_mem_region(ctx, (unsigned long)addr))
		memcpy(ctx->val.v, addr, spec->size);
	else {
		pr_dbg("stack address is not allowed: %p\n", addr);
		memset(ctx->val.v, 0, sizeof(ctx->val));
	}
}

void mcount_arch_get_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	/* type of return value cannot be FLOAT, so check format instead */
	if (spec->fmt != ARG_FMT_FLOAT)
		memcpy(ctx->val.v, ctx->retval, spec->size);
	else if (spec->size == 4)
		asm volatile("fstps %0\n\tflds %0" : "=m"(ctx->val.v));
	else if (spec->size == 8)
		asm volatile("fstpl %0\n\tfldl %0" : "=m"(ctx->val.v));
	else if (spec->size == 10)
		asm volatile("fstpt %0\n\tfldt %0" : "=m"(ctx->val.v));
}

void mcount_save_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile("movsd %%xmm0, %0\n" : "=m"(ctx->xmm[0]));
	asm volatile("movsd %%xmm1, %0\n" : "=m"(ctx->xmm[1]));
	asm volatile("movsd %%xmm2, %0\n" : "=m"(ctx->xmm[2]));
	asm volatile("movsd %%xmm3, %0\n" : "=m"(ctx->xmm[3]));
	asm volatile("movsd %%xmm4, %0\n" : "=m"(ctx->xmm[4]));
	asm volatile("movsd %%xmm5, %0\n" : "=m"(ctx->xmm[5]));
	asm volatile("movsd %%xmm6, %0\n" : "=m"(ctx->xmm[6]));
	asm volatile("movsd %%xmm7, %0\n" : "=m"(ctx->xmm[7]));
}

void mcount_restore_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile("movsd %0, %%xmm0\n" ::"m"(ctx->xmm[0]));
	asm volatile("movsd %0, %%xmm1\n" ::"m"(ctx->xmm[1]));
	asm volatile("movsd %0, %%xmm2\n" ::"m"(ctx->xmm[2]));
	asm volatile("movsd %0, %%xmm3\n" ::"m"(ctx->xmm[3]));
	asm volatile("movsd %0, %%xmm4\n" ::"m"(ctx->xmm[4]));
	asm volatile("movsd %0, %%xmm5\n" ::"m"(ctx->xmm[5]));
	asm volatile("movsd %0, %%xmm6\n" ::"m"(ctx->xmm[6]));
	asm volatile("movsd %0, %%xmm7\n" ::"m"(ctx->xmm[7]));
}

/*
	For 16-byte stack-alignment,
	the main function stores the return address in its stack scope at prologue.
	When the time comes for the main function to return,
	1. restore the saved return address from stack.
	2. After cleaning up the stack.
	3. Put the return address at the top of the stack and return.
	4. will be returned.

	080485f8 <main>:
	80485f8: 8d 4c 24 04           lea    0x4(%esp),%ecx
	80485fc: 83 e4 f0              and    $0xfffffff0,%esp
	80485ff: ff 71 fc              pushl  -0x4(%ecx)
	8048602: 55                    push   %ebp
	8048603: 89 e5                 mov    %esp,%ebp
	8048605: 51                    push   %ecx
	8048606: 83 ec 14              sub    $0x14,%esp
	8048609: e8 02 fe ff ff        call   8048410 <mcount@plt>

	... ...

	8048645: 8b 4d fc              mov    -0x4(%ebp),%ecx
	8048648: c9                    leave
	8048649: 8d 61 fc              lea    -0x4(%ecx),%esp
	804864c: c3                    ret

	So, in this case. The return address we want to replace with
	mcount_exit is in the stack scope of the main function.
	Non a parent located.

	we search stack for that address.
	we will look for it.
	we will find it, and we will replace it.
	GOOD LUCK!
*/
unsigned long *mcount_arch_parent_location(struct uftrace_sym_info *symtabs,
					   unsigned long *parent_loc, unsigned long child_ip)
{
	if (!search_main_ret) {
		struct uftrace_symbol *parent_sym, *child_sym;
		char *parent_name, *child_name;

		const char *find_main[] = { "__libc_start_main", "main" };
		unsigned long ret_addr;
		unsigned long search_ret_addr;
		bool found_main_ret = false;
		int stack_index = 0;

		ret_addr = *parent_loc;
		parent_sym = find_symtabs(symtabs, ret_addr);
		parent_name = symbol_getname(parent_sym, ret_addr);
		child_sym = find_symtabs(symtabs, child_ip);
		child_name = symbol_getname(child_sym, child_ip);

		// Assuming that this happens only in main..
		if (!(strcmp(find_main[0], parent_name) || strcmp(find_main[1], child_name))) {
			ret_addr = *parent_loc;
			for (stack_index = 1; stack_index < MAX_SEARCH_STACK; stack_index++) {
				search_ret_addr = *(unsigned long *)(parent_loc + stack_index);
				if (search_ret_addr == ret_addr) {
					parent_loc = parent_loc + stack_index;
					found_main_ret = true;
				}
			}
			// if we couldn't found correct position of return address,
			// maybe this approach is not available anymore.
			if (!found_main_ret) {
				pr_dbg2("cannot find ret address of main\n");
			}
			search_main_ret = true;
		}
	}
	return parent_loc;
}

// in i386, the idx value is set to a multiple of 8 unlike other.
static unsigned long mcount_arch_child_idx(unsigned long child_idx)
{
	if (child_idx > 0) {
		if (child_idx % 8) {
			pr_err_ns("the malformed child idx : %lx\n", child_idx);
		}
		child_idx = child_idx / 8;
	}
	return child_idx;
}
