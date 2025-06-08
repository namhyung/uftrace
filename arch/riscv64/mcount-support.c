#include <stdlib.h>

#include "libmcount/internal.h"
#include "utils/filter.h"
#include "utils/utils.h"

/* These functions are implemented in assembly */
extern void _mcount(void);
extern void plt_hooker(void);
extern void mcount_return(void);
extern void plthook_return(void);

/* These functions are defined in the current file */
static unsigned long mcount_arch_plthook_addr(struct plthook_data *, int);

const struct mcount_arch_ops mcount_arch_ops = {
	.entry = {
		[UFT_ARCH_OPS_MCOUNT] = (unsigned long)_mcount,
		[UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plt_hooker,
	},
	.exit = {
		[UFT_ARCH_OPS_MCOUNT] = (unsigned long)mcount_return,
		[UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plthook_return,
	},
	.plthook_addr = mcount_arch_plthook_addr,
};

static int mcount_get_register_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	int reg_idx;

	switch (spec->type) {
	case ARG_TYPE_REG:
		reg_idx = spec->reg_idx;
		break;
	case ARG_TYPE_INDEX:
		reg_idx = spec->idx; /* for integer arguments */
		break;
	case ARG_TYPE_FLOAT:
		reg_idx = spec->idx + UFT_RISCV64_REG_FLOAT_BASE;
		break;
	case ARG_TYPE_STACK:
	default:
		return -1;
	}

	ctx->val.i = 0;

	switch (reg_idx) {
	case UFT_RISCV64_REG_A0:
		ctx->val.i = ARG1(regs);
		break;
	case UFT_RISCV64_REG_A1:
		ctx->val.i = ARG2(regs);
		break;
	case UFT_RISCV64_REG_A2:
		ctx->val.i = ARG3(regs);
		break;
	case UFT_RISCV64_REG_A3:
		ctx->val.i = ARG4(regs);
		break;
	case UFT_RISCV64_REG_A4:
		ctx->val.i = ARG5(regs);
		break;
	case UFT_RISCV64_REG_A5:
		ctx->val.i = ARG6(regs);
		break;
	case UFT_RISCV64_REG_A6:
		ctx->val.i = ARG7(regs);
		break;
	case UFT_RISCV64_REG_A7:
		ctx->val.i = ARG8(regs);
		break;
	case UFT_RISCV64_REG_FA0:
		asm volatile("fsd fa0, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_RISCV64_REG_FA1:
		asm volatile("fsd fa1, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_RISCV64_REG_FA2:
		asm volatile("fsd fa2, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_RISCV64_REG_FA3:
		asm volatile("fsd fa3, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_RISCV64_REG_FA4:
		asm volatile("fsd fa4, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_RISCV64_REG_FA5:
		asm volatile("fsd fa5, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_RISCV64_REG_FA6:
		asm volatile("fsd fa6, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_RISCV64_REG_FA7:
		asm volatile("fsd fa7, %0\n" : "=m"(ctx->val.v));
		break;
	default:
		return -1;
	}

	return 0;
}

static void mcount_get_stack_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	int offset;
	unsigned long *addr = ctx->stack_base;

	switch (spec->type) {
	case ARG_TYPE_STACK:
		offset = spec->stack_ofs;
		break;
	case ARG_TYPE_INDEX:
		offset = spec->idx - ARCH_MAX_REG_ARGS;
		break;
	case ARG_TYPE_FLOAT:
		offset = (spec->idx - ARCH_MAX_FLOAT_REGS) * 2 - 1;
		break;
	case ARG_TYPE_REG:
	default:
		/* should not reach here */
		pr_err_ns("invalid stack access for arguments\n");
		break;
	}

	if (offset < 1 || offset > 100) {
		pr_dbg("invalid stack offset: %d\n", offset);
		mcount_memset4(ctx->val.v, 0, sizeof(ctx->val));
		return;
	}

	addr += offset;

	if (check_mem_region(ctx, (unsigned long)addr)) {
		/* save long double arguments properly */
		mcount_memcpy4(ctx->val.v, addr, ALIGN(spec->size, 4));
	}
	else {
		pr_dbg("stack address is not allowed: %p\n", addr);
		mcount_memset4(ctx->val.v, 0, sizeof(ctx->val));
	}
}

static void mcount_get_struct_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	struct uftrace_arg_spec reg_spec = {
		.type = ARG_TYPE_REG,
	};
	void *ptr = ctx->val.p;
	int i;

	for (i = 0; i < spec->struct_reg_cnt; i++) {
		reg_spec.reg_idx = spec->struct_regs[i];

		mcount_get_register_arg(ctx, &reg_spec);
		mcount_memcpy4(ptr, ctx->val.v, sizeof(long));
		ptr += sizeof(long);
	}

	if (spec->stack_ofs > 0) {
		unsigned long *addr = ctx->stack_base + spec->stack_ofs;

		/*
		 * it cannot call mcount_get_stack_arg() since the struct
		 * might be bigger than the ctx->val.  It directly updates
		 * the argument buffer (in the ptr).
		 */
		if (check_mem_region(ctx, (unsigned long)addr))
			mcount_memcpy4(ptr, addr, spec->size);
		else {
			pr_dbg("stack address is not allowed: %p\n", addr);
			mcount_memset4(ptr, 0, spec->size);
		}
	}
	else if (spec->struct_reg_cnt == 0) {
		mcount_get_register_arg(ctx, spec);
		mcount_memcpy4(ptr, ctx->val.v, sizeof(long));
	}
}

void mcount_arch_get_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	if (spec->fmt == ARG_FMT_STRUCT) {
		mcount_get_struct_arg(ctx, spec);
		return;
	}

	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	if (spec->fmt == ARG_FMT_STRUCT)
		mcount_memcpy4(ctx->val.v, ctx->retval, sizeof(long));
	/* type of return value cannot be FLOAT, so check format instead */
	else if (spec->fmt == ARG_FMT_FLOAT) {
		if (spec->size <= 4) {
			asm volatile("fsw fa0, %0\n" : "=m"(ctx->val.v));
		}
		else {
			asm volatile("fsd fa0, %0\n" : "=m"(ctx->val.v));
		}
	}
	else
		mcount_memcpy4(ctx->val.v, ctx->retval, spec->size);
}

void mcount_save_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile("fsd fa0, %0\n" : "=m"(ctx->f[0]));
	asm volatile("fsd fa1, %0\n" : "=m"(ctx->f[1]));
	asm volatile("fsd fa2, %0\n" : "=m"(ctx->f[2]));
	asm volatile("fsd fa3, %0\n" : "=m"(ctx->f[3]));
	asm volatile("fsd fa4, %0\n" : "=m"(ctx->f[4]));
	asm volatile("fsd fa5, %0\n" : "=m"(ctx->f[5]));
	asm volatile("fsd fa6, %0\n" : "=m"(ctx->f[6]));
	asm volatile("fsd fa7, %0\n" : "=m"(ctx->f[7]));
}

void mcount_restore_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile("fld fa0, %0\n" ::"m"(ctx->f[0]));
	asm volatile("fld fa1, %0\n" ::"m"(ctx->f[1]));
	asm volatile("fld fa2, %0\n" ::"m"(ctx->f[2]));
	asm volatile("fld fa3, %0\n" ::"m"(ctx->f[3]));
	asm volatile("fld fa4, %0\n" ::"m"(ctx->f[4]));
	asm volatile("fld fa5, %0\n" ::"m"(ctx->f[5]));
	asm volatile("fld fa6, %0\n" ::"m"(ctx->f[6]));
	asm volatile("fld fa7, %0\n" ::"m"(ctx->f[7]));
}

static unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx)
{
	return pd->plt_addr;
}
