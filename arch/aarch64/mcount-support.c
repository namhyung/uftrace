#include <stdlib.h>
#include <assert.h>

#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/filter.h"

int mcount_get_register_arg(struct mcount_arg_context *ctx,
			    struct uftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	int reg_idx;

	switch (spec->type) {
	case ARG_TYPE_REG:
		reg_idx = spec->reg_idx;
		break;
	case ARG_TYPE_FLOAT:
		if (spec->size <= 4)
			reg_idx = spec->idx + AARCH64_REG_FLOAT_BASE;
		else
			reg_idx = spec->idx + AARCH64_REG_DOUBLE_BASE;
		break;
	case ARG_TYPE_INDEX:
		reg_idx = spec->idx; /* for integer arguments */
		break;
	case ARG_TYPE_STACK:
	default:
		return -1;
	}

	switch (reg_idx) {
	case AARCH64_REG_R0:
		ctx->val.i = ARG1(regs);
		break;
	case AARCH64_REG_R1:
		ctx->val.i = ARG2(regs);
		break;
	case AARCH64_REG_R2:
		ctx->val.i = ARG3(regs);
		break;
	case AARCH64_REG_R3:
		ctx->val.i = ARG4(regs);
		break;
	case AARCH64_REG_R4:
		ctx->val.i = ARG5(regs);
		break;
	case AARCH64_REG_R5:
		ctx->val.i = ARG6(regs);
		break;
	case AARCH64_REG_R6:
		ctx->val.i = ARG7(regs);
		break;
	case AARCH64_REG_R7:
		ctx->val.i = ARG8(regs);
		break;
	case AARCH64_REG_S0:
		asm volatile ("str s0, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_S1:
		asm volatile ("str s1, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_S2:
		asm volatile ("str s2, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_S3:
		asm volatile ("str s3, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_S4:
		asm volatile ("str s4, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_S5:
		asm volatile ("str s5, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_S6:
		asm volatile ("str s6, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_S7:
		asm volatile ("str s7, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_D0:
		asm volatile ("str d0, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_D1:
		asm volatile ("str d1, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_D2:
		asm volatile ("str d2, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_D3:
		asm volatile ("str d3, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_D4:
		asm volatile ("str d4, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_D5:
		asm volatile ("str d5, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_D6:
		asm volatile ("str d6, %0\n" : "=m" (ctx->val.v));
		break;
	case AARCH64_REG_D7:
		asm volatile ("str d7, %0\n" : "=m" (ctx->val.v));
		break;
	default:
		return -1;
	}

	return 0;
}

void mcount_get_stack_arg(struct mcount_arg_context *ctx,
			  struct uftrace_arg_spec *spec)
{
	int offset = 1;

	switch (spec->type) {
	case ARG_TYPE_STACK:
		offset = spec->stack_ofs;
		break;
	case ARG_TYPE_FLOAT:
		offset = spec->idx - ARCH_MAX_FLOAT_REGS;
		break;
	case ARG_TYPE_INDEX:
		offset = spec->idx - ARCH_MAX_REG_ARGS;
		break;
	case ARG_TYPE_REG:
	default:
		/* should not reach here */
		pr_err_ns("invalid stack access for arguments\n");
		break;
	}

	if (offset < 1 || offset > 100)
		pr_dbg("invalid stack offset: %d\n", offset);

	memcpy(ctx->val.v, ctx->stack_base + offset, spec->size);
}

void mcount_arch_get_arg(struct mcount_arg_context *ctx,
			 struct uftrace_arg_spec *spec)
{
	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct uftrace_arg_spec *spec)
{
	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

	/* type of return value cannot be FLOAT, so check format instead */
	if (spec->fmt == ARG_FMT_FLOAT) {
		if (spec->size <= 4)
			asm volatile ("str s0, %0\n" : "=m" (ctx->val.v));
		else
			asm volatile ("str d0, %0\n" : "=m" (ctx->val.v));
	}
	else
		memcpy(ctx->val.v, ctx->retval, spec->size);
}

unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx)
{
	struct sym *sym;

	sym = &pd->dsymtab.sym[0];
	return sym->addr - ARCH_PLT0_SIZE;
}
