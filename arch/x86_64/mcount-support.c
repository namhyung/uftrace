#include <assert.h>
#include <string.h>

#include "mcount-arch.h"
#include "libmcount/mcount.h"
#include "utils/filter.h"

int mcount_get_register_arg(struct mcount_arg_context *ctx,
			    struct ftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	int reg_idx = spec->idx;

	if (spec->type == ARG_TYPE_FLOAT)
		reg_idx += X86_REG_FLOAT_BASE;

	switch (reg_idx) {
	case X86_REG_RDI:
		ctx->val.i = ARG1(regs);
		break;
	case X86_REG_RSI:
		ctx->val.i = ARG2(regs);
		break;
	case X86_REG_RDX:
		ctx->val.i = ARG3(regs);
		break;
	case X86_REG_RCX:
		ctx->val.i = ARG4(regs);
		break;
	case X86_REG_R8:
		ctx->val.i = ARG5(regs);
		break;
	case X86_REG_R9:
		ctx->val.i = ARG6(regs);
		break;
	case X86_REG_XMM0:
		asm volatile ("movsd %%xmm0, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM1:
		asm volatile ("movsd %%xmm1, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM2:
		asm volatile ("movsd %%xmm2, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM3:
		asm volatile ("movsd %%xmm3, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM4:
		asm volatile ("movsd %%xmm4, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM5:
		asm volatile ("movsd %%xmm5, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM6:
		asm volatile ("movsd %%xmm6, %0\n" : "=m" (ctx->val.v));
		break;
	case X86_REG_XMM7:
		asm volatile ("movsd %%xmm7, %0\n" : "=m" (ctx->val.v));
		break;
	default:
		return -1;
	}

	return 0;
}

void mcount_get_stack_arg(struct mcount_arg_context *ctx,
			  struct ftrace_arg_spec *spec)
{
	int offset = spec->idx - ARCH_MAX_REG_ARGS;

	if (spec->type == ARG_TYPE_FLOAT)
		offset = (spec->idx - ARCH_MAX_FLOAT_REGS) * 2 - 1;

	if (offset < 1 || offset > 100)
		pr_dbg("invalid stack offset: %d\n", offset);

	memcpy(ctx->val.v, ctx->stack_base + offset, spec->size);
}

void mcount_arch_get_arg(struct mcount_arg_context *ctx,
			 struct ftrace_arg_spec *spec)
{
	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct ftrace_arg_spec *spec)
{
	/* type of return value is always INDEX, so check format instead */
	if (spec->fmt != ARG_FMT_FLOAT)
		memcpy(ctx->val.v, ctx->retval, spec->size);
	else
		asm volatile ("movsd %%xmm0, %0\n" : "=m" (ctx->val.v));
}
