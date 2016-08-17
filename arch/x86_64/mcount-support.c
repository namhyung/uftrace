#include <assert.h>
#include <string.h>

#include "mcount-arch.h"
#include "libmcount/mcount.h"
#include "utils/filter.h"

void mcount_arch_get_arg(struct mcount_arg_context *ctx,
			 struct ftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	long val;

	if (spec->idx <= ARCH_MAX_REG_ARGS) {
		switch (spec->idx) {
		case 1:
			val = ARG1(regs);
			break;
		case 2:
			val = ARG2(regs);
			break;
		case 3:
			val = ARG3(regs);
			break;
		case 4:
			val = ARG4(regs);
			break;
		case 5:
			val = ARG5(regs);
			break;
		case 6:
			val = ARG6(regs);
			break;
		default:
			/* cannot reach here */
			val = 0;
			break;
		}
	}
	else {
		/* TODO: limit max argument index */
		val = ctx->stack_base[spec->idx - ARCH_MAX_REG_ARGS];
	}

	/* XXX: this assumes little endian */
	memcpy(ctx->val.v, &val, spec->size);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct ftrace_arg_spec *spec)
{
	memcpy(ctx->val.v, ctx->retval, spec->size);
}
