#include <assert.h>

#include "mcount-arch.h"
#include "libmcount/mcount.h"
#include "utils/filter.h"

long mcount_arch_get_arg(struct mcount_arg_context *ctx,
			 struct ftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;

	if (spec->idx <= ARCH_MAX_REG_ARGS) {
		switch (spec->idx) {
		case 1:
			return ARG1(regs);
		case 2:
			return ARG2(regs);
		case 3:
			return ARG3(regs);
		case 4:
			return ARG4(regs);
		case 5:
			return ARG5(regs);
		case 6:
			return ARG6(regs);
		default:
			/* cannot reach here */
			return 0;
		}
	}

	/* TODO: limit max argument index */
	return ctx->stack_base[spec->idx - ARCH_MAX_REG_ARGS];
}
