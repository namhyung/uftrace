#include "mcount-arch.h"
#include "libmcount/mcount.h"
#include "utils/filter.h"

void mcount_arch_get_arg(struct mcount_arg_context *ctx,
			 struct ftrace_arg_spec *spec)
{
	memset(ctx->val.v, 0, spec->size);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct ftrace_arg_spec *spec)
{
	memset(ctx->val.v, 0, spec->size);
}

