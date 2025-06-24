#include <stdlib.h>

#include "libmcount/internal.h"
#include "utils/filter.h"
#include "utils/utils.h"

/* These functions are implemented in assembly */
extern void _mcount(void);
extern void plt_hooker(void);
extern void __fentry__(void);
extern void __dentry__(void);
extern void mcount_return(void);
extern void plthook_return(void);
extern void dynamic_return(void);

/* These functions are defined in the current file */
static unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx);

/* These functions are defined in mcount-dynamic.c */
extern int mcount_setup_trampoline(struct mcount_dynamic_info *mdi);
extern void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi);
extern int mcount_patch_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			     struct mcount_disasm_engine *disasm, unsigned min_size);
extern int mcount_unpatch_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			       struct mcount_disasm_engine *disasm);
extern void mcount_arch_find_module(struct mcount_dynamic_info *mdi, struct uftrace_symtab *symtab);
extern void mcount_arch_dynamic_recover(struct mcount_dynamic_info *mdi,
					struct mcount_disasm_engine *disasm);

/* These functions are defined in mcount-insn.c */
void mcount_disasm_init(struct mcount_disasm_engine *disasm);
void mcount_disasm_finish(struct mcount_disasm_engine *disasm);

const struct mcount_arch_ops mcount_arch_ops = {
	.entry = {
		[UFT_ARCH_OPS_MCOUNT] = (unsigned long)_mcount,
		[UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plt_hooker,
		[UFT_ARCH_OPS_FENTRY] = (unsigned long)__fentry__,
		[UFT_ARCH_OPS_DYNAMIC] = (unsigned long)__dentry__,
	},
	.exit = {
		[UFT_ARCH_OPS_MCOUNT] = (unsigned long)mcount_return,
		[UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plthook_return,
		[UFT_ARCH_OPS_FENTRY] = (unsigned long)mcount_return,
		[UFT_ARCH_OPS_DYNAMIC] = (unsigned long)dynamic_return,
	},
	.plthook_addr = mcount_arch_plthook_addr,
#ifdef HAVE_LIBCAPSTONE
	.disasm_init = mcount_disasm_init,
	.disasm_finish = mcount_disasm_finish,
#endif
	.setup_trampoline = mcount_setup_trampoline,
	.cleanup_trampoline = mcount_cleanup_trampoline,
	.patch_func = mcount_patch_func,
	.unpatch_func = mcount_unpatch_func,
	.find_module = mcount_arch_find_module,
	.dynamic_recover = mcount_arch_dynamic_recover,
};

/* FIXME: x0 is overwritten before calling _mcount() */
static int mcount_get_register_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	struct mcount_regs *regs = ctx->regs;
	int reg_idx;

	switch (spec->type) {
	case ARG_TYPE_REG:
		reg_idx = spec->reg_idx;
		break;
	case ARG_TYPE_FLOAT:
		if (spec->size <= 4)
			reg_idx = spec->idx + UFT_AARCH64_REG_FLOAT_BASE;
		else
			reg_idx = spec->idx + UFT_AARCH64_REG_DOUBLE_BASE;
		break;
	case ARG_TYPE_INDEX:
		reg_idx = spec->idx; /* for integer arguments */
		break;
	case ARG_TYPE_STACK:
	default:
		return -1;
	}

	switch (reg_idx) {
	case UFT_AARCH64_REG_X0:
		ctx->val.i = ARG1(regs);
		break;
	case UFT_AARCH64_REG_X1:
		ctx->val.i = ARG2(regs);
		break;
	case UFT_AARCH64_REG_X2:
		ctx->val.i = ARG3(regs);
		break;
	case UFT_AARCH64_REG_X3:
		ctx->val.i = ARG4(regs);
		break;
	case UFT_AARCH64_REG_X4:
		ctx->val.i = ARG5(regs);
		break;
	case UFT_AARCH64_REG_X5:
		ctx->val.i = ARG6(regs);
		break;
	case UFT_AARCH64_REG_X6:
		ctx->val.i = ARG7(regs);
		break;
	case UFT_AARCH64_REG_X7:
		ctx->val.i = ARG8(regs);
		break;
	case UFT_AARCH64_REG_S0:
		asm volatile("str s0, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_S1:
		asm volatile("str s1, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_S2:
		asm volatile("str s2, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_S3:
		asm volatile("str s3, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_S4:
		asm volatile("str s4, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_S5:
		asm volatile("str s5, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_S6:
		asm volatile("str s6, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_S7:
		asm volatile("str s7, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_D0:
		asm volatile("str d0, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_D1:
		asm volatile("str d1, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_D2:
		asm volatile("str d2, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_D3:
		asm volatile("str d3, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_D4:
		asm volatile("str d4, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_D5:
		asm volatile("str d5, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_D6:
		asm volatile("str d6, %0\n" : "=m"(ctx->val.v));
		break;
	case UFT_AARCH64_REG_D7:
		asm volatile("str d7, %0\n" : "=m"(ctx->val.v));
		break;
	default:
		return -1;
	}

	return 0;
}

static void mcount_get_stack_arg(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	int offset = 1;
	unsigned long *addr = ctx->stack_base;

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

	if (offset < 1 || offset > 100) {
		pr_dbg("invalid stack offset: %d\n", offset);
		mcount_memset4(ctx->val.v, 0, sizeof(ctx->val));
		return;
	}

	addr += offset;

	if (check_mem_region(ctx, (unsigned long)addr))
		mcount_memcpy4(ctx->val.v, addr, spec->size);
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

	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx, struct uftrace_arg_spec *spec)
{
	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

	if (spec->fmt == ARG_FMT_STRUCT)
		mcount_memcpy4(ctx->val.v, ctx->retval, sizeof(long));
	/* type of return value cannot be FLOAT, so check format instead */
	else if (spec->fmt == ARG_FMT_FLOAT) {
		long *float_retval = ctx->retval - 2;

		if (spec->size <= 4) {
			asm volatile("ldr s0, %1\n"
				     "str s0, %0\n"
				     : "=m"(ctx->val.v)
				     : "m"(*float_retval));
		}
		else {
			asm volatile("ldr d0, %1\n"
				     "str d0, %0\n"
				     : "=m"(ctx->val.v)
				     : "m"(*float_retval));
		}
	}
	else
		mcount_memcpy4(ctx->val.v, ctx->retval, spec->size);
}

static unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx)
{
	struct uftrace_symbol *sym;

	sym = &pd->dsymtab.sym[0];
	return sym->addr - ARCH_PLT0_SIZE;
}

void mcount_save_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile("str d0, %0\n" : "=m"(ctx->d[0]));
	asm volatile("str d1, %0\n" : "=m"(ctx->d[1]));
	asm volatile("str d2, %0\n" : "=m"(ctx->d[2]));
	asm volatile("str d3, %0\n" : "=m"(ctx->d[3]));
	asm volatile("str d4, %0\n" : "=m"(ctx->d[4]));
	asm volatile("str d5, %0\n" : "=m"(ctx->d[5]));
	asm volatile("str d6, %0\n" : "=m"(ctx->d[6]));
	asm volatile("str d7, %0\n" : "=m"(ctx->d[7]));
}

void mcount_restore_arch_context(struct mcount_arch_context *ctx)
{
	asm volatile("ldr d0, %0\n" ::"m"(ctx->d[0]));
	asm volatile("ldr d1, %0\n" ::"m"(ctx->d[1]));
	asm volatile("ldr d2, %0\n" ::"m"(ctx->d[2]));
	asm volatile("ldr d3, %0\n" ::"m"(ctx->d[3]));
	asm volatile("ldr d4, %0\n" ::"m"(ctx->d[4]));
	asm volatile("ldr d5, %0\n" ::"m"(ctx->d[5]));
	asm volatile("ldr d6, %0\n" ::"m"(ctx->d[6]));
	asm volatile("ldr d7, %0\n" ::"m"(ctx->d[7]));
}
