#include <string.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "mcount"
#define PR_DOMAIN DBG_MCOUNT

#include "libmcount/internal.h"
#include "utils/arch.h"
#include "utils/filter.h"

/* These functions are implemented in assembly */
extern void mcount(void);
extern void plt_hooker(void);
extern void __fentry__(void);
extern void __dentry__(void);
extern void __xray_entry(void);
extern void mcount_return(void);
extern void plthook_return(void);
extern void dynamic_return(void);
extern void __xray_exit(void);

/* These functions are defined in mcount-plthook.c */
extern void mcount_arch_plthook_setup(struct plthook_data *pd, struct uftrace_elf_data *elf);
extern unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx);
extern struct plthook_data *mcount_arch_hook_no_plt(struct uftrace_elf_data *, const char *,
						    unsigned long);

/* These functions are defined in mcount-event.c */
extern int mcount_arch_enable_event(struct mcount_event_info *mei);

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
extern int mcount_arch_branch_table_size(struct mcount_disasm_info *info);
extern void mcount_arch_patch_branch(struct mcount_disasm_info *info,
				     struct mcount_orig_insn *orig);

/* These functions are defined in mcount-insn.c */
extern void mcount_disasm_init(struct mcount_disasm_engine *disasm);
extern void mcount_disasm_finish(struct mcount_disasm_engine *disasm);

const struct mcount_arch_ops mcount_arch_ops = {
	.entry = {
		[UFT_ARCH_OPS_MCOUNT] = (unsigned long)mcount,
		[UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plt_hooker,
		[UFT_ARCH_OPS_FENTRY] = (unsigned long)__fentry__,
		[UFT_ARCH_OPS_DYNAMIC] = (unsigned long)__dentry__,
		[UFT_ARCH_OPS_XRAY] = (unsigned long)__xray_entry,
	},
	.exit = {
		[UFT_ARCH_OPS_MCOUNT] = (unsigned long)mcount_return,
		[UFT_ARCH_OPS_PLTHOOK] = (unsigned long)plthook_return,
		[UFT_ARCH_OPS_FENTRY] = (unsigned long)mcount_return,
		[UFT_ARCH_OPS_DYNAMIC] = (unsigned long)dynamic_return,
		[UFT_ARCH_OPS_XRAY] = (unsigned long)__xray_exit,
	},
	.plthook_setup = mcount_arch_plthook_setup,
	.plthook_addr = mcount_arch_plthook_addr,
	.hook_no_plt = mcount_arch_hook_no_plt,
	.enable_event = mcount_arch_enable_event,
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
	.branch_table_size = mcount_arch_branch_table_size,
	.patch_branch = mcount_arch_patch_branch,
};

#define COPY_XMM(xmm)                                                                              \
	do {                                                                                       \
		if (spec->size == 8)                                                               \
			asm volatile("movsd %%" xmm ", %0\n" : "=m"(ctx->val.v));                  \
		else                                                                               \
			asm volatile("movss %%" xmm ", %0\n" : "=m"(ctx->val.v));                  \
	} while (0)

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
		reg_idx = spec->idx + UFT_X86_64_REG_FLOAT_BASE;
		break;
	case ARG_TYPE_STACK:
	default:
		return -1;
	}

	ctx->val.i = 0;

	switch (reg_idx) {
	case UFT_X86_64_REG_RDI:
		ctx->val.i = ARG1(regs);
		break;
	case UFT_X86_64_REG_RSI:
		ctx->val.i = ARG2(regs);
		break;
	case UFT_X86_64_REG_RDX:
		ctx->val.i = ARG3(regs);
		break;
	case UFT_X86_64_REG_RCX:
		ctx->val.i = ARG4(regs);
		break;
	case UFT_X86_64_REG_R8:
		ctx->val.i = ARG5(regs);
		break;
	case UFT_X86_64_REG_R9:
		ctx->val.i = ARG6(regs);
		break;
	case UFT_X86_64_REG_XMM0:
		COPY_XMM("xmm0");
		break;
	case UFT_X86_64_REG_XMM1:
		COPY_XMM("xmm1");
		break;
	case UFT_X86_64_REG_XMM2:
		COPY_XMM("xmm2");
		break;
	case UFT_X86_64_REG_XMM3:
		COPY_XMM("xmm3");
		break;
	case UFT_X86_64_REG_XMM4:
		COPY_XMM("xmm4");
		break;
	case UFT_X86_64_REG_XMM5:
		COPY_XMM("xmm5");
		break;
	case UFT_X86_64_REG_XMM6:
		COPY_XMM("xmm6");
		break;
	case UFT_X86_64_REG_XMM7:
		COPY_XMM("xmm7");
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
		offset = (spec->idx - ARCH_MAX_FLOAT_ARGS) * 2 - 1;
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
	else if (spec->fmt != ARG_FMT_FLOAT)
		mcount_memcpy1(ctx->val.v, ctx->retval, spec->size);
	else if (spec->size == 10) /* for long double type */
		asm volatile("fstpt %0\n\tfldt %0" : "=m"(ctx->val.v));
	else
		asm volatile("movsd %%xmm0, %0\n" : "=m"(ctx->val.v));
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
