#include <stdlib.h>
#include <assert.h>
#include <link.h>
#include <elf.h>

#ifndef EF_ARM_ABI_FLOAT_HARD
# define EF_ARM_ABI_FLOAT_HARD  EF_ARM_VFP_FLOAT
#endif

#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"
#include "utils/filter.h"

#define USE_OFFSET_CACHE  0

static struct rb_root offset_cache = RB_ROOT;

/* whether current machine supports hardfp */
static bool use_hard_float = false;

#ifdef HAVE_ARM_HARDFP
/* need to check hardfp at runtime */
static bool float_abi_checked = false;
#else
/* disable hardfp as it's not supported */
static bool float_abi_checked = true;
#endif

struct offset_entry {
	struct rb_node node;
	unsigned long  addr;
	unsigned long  offset;
};

static struct offset_entry *lookup_cache(struct rb_root *root,
					 unsigned long addr, bool create)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct offset_entry *iter;

	if (!USE_OFFSET_CACHE)
		return NULL;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct offset_entry, node);

		if (iter->addr == addr)
			return iter;

		if (iter->addr > addr)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	if (!create)
		return NULL;

	iter = xmalloc(sizeof(*iter));
	iter->addr = addr;

	rb_link_node(&iter->node, parent, p);
	rb_insert_color(&iter->node, root);
	return iter;
}

#define MAX_ANALYSIS_COUNT  16

static void analyze_mcount_instructions(unsigned short *insn, struct lr_offset *lr)
{
	int ret;
	int count = 0;

	do {
		ret = analyze_mcount_prolog(insn, lr);
		insn += ret;
	}
	while (ret && count++ < MAX_ANALYSIS_COUNT);

	if (count > MAX_ANALYSIS_COUNT) {
		pr_dbg("stopping analysis on a long function prologue\n");
		return;
	}

	pr_dbg2("%s: return address offset = %+d\n", __func__, lr->offset);
}

/* This code is only meaningful on THUMB2 mode: @loc = $sp + 4 */
unsigned long *mcount_arch_parent_location(struct symtabs *symtabs,
					   unsigned long *parent_loc,
					   unsigned long child_ip)
{
	struct sym *sym;
	unsigned short buf[MAX_ANALYSIS_COUNT];
	struct lr_offset lr = {
		.offset = 0,
	};
	struct offset_entry *cache;

	sym = find_symtabs(symtabs, child_ip);
	if (sym == NULL)
		pr_err_ns("cannot find symbol for %lx\n", child_ip);

	// on ARM mode, return as is
	if ((sym->addr & 1) == 0)
		return parent_loc;

	/* if dynamic tracing is enabled */
	if (mcount_find_code(child_ip) != NULL)
		return parent_loc;

	cache = lookup_cache(&offset_cache, sym->addr, false);
	if (cache)
		return parent_loc + cache->offset;

	pr_dbg2("copying instructions of %s\n", sym->name);
	memcpy(buf, (void *)(long)(sym->addr & ~1), sizeof(buf));

	analyze_mcount_instructions(buf, &lr);

	cache = lookup_cache(&offset_cache, sym->addr, true);
	if (cache)
		cache->offset = lr.offset;

	return parent_loc + lr.offset;
}

int check_float_abi_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	unsigned i;

	for (i = 0; i < info->dlpi_phnum; i++) {
		const Elf32_Phdr *phdr = info->dlpi_phdr + i;

		if (phdr->p_type == PT_LOAD) {
			Elf32_Ehdr *ehdr = (void *)info->dlpi_addr + phdr->p_vaddr;
			use_hard_float = ehdr->e_flags & EF_ARM_ABI_FLOAT_HARD;
			break;
		}
	}
	float_abi_checked = true;

	return 1;
}

void check_float_abi(void)
{
	dl_iterate_phdr(check_float_abi_cb, NULL);
}

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
		if (use_hard_float) {
			if (spec->size <= 4)
				reg_idx = spec->idx + UFT_ARM_REG_FLOAT_BASE;
			else
				reg_idx = spec->idx + UFT_ARM_REG_DOUBLE_BASE;
			break;
		}
		/* fall through */
	case ARG_TYPE_INDEX:
		reg_idx = spec->idx; /* for integer arguments */
		if (spec->size == 8 && (reg_idx & 1) == 0)
			reg_idx++;
		break;
	case ARG_TYPE_STACK:
	default:
		return -1;
	}

	switch (reg_idx) {
	case UFT_ARM_REG_R0:
		ctx->val.i = ARG1(regs);
		if (spec->size == 8)
			ctx->val.ll.hi = ARG2(regs);
		break;
	case UFT_ARM_REG_R1:
		ctx->val.i = ARG2(regs);
		break;
	case UFT_ARM_REG_R2:
		ctx->val.i = ARG3(regs);
		if (spec->size == 8)
			ctx->val.ll.hi = ARG4(regs);
		break;
	case UFT_ARM_REG_R3:
		ctx->val.i = ARG4(regs);
		break;

#ifdef HAVE_ARM_HARDFP
	case UFT_ARM_REG_S0:
		asm volatile ("vstr %%s0, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S1:
		asm volatile ("vstr %%s1, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S2:
		asm volatile ("vstr %%s2, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S3:
		asm volatile ("vstr %%s3, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S4:
		asm volatile ("vstr %%s4, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S5:
		asm volatile ("vstr %%s5, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S6:
		asm volatile ("vstr %%s6, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S7:
		asm volatile ("vstr %%s7, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S8:
		asm volatile ("vstr %%s8, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S9:
		asm volatile ("vstr %%s9, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S10:
		asm volatile ("vstr %%s10, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S11:
		asm volatile ("vstr %%s11, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S12:
		asm volatile ("vstr %%s12, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S13:
		asm volatile ("vstr %%s13, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S14:
		asm volatile ("vstr %%s14, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_S15:
		asm volatile ("vstr %%s15, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_D0:
		asm volatile ("vstr %%d0, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_D1:
		asm volatile ("vstr %%d1, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_D2:
		asm volatile ("vstr %%d2, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_D3:
		asm volatile ("vstr %%d3, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_D4:
		asm volatile ("vstr %%d4, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_D5:
		asm volatile ("vstr %%d5, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_D6:
		asm volatile ("vstr %%d6, %0\n" : "=m" (ctx->val.v));
		break;
	case UFT_ARM_REG_D7:
		asm volatile ("vstr %%d7, %0\n" : "=m" (ctx->val.v));
		break;
#endif /* HAVE_ARM_HARDFP */

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
		if (use_hard_float) {
			if (spec->size <= 4)
				offset = spec->idx - ARCH_MAX_FLOAT_REGS;
			else
				offset = (spec->idx - ARCH_MAX_DOUBLE_REGS) * 2 - 1;
			break;
		}
		/* fall through */
	case ARG_TYPE_INDEX:
		offset = spec->idx - ARCH_MAX_REG_ARGS;
		if (spec->size == 8 && (offset & 1) == 0)
			offset++;
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
	if (!float_abi_checked)
		check_float_abi();

	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct uftrace_arg_spec *spec)
{
	if (!float_abi_checked)
		check_float_abi();

	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

	/* type of return value cannot be FLOAT, so check format instead */
#ifdef HAVE_ARM_HARDFP
	if (spec->fmt == ARG_FMT_FLOAT && use_hard_float) {
		/* d0 register (64 bit) was saved below the r0 */
		memcpy(ctx->val.v, ctx->retval - 2, spec->size);
	}
	else
#endif /* HAVE_ARM_HARDFP */
		memcpy(ctx->val.v, ctx->retval, spec->size);
}

unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx)
{
	return pd->plt_addr;
}
