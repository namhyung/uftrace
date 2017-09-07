#include <stdlib.h>
#include <assert.h>
#include <gelf.h>

#include "mcount-arch.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"
#include "utils/filter.h"

int mcount_get_register_arg(struct mcount_arg_context *ctx,
			    struct ftrace_arg_spec *spec)
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
			  struct ftrace_arg_spec *spec)
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
			 struct ftrace_arg_spec *spec)
{
	/* don't support long double, treat it as double */
	if (unlikely(spec->size == 10))
		spec->size = 8;

	if (mcount_get_register_arg(ctx, spec) < 0)
		mcount_get_stack_arg(ctx, spec);
}

void mcount_arch_get_retval(struct mcount_arg_context *ctx,
			    struct ftrace_arg_spec *spec)
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

int mcount_arch_undo_bindnow(Elf *elf, struct plthook_data *pd)
{
	size_t shstr_idx, dynstr_idx = 0;
	Elf_Scn *sec, *dynsym_sec, *relplt_sec;
	Elf_Data *dynsym_data, *relplt_data;
	unsigned long pltgot_addr = (unsigned long)pd->pltgot_ptr;
	unsigned long plt_addr = 0;
	unsigned idx, nr_rels = 0;
	int count = 0;
	const char *skip_syms[] = {
		"mcount", "_mcount",
		"__cyg_profile_func_enter", "__cyg_profile_func_exit",
		"__cxa_finalize",  /* XXX: it caused segfault */
	};

	pr_dbg2("restore PLTGOT for bind-now\n");

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		return -1;

	sec = dynsym_sec = relplt_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *shstr;
		GElf_Shdr shdr;

		if (gelf_getshdr(sec, &shdr) == NULL)
			return -1;

		shstr = elf_strptr(elf, shstr_idx, shdr.sh_name);

		if (strcmp(shstr, ".dynsym") == 0) {
			dynsym_sec = sec;
			dynstr_idx = shdr.sh_link;
		}
		else if (strcmp(shstr, ".rela.plt") == 0) {
			relplt_sec = sec;
			nr_rels = shdr.sh_size / shdr.sh_entsize;
		}
		else if (strcmp(shstr, ".plt") == 0) {
			plt_addr = shdr.sh_addr + pd->base_addr;
		}
	}

	if (plt_addr == 0) {
		pr_dbg("cannot find PLT section\n");
		return -1;
	}

	relplt_data = elf_getdata(relplt_sec, NULL);
	dynsym_data = elf_getdata(dynsym_sec, NULL);
	if (relplt_data == NULL || dynsym_data == NULL)
		return -1;

	for (idx = 0; idx < nr_rels; idx++) {
		struct sym *sym;
		GElf_Sym esym;
		unsigned sym_idx;
		int got_idx;
		char *name;
		GElf_Rela rel;

		if (gelf_getrela(relplt_data, idx, &rel) == NULL)
			return -1;

		if (GELF_R_TYPE(rel.r_info) != R_AARCH64_JUMP_SLOT) {
			pr_dbg("invalid reloc type: %u\n",
			       GELF_R_TYPE(rel.r_info));
			return -1;
		}

		sym_idx = GELF_R_SYM(rel.r_info);

		gelf_getsym(dynsym_data, sym_idx, &esym);
		name = elf_strptr(elf, dynstr_idx, esym.st_name);

		sym = &pd->dsymtab.sym[idx];
		if (strcmp(name, sym->name)) {
			pr_dbg("symbol name mismatch (%s vs %s)\n",
			       name, sym->name);
			return -1;
		}

		for (sym_idx = 0; sym_idx < ARRAY_SIZE(skip_syms); sym_idx++) {
			if (!strcmp(sym->name, skip_syms[sym_idx]))
				break;
		}
		if (sym_idx != ARRAY_SIZE(skip_syms))
			continue;

		got_idx = (rel.r_offset + pd->base_addr - pltgot_addr) >> 3;
		setup_pltgot(pd, got_idx, idx, (void *)plt_addr);
		count++;

		pr_dbg3("restore GOT[%u] (%s) r_offset = %lx\n",
			got_idx, name, (unsigned long)rel.r_offset);
	}
	pr_dbg2("restored %d entries\n", count);

	return 0;
}

unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx)
{
	struct sym *sym;

	sym = &pd->dsymtab.sym[0];
	return sym->addr - ARCH_PLT0_SIZE;
}
