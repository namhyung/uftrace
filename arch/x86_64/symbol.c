#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "symbol"
#define PR_DOMAIN DBG_SYMBOL

#include "libmcount/internal.h"
#include "mcount-arch.h"
#include "uftrace.h"
#include "utils/symbol.h"
#include "utils/utils.h"

#define R_OFFSET_POS 2
#define JMP_INSN_SIZE 6
#define PLTGOT_SIZE 8

int arch_load_dynsymtab_noplt(struct uftrace_symtab *dsymtab, struct uftrace_elf_data *elf,
			      unsigned long offset, unsigned long flags)
{
	struct uftrace_elf_iter sec_iter;
	struct uftrace_elf_iter rel_iter;
	struct uftrace_elf_iter sym_iter;
	unsigned grow = SYMTAB_GROW;
	unsigned long reloc_start = 0;
	size_t reloc_entsize = 0;

	memset(dsymtab, 0, sizeof(*dsymtab));

	/* assumes there's only one RELA section (rela.dyn) for no-plt binary */
	elf_for_each_shdr(elf, &sec_iter) {
		if (sec_iter.shdr.sh_type == SHT_RELA) {
			memcpy(&rel_iter, &sec_iter, sizeof(sec_iter));
			pr_dbg2("found RELA section: %s\n",
				elf_get_name(elf, &sec_iter, sec_iter.shdr.sh_name));

			reloc_start = rel_iter.shdr.sh_addr + offset;
			reloc_entsize = rel_iter.shdr.sh_entsize;
		}
		else if (sec_iter.shdr.sh_type == SHT_DYNSYM) {
			memcpy(&sym_iter, &sec_iter, sizeof(sec_iter));
			elf_get_strtab(elf, &sym_iter, sec_iter.shdr.sh_link);
			elf_get_secdata(elf, &sym_iter);
		}
	}

	if (reloc_start == 0)
		return 0;

	elf_for_each_rela(elf, &rel_iter) {
		struct uftrace_symbol *sym;
		int symidx;
		char *name;

		symidx = elf_rel_symbol(&rel_iter.rela);
		if (symidx == 0)
			continue;

		if (elf_rel_type(&rel_iter.rela) != R_X86_64_GLOB_DAT)
			continue;

		elf_get_symbol(elf, &sym_iter, symidx);

		if (elf_symbol_type(&sym_iter.sym) != STT_FUNC &&
		    elf_symbol_type(&sym_iter.sym) != STT_GNU_IFUNC)
			continue;

		if (sym_iter.sym.st_shndx != STN_UNDEF)
			continue;

		if (dsymtab->nr_sym >= dsymtab->nr_alloc) {
			if (dsymtab->nr_alloc >= grow * 4)
				grow *= 2;
			dsymtab->nr_alloc += grow;
			dsymtab->sym = xrealloc(dsymtab->sym, dsymtab->nr_alloc * sizeof(*sym));
		}

		sym = &dsymtab->sym[dsymtab->nr_sym++];

		/* use reloc address as symbol address as it's in the map */
		sym->addr = reloc_start + rel_iter.i * reloc_entsize;
		sym->size = reloc_entsize;
		sym->type = ST_PLT_FUNC;

		name = elf_get_name(elf, &sym_iter, sym_iter.sym.st_name);
		if (flags & SYMTAB_FL_DEMANGLE)
			sym->name = demangle(name);
		else
			sym->name = xstrdup(name);

		pr_dbg3("[%zd] %c %lx + %-5u %s\n", dsymtab->nr_sym, sym->type, sym->addr,
			sym->size, sym->name);
	}

	return dsymtab->nr_sym;
}

void mcount_arch_plthook_setup(struct plthook_data *pd, struct uftrace_elf_data *elf)
{
	struct plthook_arch_context *ctx;
	struct uftrace_elf_iter iter;
	char *secname;

	ctx = xzalloc(sizeof(*ctx));

	elf_for_each_shdr(elf, &iter) {
		secname = elf_get_name(elf, &iter, iter.shdr.sh_name);

		if (strcmp(secname, ".plt.sec") == 0) {
			ctx->has_plt_sec = true;
			break;
		}
	}

	pd->arch = ctx;
}

unsigned long mcount_arch_plthook_addr(struct plthook_data *pd, int idx)
{
	struct plthook_arch_context *ctx = pd->arch;
	struct uftrace_symbol *sym;

	if (ctx->has_plt_sec) {
		unsigned long sym_addr;

		/* symbol has .plt.sec address, so return .plt address */
		sym_addr = pd->plt_addr + (idx + 1) * 16;
		return sym_addr;
	}

	sym = &pd->dsymtab.sym[idx];
	return sym->addr + ARCH_PLTHOOK_ADDR_OFFSET;
}
