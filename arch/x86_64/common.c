#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "symbol"
#define PR_DOMAIN DBG_SYMBOL

#include "uftrace.h"
#include "utils/arch.h"
#include "utils/symbol.h"
#include "utils/utils.h"

/* These functions are defined in the current file. */
static int arch_load_dynsymtab_noplt(struct uftrace_symtab *dsymtab, struct uftrace_elf_data *elf,
				     unsigned long offset, unsigned long flags);

/* This is a common arch-ops that will be used by both uftrace and libmcount. */
const struct uftrace_arch_ops uftrace_arch_ops = {
	.load_dynsymtab = arch_load_dynsymtab_noplt,
};

static int arch_load_dynsymtab_noplt(struct uftrace_symtab *dsymtab, struct uftrace_elf_data *elf,
				     unsigned long offset, unsigned long flags)
{
	struct uftrace_elf_iter sec_iter = {};
	struct uftrace_elf_iter rel_iter;
	struct uftrace_elf_iter sym_iter;
	unsigned grow = SYMTAB_GROW;
	unsigned long reloc_start = 0;
	size_t reloc_entsize = 0;

	memset(dsymtab, 0, sizeof(*dsymtab));

	elf_for_each_shdr(elf, &sec_iter) {
		if (strcmp(elf_get_name(elf, &sec_iter, sec_iter.shdr.sh_name), ".rela.dyn") == 0) {
			memcpy(&rel_iter, &sec_iter, sizeof(sec_iter));
			pr_dbg2("found rela.dyn section with %ld entry.\n",
				sec_iter.shdr.sh_entsize);

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
	sort_dynsymtab(dsymtab);

	return dsymtab->nr_sym;
}
