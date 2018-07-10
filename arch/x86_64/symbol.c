#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "symbol"
#define PR_DOMAIN  DBG_SYMBOL

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define R_OFFSET_POS  2
#define JMP_INSN_SIZE 6
#define PLTGOT_SIZE   8

int arch_load_dynsymtab_bindnow(struct symtab *dsymtab,
				struct uftrace_elf_data *elf,
				unsigned long offset, unsigned long flags)
{
	unsigned grow = SYMTAB_GROW;
	unsigned long plt_addr = 0;
	unsigned long plt_size;
	int rel_type = SHT_NULL;
	unsigned long got_addr;
	unsigned long pos;
	int i, ret = -1;
	bool found_dynsym = false;
	struct uftrace_elf_iter sec_iter;
	struct uftrace_elf_iter dyn_iter;
	struct uftrace_elf_iter rel_iter;
	struct uftrace_elf_iter plt_iter;

	pr_dbg2("load dynamic symbols for bind-now\n");

	elf_for_each_shdr(elf, &sec_iter) {
		char *shstr;

		shstr = elf_get_name(elf, &sec_iter, sec_iter.shdr.sh_name);

		if (strcmp(shstr, ".dynsym") == 0) {
			memcpy(&dyn_iter, &sec_iter, sizeof(dyn_iter));
			elf_get_strtab(elf, &dyn_iter, sec_iter.shdr.sh_link);
			elf_get_secdata(elf, &dyn_iter);
			found_dynsym = true;
		}
		else if (strcmp(shstr, ".rela.dyn") == 0) {
			memcpy(&rel_iter, &sec_iter, sizeof(rel_iter));
			rel_type = SHT_RELA;
		}
		else if (strcmp(shstr, ".plt.got") == 0) {
			memcpy(&plt_iter, &sec_iter, sizeof(rel_iter));
			plt_addr = plt_iter.shdr.sh_addr + offset;
			plt_size = plt_iter.shdr.sh_size;
			elf_get_secdata(elf, &plt_iter);
		}
	}

	if (!found_dynsym || plt_addr == 0) {
		pr_dbg("cannot find dynamic symbols.. skipping\n");
		goto out;
	}

	if (rel_type != SHT_RELA) {
		pr_dbg("cannot find relocation info for PLT\n");
		goto out;
	}

	for (i = pos = 0; pos < plt_size; i++, pos += PLTGOT_SIZE) {
		unsigned got_offset;

		elf_read_secdata(elf, &plt_iter, pos + R_OFFSET_POS,
				 &got_offset, sizeof(got_offset));

		got_addr = plt_addr + pos + JMP_INSN_SIZE + got_offset;

		pr_dbg3("find rel for PLT%d with r_offset: %#lx\n", i+1, got_addr);

		elf_for_each_rela(elf, &rel_iter) {
			struct sym *sym;
			int symidx;
			char *name;

			if (rel_iter.rela.r_offset + offset != got_addr)
				continue;

			symidx = elf_rel_symbol(&rel_iter.rela);
			elf_get_symbol(elf, &dyn_iter, symidx);
			name = elf_get_name(elf, &dyn_iter, dyn_iter.sym.st_name);

			if (dsymtab->nr_sym >= dsymtab->nr_alloc) {
				if (dsymtab->nr_alloc >= grow * 4)
					grow *= 2;
				dsymtab->nr_alloc += grow;
				dsymtab->sym = xrealloc(dsymtab->sym,
							dsymtab->nr_alloc * sizeof(*sym));
			}

			sym = &dsymtab->sym[dsymtab->nr_sym++];

			sym->addr = plt_addr + (i * PLTGOT_SIZE);
			sym->size = PLTGOT_SIZE;
			sym->type = ST_PLT;

			if (flags & SYMTAB_FL_DEMANGLE)
				sym->name = demangle(name);
			else
				sym->name = xstrdup(name);

			pr_dbg3("[%zd] %c %lx + %-5u %s\n", dsymtab->nr_sym,
				sym->type, sym->addr, sym->size, sym->name);
			break;
		}
	}
	pr_dbg2("loaded %u symbols from .plt.got section\n", dsymtab->nr_sym);
	ret = 0;

out:
	return ret;
}
