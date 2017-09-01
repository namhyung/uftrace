#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <gelf.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "symbol"
#define PR_DOMAIN  DBG_SYMBOL

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define R_OFFSET_POS  2
#define JMP_INSN_SIZE 6
#define PLTGOT_SIZE   8

int arch_load_dynsymtab_bindnow(Elf *elf, struct symtab *dsymtab,
				unsigned long offset, unsigned long flags)
{
	unsigned grow = SYMTAB_GROW;
	Elf_Scn *dynsym_sec, *relplt_sec, *pltgot_sec, *sec;
	Elf_Data *dynsym_data, *relplt_data, *pltgot_data;
	GElf_Addr plt_addr = 0;
	int rel_type = SHT_NULL;
	size_t shstr_idx, dynstr_idx = 0;
	unsigned char *pltgot;
	unsigned char *pltend;
	unsigned long got_addr;
	int i, ret = -1;
	size_t idx, nr_rels = 0;

	pr_dbg("load dynamic symbols for bind-now\n");

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto elf_error;

	sec = dynsym_sec = relplt_sec = pltgot_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *shstr;
		GElf_Shdr shdr;

		if (gelf_getshdr(sec, &shdr) == NULL)
			goto elf_error;

		shstr = elf_strptr(elf, shstr_idx, shdr.sh_name);

		if (strcmp(shstr, ".dynsym") == 0) {
			dynsym_sec = sec;
			dynstr_idx = shdr.sh_link;
		}
		else if (strcmp(shstr, ".rela.dyn") == 0) {
			if (rel_type != SHT_NULL)
				continue;
			relplt_sec = sec;
			nr_rels = shdr.sh_size / shdr.sh_entsize;
			rel_type = SHT_RELA;
		}
		else if (strcmp(shstr, ".rel.dyn") == 0) {
			if (rel_type != SHT_NULL)
				continue;
			relplt_sec = sec;
			nr_rels = shdr.sh_size / shdr.sh_entsize;
			rel_type = SHT_REL;
		}
		else if (strcmp(shstr, ".plt.got") == 0) {
			plt_addr = shdr.sh_addr;
			pltgot_sec = sec;
		}
	}

	if (dynsym_sec == NULL || plt_addr == 0) {
		pr_dbg("cannot find dynamic symbols.. skipping\n");
		goto out;
	}

	if (rel_type != SHT_RELA && rel_type != SHT_REL) {
		pr_dbg("cannot find relocation info for PLT\n");
		goto out;
	}

	dynsym_data = elf_getdata(dynsym_sec, NULL);
	if (dynsym_data == NULL)
		goto elf_error;

	relplt_data = elf_getdata(relplt_sec, NULL);
	if (relplt_data == NULL)
		goto elf_error;

	pltgot_data = elf_getdata(pltgot_sec, NULL);
	if (pltgot_data == NULL)
		goto elf_error;

	pltgot = pltgot_data->d_buf;
	pltend = pltgot_data->d_buf + pltgot_data->d_size;

	for (i = 0; pltgot < pltend; i++, pltgot += PLTGOT_SIZE) {
		unsigned got_offset;

		memcpy(&got_offset, &pltgot[R_OFFSET_POS], sizeof(got_offset));
		got_addr = plt_addr + (i * PLTGOT_SIZE) + JMP_INSN_SIZE + got_offset;

		pr_dbg3("find rel for PLT%d with r_offset: %#lx\n", i, got_addr);

		for (idx = 0; idx < nr_rels; idx++) {
			GElf_Sym esym;
			struct sym *sym;
			int symidx;
			char *name;

			if (rel_type == SHT_RELA) {
				GElf_Rela rela;

				if (gelf_getrela(relplt_data, idx, &rela) == NULL)
					goto elf_error;

				if (rela.r_offset != got_addr)
					continue;

				symidx = GELF_R_SYM(rela.r_info);
			}
			else {
				GElf_Rel rel;

				if (gelf_getrel(relplt_data, idx, &rel) == NULL)
					goto elf_error;

				if (rel.r_offset != got_addr)
					continue;

				symidx = GELF_R_SYM(rel.r_info);
			}

			gelf_getsym(dynsym_data, symidx, &esym);
			name = elf_strptr(elf, dynstr_idx, esym.st_name);

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

			if (flags & SYMTAB_FL_ADJ_OFFSET)
				sym->addr += offset;

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

elf_error:
	pr_dbg("ELF error during load dynsymtab: %s\n",
	       elf_errmsg(elf_errno()));
	return -1;
}
