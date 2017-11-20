/*
 * symbol management routines for uftrace
 *
 * Copyright (C) 2014-2017, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <gelf.h>
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "symbol"
#define PR_DOMAIN  DBG_SYMBOL

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"

#ifndef  EM_AARCH64
# define EM_AARCH64  183
#endif

static struct symtabs ksymtabs;

static int addrsort(const void *a, const void *b)
{
	const struct sym *syma = a;
	const struct sym *symb = b;

	if (syma->addr > symb->addr)
		return 1;
	if (syma->addr < symb->addr)
		return -1;
	return 0;
}

static int addrfind(const void *a, const void *b)
{
	uint64_t addr = *(uint64_t *) a;
	const struct sym *sym = b;

	if (sym->addr <= addr && addr < sym->addr + sym->size)
		return 0;

	if (sym->addr > addr)
		return -1;
	return 1;
}

static int namesort(const void *a, const void *b)
{
	const struct sym *syma = *(const struct sym **)a;
	const struct sym *symb = *(const struct sym **)b;

	return strcmp(syma->name, symb->name);
}

static int namefind(const void *a, const void *b)
{
	const char *name = a;
	const struct sym *sym = *(const struct sym **)b;

	return strcmp(name, sym->name);
}

bool check_libpthread(const char *filename)
{
	int fd;
	Elf *elf;
	bool ret = false;
	size_t i, nr_dyn = 0;
	int shstr_idx;
	Elf_Scn *dyn_sec, *sec;
	Elf_Data *dyn_data;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg("error during open symbol file: %s: %m\n", filename);
		return -1;
	}

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto elf_error;

	sec = dyn_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		GElf_Shdr shdr;

		if (gelf_getshdr(sec, &shdr) == NULL)
			goto elf_error;

		if (shdr.sh_type == SHT_DYNAMIC) {
			dyn_sec = sec;
			shstr_idx = shdr.sh_link;
			nr_dyn = shdr.sh_size / shdr.sh_entsize;
			break;
		}
	}

	if (dyn_sec == NULL)
		goto out;

	dyn_data = elf_getdata(dyn_sec, NULL);
	if (dyn_data == NULL)
		goto elf_error;

	for (i = 0; i < nr_dyn; i++) {
		GElf_Dyn dyn;

		if (gelf_getdyn(dyn_data, i, &dyn) == NULL)
			goto elf_error;

		if (dyn.d_tag == DT_NEEDED) {
			char *soname = elf_strptr(elf, shstr_idx, dyn.d_un.d_ptr);
			if (!strcmp(soname, "libpthread.so.0")) {
				ret = true;
				break;
			}
		}
	}

out:
	elf_end(elf);
	close(fd);
	return ret;

elf_error:
	pr_dbg("ELF error during symbol loading: %s\n",
	       elf_errmsg(elf_errno()));
	goto out;
}

int check_static_binary(const char *filename)
{
	int fd;
	Elf *elf;
	GElf_Ehdr ehdr;
	int ret = -1;
	size_t i;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg("error during file open: %s: %m\n", filename);
		return -1;
	}

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto elf_error;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto elf_error;

	for (i = 0; i < ehdr.e_phnum; i++) {
		GElf_Phdr phdr;

		if (gelf_getphdr(elf, i, &phdr) == NULL)
			goto elf_error;

		if (phdr.p_type == PT_DYNAMIC) {
			ret = 0;
			break;
		}
	}

	if (ret == -1)
		ret = 1;  /* static binary */

out:
	elf_end(elf);
	close(fd);
	return ret;

elf_error:
	pr_dbg("ELF error when reading program headers: %s\n",
	       elf_errmsg(elf_errno()));
	goto out;
}

static void __unload_symtab(struct symtab *symtab)
{
	size_t i;

	for (i = 0; i < symtab->nr_sym; i++) {
		struct sym *sym = symtab->sym + i;
		free(sym->name);
	}

	free(symtab->sym_names);
	free(symtab->sym);

	symtab->nr_sym = 0;
	symtab->sym = NULL;
	symtab->sym_names = NULL;
}

void unload_symtabs(struct symtabs *symtabs)
{
	pr_dbg2("unload symbol tables\n");
	__unload_symtab(&symtabs->symtab);
	__unload_symtab(&symtabs->dsymtab);

	symtabs->loaded = false;
}

static int load_symtab(struct symtab *symtab, const char *filename,
		       unsigned long offset, unsigned long flags)
{
	int fd;
	Elf *elf;
	int ret = -1;
	unsigned grow = SYMTAB_GROW;
	size_t i, nr_sym = 0, nr_dynsym = 0;
	Elf_Scn *sym_sec, *dynsym_sec, *sec;
	Elf_Data *sym_data;
	size_t shstr_idx, symstr_idx = 0, dynsymstr_idx = 0;
	unsigned long prev_sym_value = -1;
	int dup_syms = 0;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg("error during open symbol file: %s: %m\n", filename);
		return -1;
	}

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto elf_error;

	if (flags & SYMTAB_FL_ADJ_OFFSET) {
		GElf_Ehdr ehdr;
		GElf_Phdr phdr;

		if (gelf_getehdr(elf, &ehdr) == NULL)
			goto elf_error;

		for (i = 0; i < ehdr.e_phnum; i++) {
			if (!gelf_getphdr(elf, i, &phdr))
				goto elf_error;

			if (phdr.p_type == PT_LOAD) {
				offset -= phdr.p_vaddr;
				break;
			}
		}
	}

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto elf_error;

	sec = sym_sec = dynsym_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *shstr;
		GElf_Shdr shdr;

		if (gelf_getshdr(sec, &shdr) == NULL)
			goto elf_error;

		shstr = elf_strptr(elf, shstr_idx, shdr.sh_name);

		if (strcmp(shstr, ".symtab") == 0) {
			sym_sec = sec;
			nr_sym = shdr.sh_size / shdr.sh_entsize;
			symstr_idx = shdr.sh_link;
			break;
		}

		if (strcmp(shstr, ".dynsym") == 0) {
			dynsym_sec = sec;
			nr_dynsym = shdr.sh_size / shdr.sh_entsize;
			dynsymstr_idx = shdr.sh_link;
		}
	}

	if (sym_sec == NULL) {
		/*
		 * fallback to dynamic symbol table when there's no symbol table
		 * (e.g. stripped binary built with -rdynamic option)
		 */
		sym_sec = dynsym_sec;
		nr_sym = nr_dynsym;
		symstr_idx = dynsymstr_idx;
		pr_dbg2("using dynsym instead\n");
	}

	if (sym_sec == NULL) {
		pr_dbg("no symbol table is found\n");
		goto out;
	}

	sym_data = elf_getdata(sym_sec, NULL);
	if (sym_data == NULL)
		goto elf_error;

	pr_dbg2("loading symbols from %s (offset: %#lx)\n", filename, offset);
	for (i = 0; i < nr_sym; i++) {
		GElf_Sym elf_sym;
		struct sym *sym;
		char *name;

		if (gelf_getsym(sym_data, i, &elf_sym) == NULL)
			goto elf_error;

		if (elf_sym.st_shndx == STN_UNDEF)
			continue;

		if (elf_sym.st_size == 0)
			continue;

		if (GELF_ST_TYPE(elf_sym.st_info) != STT_FUNC)
			continue;

		/* skip aliases */
		if (prev_sym_value == elf_sym.st_value)
			continue;
		prev_sym_value = elf_sym.st_value;

		if (symtab->nr_sym >= symtab->nr_alloc) {
			if (symtab->nr_alloc >= grow * 4)
				grow *= 2;
			symtab->nr_alloc += grow;
			symtab->sym = xrealloc(symtab->sym,
					       symtab->nr_alloc * sizeof(*sym));
		}

		sym = &symtab->sym[symtab->nr_sym++];

		sym->addr = elf_sym.st_value + offset;
		sym->size = elf_sym.st_size;

		switch (GELF_ST_BIND(elf_sym.st_info)) {
		case STB_LOCAL:
			sym->type = ST_LOCAL;
			break;
		case STB_GLOBAL:
			sym->type = ST_GLOBAL;
			break;
		case STB_WEAK:
			sym->type = ST_WEAK;
			break;
		default:
			sym->type = ST_UNKNOWN;
			break;
		}

		name = elf_strptr(elf, symstr_idx, elf_sym.st_name);

		if (flags & SYMTAB_FL_DEMANGLE)
			sym->name = demangle(name);
		else
			sym->name = xstrdup(name);

		pr_dbg3("[%zd] %c %"PRIx64" + %-5u %s\n", symtab->nr_sym,
			sym->type, sym->addr, sym->size, sym->name);
	}
	pr_dbg2("loaded %zd symbols\n", symtab->nr_sym);

	if (symtab->nr_sym == 0)
		goto out;

	qsort(symtab->sym, symtab->nr_sym, sizeof(*symtab->sym), addrsort);

	/* remove duplicated (overlapped?) symbols */
	for (i = 0; i < symtab->nr_sym - 1; i++) {
		struct sym *curr = &symtab->sym[i];
		struct sym *next = &symtab->sym[i + 1];
		int count = 0;

		while (curr->addr == next->addr &&
		       next < &symtab->sym[symtab->nr_sym]) {
			count++;
			next++;
		}

		if (count) {
			struct sym *tmp = curr;

			while (tmp < next - 1) {
				free(tmp->name);
				tmp++;
			}

			memmove(curr, next - 1,
				(symtab->nr_sym - i - count) * sizeof(*next));

			symtab->nr_sym -= count;
			dup_syms += count;
		}
	}

	if (dup_syms)
		pr_dbg2("removed %d duplicates\n", dup_syms);

	symtab->nr_alloc = symtab->nr_sym;
	symtab->sym = xrealloc(symtab->sym, symtab->nr_sym * sizeof(*symtab->sym));

	symtab->sym_names = xmalloc(sizeof(*symtab->sym_names) * symtab->nr_sym);

	for (i = 0; i < symtab->nr_sym; i++)
		symtab->sym_names[i] = &symtab->sym[i];
	qsort(symtab->sym_names, symtab->nr_sym, sizeof(*symtab->sym_names), namesort);

	symtab->name_sorted = true;
	ret = 0;
out:
	elf_end(elf);
	close(fd);
	return ret;

elf_error:
	pr_dbg("ELF error during symbol loading: %s\n",
	       elf_errmsg(elf_errno()));
	goto out;
}

static void sort_dynsymtab(struct symtab *dsymtab)
{
	unsigned i, k;

	/*
	 * abuse ->sym_names[] to save original index
	 */
	dsymtab->sym_names = xmalloc(sizeof(*dsymtab->sym_names) * dsymtab->nr_sym);

	/* save current address for each symbol */
	for (i = 0; i < dsymtab->nr_sym; i++)
		dsymtab->sym_names[i] = (void *)(long)dsymtab->sym[i].addr;

	/* sort ->sym by address now */
	qsort(dsymtab->sym, dsymtab->nr_sym, sizeof(*dsymtab->sym), addrsort);

	/* find position of sorted symbol */
	for (i = 0; i < dsymtab->nr_sym; i++) {
		for (k = 0; k < dsymtab->nr_sym; k++) {
			if (dsymtab->sym_names[i] == (void *)(long)dsymtab->sym[k].addr) {
				dsymtab->sym_names[i] = &dsymtab->sym[k];
				break;
			}
		}
	}

	dsymtab->name_sorted = false;
}

__weak int arch_load_dynsymtab_bindnow(Elf *elf, struct symtab *dsymtab,
				       unsigned long offset, unsigned long flags)
{
	return 0;
}

static int try_load_dynsymtab_bindnow(Elf *elf, struct Elf_Scn *dynsec,
				      int nr_dyns, struct symtab *dsymtab,
				      unsigned long offset, unsigned long flags)
{
	int idx;
	bool bind_now = false;
	Elf_Data *dynamic_data;

	dynamic_data = elf_getdata(dynsec, NULL);
	if (dynamic_data == NULL)
		return 0;

	for (idx = 0; idx < nr_dyns; idx++) {
		GElf_Dyn dyn;

		if (gelf_getdyn(dynamic_data, idx, &dyn) == NULL)
			return 0;

		if (dyn.d_tag != DT_BIND_NOW)
			bind_now = true;
		else if (dyn.d_tag == DT_FLAGS_1 && (dyn.d_un.d_val & DF_1_NOW))
			bind_now = true;
	}

	if (!bind_now)
		return 0;

	if (arch_load_dynsymtab_bindnow(elf, dsymtab, offset, flags) < 0) {
		pr_dbg("cannot load dynamic symbols for bind-now\n");
		__unload_symtab(dsymtab);
		return -1;
	}

	if (!dsymtab->nr_sym)
		return 0;

	sort_dynsymtab(dsymtab);
	return 1;
}

int load_elf_dynsymtab(struct symtab *dsymtab, Elf *elf,
		       unsigned long offset, unsigned long flags)
{
	int ret = -1;
	int idx, nr_rels = 0, nr_dyns = 0;
	unsigned grow = SYMTAB_GROW;
	Elf_Scn *dynsym_sec, *relplt_sec, *dynamic_sec, *sec;
	Elf_Data *dynsym_data, *relplt_data;
	size_t shstr_idx, dynstr_idx = 0;
	GElf_Ehdr ehdr;
	GElf_Addr plt_addr = 0;
	GElf_Addr prev_addr;
	size_t plt_entsize = 1;
	int rel_type = SHT_NULL;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto elf_error;

	if (flags & SYMTAB_FL_ADJ_OFFSET) {
		GElf_Phdr phdr;
		unsigned i;

		for (i = 0; i < ehdr.e_phnum; i++) {
			if (!gelf_getphdr(elf, i, &phdr))
				goto elf_error;

			if (phdr.p_type == PT_LOAD) {
				offset -= phdr.p_vaddr;
				break;
			}
		}
	}

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto elf_error;

	sec = dynsym_sec = relplt_sec = dynamic_sec = NULL;
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
		else if (strcmp(shstr, ".rela.plt") == 0) {
			relplt_sec = sec;
			nr_rels = shdr.sh_size / shdr.sh_entsize;
			rel_type = SHT_RELA;
		}
		else if (strcmp(shstr, ".rel.plt") == 0) {
			relplt_sec = sec;
			nr_rels = shdr.sh_size / shdr.sh_entsize;
			rel_type = SHT_REL;
		}
		else if (strcmp(shstr, ".plt") == 0) {
			plt_addr = shdr.sh_addr + offset;
			plt_entsize = shdr.sh_entsize;
		}
		else if (strcmp(shstr, ".dynamic") == 0) {
			dynamic_sec = sec;
			nr_dyns = shdr.sh_size / shdr.sh_entsize;
		}
	}

	if (dynsym_sec == NULL || dynamic_sec == NULL || plt_addr == 0) {
		pr_dbg("cannot find dynamic symbols.. skipping\n");
		ret = 0;
		goto out;
	}

	if (rel_type != SHT_RELA && rel_type != SHT_REL) {
		ret = try_load_dynsymtab_bindnow(elf, dynamic_sec, nr_dyns,
						 dsymtab, offset, flags);
		if (ret <= 0)
			pr_dbg("cannot find relocation info for PLT\n");
		goto out;
	}

	relplt_data = elf_getdata(relplt_sec, NULL);
	if (relplt_data == NULL)
		goto elf_error;

	dynsym_data = elf_getdata(dynsym_sec, NULL);
	if (dynsym_data == NULL)
		goto elf_error;

	if (ehdr.e_machine == EM_ARM) {
		plt_addr += 8;     /* ARM PLT0 size is 20 */
		plt_entsize = 12;  /* size of R_ARM_JUMP_SLOT */
	}
	else if (ehdr.e_machine == EM_AARCH64) {
		plt_addr += 16;    /* AARCH64 PLT0 size is 32 */
	}

	prev_addr = plt_addr;

	for (idx = 0; idx < nr_rels; idx++) {
		GElf_Sym esym;
		struct sym *sym;
		int symidx;
		char *name;

		if (rel_type == SHT_RELA) {
			GElf_Rela rela;

			if (gelf_getrela(relplt_data, idx, &rela) == NULL)
				goto elf_error;

			symidx = GELF_R_SYM(rela.r_info);
		} else {
			GElf_Rel rel;

			if (gelf_getrel(relplt_data, idx, &rel) == NULL)
				goto elf_error;

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

		if (ehdr.e_machine == EM_ARM && esym.st_value)
			sym->addr = esym.st_value + offset;
		else
			sym->addr = prev_addr + plt_entsize;
		sym->size = plt_entsize;
		sym->type = ST_PLT;

		prev_addr = sym->addr;

		if (flags & SYMTAB_FL_DEMANGLE)
			sym->name = demangle(name);
		else
			sym->name = xstrdup(name);

		pr_dbg3("[%zd] %c %"PRIx64" + %-5u %s\n", dsymtab->nr_sym,
			sym->type, sym->addr, sym->size, sym->name);
	}
	pr_dbg2("loaded %zd symbols\n", dsymtab->nr_sym);

	if (dsymtab->nr_sym == 0)
		goto out;

	sort_dynsymtab(dsymtab);
	ret = 0;

out:
	return ret;

elf_error:
	pr_dbg("ELF error during load dynsymtab: %s\n",
	       elf_errmsg(elf_errno()));
	__unload_symtab(dsymtab);
	goto out;
}

static int load_dynsymtab(struct symtab *dsymtab, const char *filename,
			  unsigned long offset, unsigned long flags)
{
	int fd, ret;
	Elf *elf;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg("error during open symbol file: %s: %m\n", filename);
		return -1;
	}

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL) {
		int err = elf_errno();

		pr_dbg("ELF error during load dynsymtab: %s\n", elf_errmsg(err));
		close(fd);
		return -1;
	}

	pr_dbg2("loading dynamic symbols from %s (offset: %#lx)\n", filename, offset);
	ret = load_elf_dynsymtab(dsymtab, elf, offset, flags);

	elf_end(elf);
	close(fd);
	return ret;
}

static void merge_symtabs(struct symtab *left, struct symtab *right)
{
	size_t nr_sym = left->nr_sym + right->nr_sym;
	struct sym *syms;
	size_t i;

	if (right->nr_sym == 0)
		return;

	if (left->nr_sym == 0) {
		*left = *right;
		right->nr_sym = 0;
		right->sym = NULL;
		return;
	}

	pr_dbg2("merge two symbol tables (left = %u, right = %u)\n",
		left->nr_sym, right->nr_sym);

	syms = xmalloc(nr_sym * sizeof(*syms));

	if (left->sym[0].addr < right->sym[0].addr) {
		memcpy(&syms[0], left->sym, left->nr_sym * sizeof(*syms));
		memcpy(&syms[left->nr_sym], right->sym, right->nr_sym * sizeof(*syms));
	}
	else {
		memcpy(&syms[0], right->sym, right->nr_sym * sizeof(*syms));
		memcpy(&syms[right->nr_sym], left->sym, left->nr_sym * sizeof(*syms));
	}

	free(left->sym);
	free(right->sym);
	left->sym = NULL;
	right->sym = NULL;

	free(left->sym_names);
	free(right->sym_names);
	left->sym_names = NULL;
	right->sym_names = NULL;

	left->nr_sym = left->nr_alloc = nr_sym;
	left->sym = syms;
	left->sym_names = xmalloc(nr_sym * sizeof(*left->sym_names));

	qsort(left->sym, left->nr_sym, sizeof(*left->sym), addrsort);

	for (i = 0; i < left->nr_sym; i++)
		left->sym_names[i] = &left->sym[i];
	qsort(left->sym_names, left->nr_sym, sizeof(*left->sym_names), namesort);

	left->name_sorted = true;
}

int check_trace_functions(const char *filename)
{
	int fd;
	int ret = -1;
	int idx, nr_dynsym = 0;
	size_t i;
	Elf *elf;
	Elf_Scn *dynsym_sec, *sec;
	Elf_Data *dynsym_data;
	size_t shstr_idx, dynstr_idx = 0;
	const char *trace_funcs[] = {
		"mcount",
		"_mcount",
		"__fentry__",
		"__gnu_mcount_nc",
		"__cyg_profile_func_enter",
	};

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg("error during open symbol file: %s: %m\n", filename);
		return -1;
	}

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto elf_error;

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto elf_error;

	sec = dynsym_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		GElf_Shdr shdr;

		if (gelf_getshdr(sec, &shdr) == NULL)
			goto elf_error;

		if (shdr.sh_type == SHT_DYNSYM) {
			dynsym_sec = sec;
			dynstr_idx = shdr.sh_link;
			nr_dynsym = shdr.sh_size / shdr.sh_entsize;
			break;
		}
	}

	if (dynsym_sec == NULL) {
		pr_dbg("cannot find dynamic symbols.. skipping\n");
		ret = 0;
		goto out;
	}

	dynsym_data = elf_getdata(dynsym_sec, NULL);
	if (dynsym_data == NULL)
		goto elf_error;

	pr_dbg2("check trace functions in %s\n", filename);
	for (idx = 0; idx < nr_dynsym; idx++) {
		GElf_Sym dsym;
		char *name;

		gelf_getsym(dynsym_data, idx, &dsym);
		name = elf_strptr(elf, dynstr_idx, dsym.st_name);

		for (i = 0; i < ARRAY_SIZE(trace_funcs); i++) {
			if (!strcmp(name, trace_funcs[i])) {
				/* 1 for mcount, 2 for cyg_prof.. */
				ret = (i == 3) ? 2 : 1;
				goto out;
			}
		}
	}
	ret = 0;

out:
	elf_end(elf);
	close(fd);
	return ret;

elf_error:
	pr_dbg("ELF error during load dynsymtab: %s\n",
	       elf_errmsg(elf_errno()));
	goto out;
}

static uint64_t find_map_offset(struct symtabs *symtabs,
				     const char *filename)
{
	struct uftrace_mmap *maps = symtabs->maps;

	while (maps) {
		if (!strcmp(maps->libname, filename))
			return maps->start;

		maps = maps->next;
	}
	return 0;
}

struct uftrace_mmap *find_map_by_name(struct symtabs *symtabs,
				      const char *prefix)
{
	struct uftrace_mmap *maps = symtabs->maps;
	char *mod_name;

	while (maps) {
		mod_name = strrchr(maps->libname, '/');
		if (mod_name == NULL)
			mod_name = maps->libname;
		else
			mod_name++;

		if (!strncmp(mod_name, prefix, strlen(prefix)))
			return maps;

		maps = maps->next;
	}
	return NULL;
}

void load_symtabs(struct symtabs *symtabs, const char *dirname,
		  const char *filename)
{
	unsigned long offset = 0;

	if (symtabs->loaded)
		return;

	symtabs->dirname = dirname;
	symtabs->filename = filename;

	if (symtabs->flags & SYMTAB_FL_ADJ_OFFSET)
		offset = find_map_offset(symtabs, filename);

	/* try .sym files first */
	if (dirname != NULL && (symtabs->flags & SYMTAB_FL_USE_SYMFILE)) {
		char *symfile = NULL;

		xasprintf(&symfile, "%s/%s.sym", dirname, basename(filename));
		if (access(symfile, F_OK) == 0)
			load_symbol_file(symtabs, symfile, offset);

		free(symfile);
	}

	/*
	 * skip loading unnecessary symbols (when no filter is used in
	 * the libmcount).  but it still needs to load dynamic symbols
	 * for plthook anyway.
	 */
	if (symtabs->symtab.nr_sym == 0 &&
	    !(symtabs->flags & SYMTAB_FL_SKIP_NORMAL))
		load_symtab(&symtabs->symtab, filename, offset, symtabs->flags);
	if (symtabs->dsymtab.nr_sym == 0 &&
	    !(symtabs->flags & SYMTAB_FL_SKIP_DYNAMIC))
		load_dynsymtab(&symtabs->dsymtab, filename, offset, symtabs->flags);

	symtabs->loaded = true;
}

void load_dlopen_symtabs(struct symtabs *symtabs, unsigned long offset,
			 const char *filename)
{
	const char *dirname = symtabs->dirname;

	if (symtabs->loaded)
		return;

	/* try .sym files first */
	if (dirname != NULL && (symtabs->flags & SYMTAB_FL_USE_SYMFILE)) {
		char *symfile = NULL;

		xasprintf(&symfile, "%s/%s.sym", dirname, basename(filename));
		if (access(symfile, F_OK) == 0)
			load_symbol_file(symtabs, symfile, offset);

		free(symfile);
	}
	if (symtabs->symtab.nr_sym == 0 &&
	    !(symtabs->flags & SYMTAB_FL_SKIP_NORMAL))
		load_symtab(&symtabs->symtab, filename, offset, symtabs->flags);
	if (symtabs->dsymtab.nr_sym == 0 &&
	    !(symtabs->flags & SYMTAB_FL_SKIP_DYNAMIC))
		load_dynsymtab(&symtabs->dsymtab, filename, offset, symtabs->flags);

	symtabs->loaded = true;
}

static int load_module_symbol(struct symtab *symtab, const char *symfile,
			      unsigned long offset);

void load_module_symtabs(struct symtabs *symtabs)
{
	struct uftrace_mmap *maps;
	static const char * const skip_libs[] = {
		/* uftrace internal libraries */
		"libmcount.so",
		"libmcount-fast.so",
		"libmcount-single.so",
		"libmcount-fast-single.so",
		/* system base libraries */
		"libc.so.6",
		"libgcc_s.so.1",
		"libpthread.so.0",
		"linux-vdso.so.1",
		"linux-gate.so.1",
		"ld-linux-x86-64.so.2",
	};
	size_t k;
	unsigned long flags = symtabs->flags;

	assert(symtabs->maps);

	maps = symtabs->maps;
	while (maps) {
		struct symtab dsymtab = {};

		if (!strcmp(maps->libname, symtabs->filename))
			goto next;
		if (maps->libname[0] == '[')
			goto next;

		for (k = 0; k < ARRAY_SIZE(skip_libs); k++) {
			if (!strcmp(basename(maps->libname), skip_libs[k]))
				goto next;
		}

		pr_dbg2("load module symbol table: %s\n", maps->libname);

		load_symtab(&maps->symtab, maps->libname, maps->start, flags);
		load_dynsymtab(&dsymtab, maps->libname, maps->start, flags);
		merge_symtabs(&maps->symtab, &dsymtab);

next:
		maps = maps->next;
	}
}

int load_symbol_file(struct symtabs *symtabs, const char *symfile,
		     unsigned long offset)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	unsigned int i;
	unsigned int grow = SYMTAB_GROW;
	struct symtab *stab = &symtabs->symtab;
	char allowed_types[] = "TtwPK";
	uint64_t prev_addr = -1;
	char prev_type = 'X';

	fp = fopen(symfile, "r");
	if (fp == NULL) {
		pr_dbg("reading %s failed: %m\n", symfile);
		return -1;
	}

	pr_dbg2("loading symbols from %s: offset = %lx\n", symfile, offset);
	while (getline(&line, &len, fp) > 0) {
		struct sym *sym;
		uint64_t addr;
		char type;
		char *name;
		char *pos;

		pos = strchr(line, '\n');
		if (pos)
			*pos = '\0';

		addr = strtoull(line, &pos, 16);

		if (*pos++ != ' ') {
			pr_dbg2("invalid symbol file format before type\n");
			continue;
		}
		type = *pos++;

		if (*pos++ != ' ') {
			pr_dbg2("invalid symbol file format after type\n");
			continue;
		}
		name = pos;

		/*
		 * remove kernel module if any.
		 *   ex)  btrfs_end_transaction_throttle     [btrfs]
		 */
		pos = strchr(name, '\t');
		if (pos)
			*pos = '\0';

		if (addr == prev_addr && type == prev_type) {
			sym = &stab->sym[stab->nr_sym - 1];

			/* for kernel symbols, replace SyS_xxx to sys_xxx */
			if (!strncmp(sym->name, "SyS_", 4) &&
			    !strncmp(name, "sys_", 4) &&
			    !strcmp(sym->name + 4, name + 4))
				strncpy(sym->name, name, 4);

			pr_dbg2("skip duplicated symbols: %s\n", name);
			continue;
		}

		if (strchr(allowed_types, type) == NULL)
			continue;

		/*
		 * it should be updated after the type check
		 * otherwise, it might access invalid sym
		 * in the above.
		 */
		prev_addr = addr;
		prev_type = type;

		if (type == ST_PLT)
			stab = &symtabs->dsymtab;
		else
			stab = &symtabs->symtab;

		if (stab->nr_sym >= stab->nr_alloc) {
			if (stab->nr_alloc >= grow * 4)
				grow *= 2;
			stab->nr_alloc += grow;
			stab->sym = xrealloc(stab->sym,
					     stab->nr_alloc * sizeof(*sym));
		}

		sym = &stab->sym[stab->nr_sym++];

		sym->addr = addr + offset;
		sym->type = type;
		sym->name = demangle(name);
		sym->size = 0;

		pr_dbg3("[%zd] %c %"PRIx64" + %-5u %s\n", stab->nr_sym,
			sym->type, sym->addr, sym->size, sym->name);

		if (stab->nr_sym > 1)
			sym[-1].size = sym->addr - sym[-1].addr;
	}
	free(line);
	pr_dbg2("loaded %zd normal + %zd dynamic symbols\n",
		symtabs->symtab.nr_sym, symtabs->dsymtab.nr_sym);

	stab = &symtabs->symtab;
	qsort(stab->sym, stab->nr_sym, sizeof(*stab->sym), addrsort);

	stab->sym_names = xmalloc(sizeof(*stab->sym_names) * stab->nr_sym);

	for (i = 0; i < stab->nr_sym; i++)
		stab->sym_names[i] = &stab->sym[i];
	qsort(stab->sym_names, stab->nr_sym, sizeof(*stab->sym_names), namesort);

	stab->name_sorted = true;

	/*
	 * sort dynamic symbol while reserving original index in ->sym_names[]
	 */
	stab = &symtabs->dsymtab;
	if (stab->nr_sym == 0)
		goto out;

	sort_dynsymtab(stab);

out:
	fclose(fp);
	return 0;
}

void save_symbol_file(struct symtabs *symtabs, const char *dirname,
		      const char *exename)
{
	FILE *fp;
	unsigned i;
	char *symfile = NULL;
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	unsigned long offset = 0;
	int fd;
	Elf *elf = NULL;
	GElf_Ehdr ehdr;
	GElf_Phdr phdr;

	xasprintf(&symfile, "%s/%s.sym", dirname, basename(exename));

	fp = fopen(symfile, "wx");
	if (fp == NULL) {
		if (errno == EEXIST)
			return;
		pr_err("cannot open %s file", symfile);
	}

	pr_dbg2("saving symbols to %s\n", symfile);

	fd = open(exename, O_RDONLY);
	if (fd < 0) {
		pr_dbg("error during open elf file: %s: %m\n", exename);
		goto do_it;
	}

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto do_it;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto do_it;

	for (i = 0; i < ehdr.e_phnum; i++) {
		if (!gelf_getphdr(elf, i, &phdr))
			break;
		if (phdr.p_type == PT_LOAD) {
			offset = phdr.p_vaddr;
			break;
		}
	}

	/* save relative offset of symbol address */
	symtabs->flags |= SYMTAB_FL_ADJ_OFFSET;

do_it:
	/* dynamic symbols */
	for (i = 0; i < dtab->nr_sym; i++)
		fprintf(fp, "%016"PRIx64" %c %s\n", dtab->sym_names[i]->addr - offset,
		       (char) dtab->sym_names[i]->type, dtab->sym_names[i]->name);
	/* this last entry should come from ->sym[] to know the real end */
	if (i > 0) {
		fprintf(fp, "%016"PRIx64" %c %s\n", dtab->sym[i-1].addr + dtab->sym[i-1].size - offset,
			(char) dtab->sym[i-1].type, "__dynsym_end");
	}

	/* normal symbols */
	for (i = 0; i < stab->nr_sym; i++)
		fprintf(fp, "%016"PRIx64" %c %s\n", stab->sym[i].addr - offset,
		       (char) stab->sym[i].type, stab->sym[i].name);
	if (i > 0) {
		fprintf(fp, "%016"PRIx64" %c %s\n",
			stab->sym[i-1].addr + stab->sym[i-1].size - offset,
			(char) stab->sym[i-1].type, "__sym_end");
	}

	elf_end(elf);
	close(fd);
	free(symfile);
	fclose(fp);
}

static int load_module_symbol(struct symtab *symtab, const char *symfile,
			      unsigned long offset)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	unsigned int i;
	unsigned int grow = SYMTAB_GROW;
	char allowed_types[] = "TtwPK";
	uint64_t prev_addr = -1;
	char prev_type = 'X';

	fp = fopen(symfile, "r");
	if (fp == NULL) {
		pr_dbg("reading %s failed: %m\n", symfile);
		return -1;
	}

	pr_dbg2("loading symbols from %s: offset = %lx\n", symfile, offset);
	while (getline(&line, &len, fp) > 0) {
		struct sym *sym;
		uint64_t addr;
		char type;
		char *name;
		char *pos;

		pos = strchr(line, '\n');
		if (pos)
			*pos = '\0';

		addr = strtoull(line, &pos, 16);

		if (*pos++ != ' ') {
			pr_dbg2("invalid symbol file format before type\n");
			continue;
		}
		type = *pos++;

		if (*pos++ != ' ') {
			pr_dbg2("invalid symbol file format after type\n");
			continue;
		}
		name = pos;

		/*
		 * remove kernel module if any.
		 *   ex)  btrfs_end_transaction_throttle     [btrfs]
		 */
		pos = strchr(name, '\t');
		if (pos)
			*pos = '\0';

		if (addr == prev_addr && type == prev_type) {
			sym = &symtab->sym[symtab->nr_sym - 1];

			/* for kernel symbols, replace SyS_xxx to sys_xxx */
			if (!strncmp(sym->name, "SyS_", 4) &&
			    !strncmp(name, "sys_", 4) &&
			    !strcmp(sym->name + 4, name + 4))
				strncpy(sym->name, name, 4);

			pr_dbg2("skip duplicated symbols: %s\n", name);
			continue;
		}

		if (strchr(allowed_types, type) == NULL)
			continue;

		/*
		 * it should be updated after the type check
		 * otherwise, it might access invalid sym
		 * in the above.
		 */
		prev_addr = addr;
		prev_type = type;

		if (symtab->nr_sym >= symtab->nr_alloc) {
			if (symtab->nr_alloc >= grow * 4)
				grow *= 2;
			symtab->nr_alloc += grow;
			symtab->sym = xrealloc(symtab->sym,
					       symtab->nr_alloc * sizeof(*sym));
		}

		sym = &symtab->sym[symtab->nr_sym++];

		sym->addr = addr + offset;
		sym->type = type;
		sym->name = demangle(name);
		sym->size = 0;

		pr_dbg3("[%zd] %c %lx + %-5u %s\n", symtab->nr_sym,
			sym->type, sym->addr, sym->size, sym->name);

		if (symtab->nr_sym > 1)
			sym[-1].size = sym->addr - sym[-1].addr;
	}
	free(line);

	qsort(symtab->sym, symtab->nr_sym, sizeof(*symtab->sym), addrsort);

	symtab->sym_names = xmalloc(sizeof(*symtab->sym_names) * symtab->nr_sym);

	for (i = 0; i < symtab->nr_sym; i++)
		symtab->sym_names[i] = &symtab->sym[i];
	qsort(symtab->sym_names, symtab->nr_sym, sizeof(*symtab->sym_names),
	      namesort);

	symtab->name_sorted = true;

	fclose(fp);
	return 0;
}

static void save_module_symbol(struct symtab *stab, const char *symfile,
			       unsigned long offset)
{
	FILE *fp;
	unsigned i;

	if (stab->nr_sym == 0)
		return;

	fp = fopen(symfile, "wx");
	if (fp == NULL) {
		if (errno == EEXIST)
			return;
		pr_err("cannot open %s file", symfile);
	}

	pr_dbg2("saving symbols to %s\n", symfile);

	/* normal symbols */
	for (i = 0; i < stab->nr_sym; i++)
		fprintf(fp, "%016"PRIx64" %c %s\n", stab->sym[i].addr - offset,
		       (char) stab->sym[i].type, stab->sym[i].name);
	if (i > 0) {
		fprintf(fp, "%016"PRIx64" %c %s\n",
			stab->sym[i-1].addr + stab->sym[i-1].size - offset,
			(char) stab->sym[i-1].type, "__sym_end");
	}

	fclose(fp);
}

void save_module_symtabs(struct symtabs *symtabs)
{
	char *symfile = NULL;
	struct uftrace_mmap *map;

	map = symtabs->maps;
	while (map) {
		xasprintf(&symfile, "%s/%s.sym", symtabs->dirname,
			  basename(map->libname));

		save_module_symbol(&map->symtab, symfile, map->start);

		free(symfile);
		symfile = NULL;

		map = map->next;
	}
}

int save_kernel_symbol(char *dirname)
{
	char *symfile = NULL;
	char buf[4096];
	FILE *ifp, *ofp;
	ssize_t len;
	int ret = 0;

	xasprintf(&symfile, "%s/kallsyms", dirname);
	ifp = fopen("/proc/kallsyms", "r");
	ofp = fopen(symfile, "w");

	if (ifp == NULL || ofp == NULL)
		pr_err("cannot open kernel symbol file");

	while ((len = fread(buf, 1, sizeof(buf), ifp)) > 0)
		fwrite(buf, 1, len, ofp);

	if (len < 0)
		ret = len;

	fclose(ifp);
	fclose(ofp);
	free(symfile);
	return ret;
}

int load_kernel_symbol(char *dirname)
{
	unsigned i;
	char *symfile = NULL;

	if (ksymtabs.loaded)
		return 0;

	xasprintf(&symfile, "%s/kallsyms", dirname);
	if (load_symbol_file(&ksymtabs, symfile, 0) < 0) {
		free(symfile);
		return -1;
	}

	for (i = 0; i < ksymtabs.symtab.nr_sym; i++)
		ksymtabs.symtab.sym[i].type = ST_KERNEL;

	free(symfile);
	ksymtabs.loaded = true;
	return 0;
}

struct symtab * get_kernel_symtab(void)
{
	if (ksymtabs.loaded)
		return &ksymtabs.symtab;

	return NULL;
}

void build_dynsym_idxlist(struct symtab *dsymtab, struct dynsym_idxlist *idxlist,
			  const char *symlist[], unsigned symcount)
{
	unsigned i, k;
	unsigned *idx = NULL;
	unsigned count = 0;

	for (i = 0; i < dsymtab->nr_sym; i++) {
		for (k = 0; k < symcount; k++) {
			if (!strcmp(dsymtab->sym_names[i]->name, symlist[k])) {
				idx = xrealloc(idx, (count + 1) * sizeof(*idx));

				idx[count++] = i;
				break;
			}
		}
	}

	idxlist->idx   = idx;
	idxlist->count = count;
}

void destroy_dynsym_idxlist(struct dynsym_idxlist *idxlist)
{
	free(idxlist->idx);
	idxlist->idx = NULL;
	idxlist->count = 0;
}

bool check_dynsym_idxlist(struct dynsym_idxlist *idxlist, unsigned idx)
{
	unsigned i;

	for (i = 0; i < idxlist->count; i++) {
		if (idx == idxlist->idx[i])
			return true;
	}
	return false;
}

struct sym * find_dynsym(struct symtabs *symtabs, size_t idx)
{
	struct symtab *dsymtab = &symtabs->dsymtab;

	if (idx >= dsymtab->nr_sym)
		return NULL;

	/* ->sym_names are sorted by original index */
	return dsymtab->sym_names[idx];
}

size_t count_dynsym(struct symtabs *symtabs)
{
	struct symtab *dsymtab = &symtabs->dsymtab;

	return dsymtab->nr_sym;
}

struct sym * find_symtabs(struct symtabs *symtabs, uint64_t addr)
{
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	struct uftrace_mmap *maps;
	struct sym *sym;

	if (is_kernel_address(symtabs, addr)) {
		struct symtab *ktab = get_kernel_symtab();
		uint64_t kaddr = get_real_address(addr);

		if (!ktab)
			return NULL;

		sym = bsearch(&kaddr, ktab->sym, ktab->nr_sym,
			      sizeof(*ktab->sym), addrfind);
		return sym;
	}

	sym = bsearch(&addr, stab->sym, stab->nr_sym,
		      sizeof(*sym), addrfind);
	if (sym)
		return sym;

	/* try dynamic symbols if failed */
	sym = bsearch(&addr, dtab->sym, dtab->nr_sym,
		      sizeof(*sym), addrfind);
	if (sym)
		return sym;

	maps = symtabs->maps;
	while (maps) {
		if (maps->start <= addr && addr < maps->end)
			break;

		maps = maps->next;
	}

	if (maps) {
		if (maps->symtab.nr_sym == 0) {
			bool found = false;

			if (symtabs->flags & SYMTAB_FL_USE_SYMFILE) {
				char *symfile = NULL;
				unsigned long offset = 0;

				if (symtabs->flags & SYMTAB_FL_ADJ_OFFSET)
					offset = maps->start;

				xasprintf(&symfile, "%s/%s.sym", symtabs->dirname,
					  basename(maps->libname));
				if (!load_module_symbol(&maps->symtab, symfile,
							offset)) {
					found = true;
				}
				free(symfile);
			}

			if (!found) {
				load_symtab(&maps->symtab, maps->libname,
					    maps->start, symtabs->flags);
			}
		}

		stab = &maps->symtab;
		sym = bsearch(&addr, stab->sym, stab->nr_sym,
			      sizeof(*sym), addrfind);
	}

	return sym;
}

struct sym * find_symname(struct symtab *symtab, const char *name)
{
	size_t i;

	if (symtab->name_sorted) {
		struct sym **psym;

		psym = bsearch(name, symtab->sym_names, symtab->nr_sym,
			       sizeof(*psym), namefind);
		if (psym)
			return *psym;

		return NULL;
	}

	for (i = 0; i < symtab->nr_sym; i++) {
		struct sym *sym = &symtab->sym[i];

		if (!strcmp(name, sym->name))
			return sym;
	}

	return NULL;
}

char *symbol_getname(struct sym *sym, uint64_t addr)
{
	char *name;

	if (sym == NULL) {
		xasprintf(&name, "<%"PRIx64">", addr);
		return name;
	}

	return sym->name;
}

/* must be used in pair with symbol_getname() */
void symbol_putname(struct sym *sym, char *name)
{
	if (sym != NULL)
		return;
	free(name);
}

void print_symtabs(struct symtabs *symtabs)
{
	size_t i;
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	char *name;

	pr_out("Normal symbols\n");
	pr_out("==============\n");
	for (i = 0; i < stab->nr_sym; i++) {
		struct sym *sym = &stab->sym[i];

		name = symbol_getname(sym, sym->addr);
		pr_out("[%2zd] %#"PRIx64": %s (size: %u)\n",
		       i, sym->addr, name, sym->size);
		symbol_putname(sym, name);
	}

	pr_out("\n\n");
	pr_out("Dynamic symbols\n");
	pr_out("===============\n");
	for (i = 0; i < dtab->nr_sym; i++) {
		struct sym *sym = &dtab->sym[i];

		name = symbol_getname(sym, sym->addr);
		pr_out("[%2zd] %#"PRIx64": %s (size: %u)\n",
		       i, sym->addr, name, sym->size);
		symbol_putname(sym, name);
	}
}

static uint64_t get_kernel_base(char *str)
{
	uint64_t addr = strtoull(str, NULL, 16);

	if (addr < 0x40000000UL) {
		return 0x40000000UL;
	} else if (addr < 0x80000000UL) {
		return 0x80000000UL;
	} else if (addr < 0xB0000000UL) {
		return 0xB0000000UL;
	} else if (addr < 0xC0000000UL) {
		return 0xC0000000UL;
	} else {
		return 0x800000000000ULL;
	}
}

void set_kernel_base(struct symtabs *symtabs, const char *session_id)
{
	FILE *fp;
	char buf[4096];
	char line[200];
	uint64_t kernel_base_addr = -1ULL;

	snprintf(buf, sizeof(buf), "%s/sid-%.*s.map",
		 symtabs->dirname, SESSION_ID_LEN, session_id);

	fp = fopen(buf, "r");
	if (fp == NULL)
		pr_err("open %s file failed", buf);

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strstr(line, "[stack") != NULL) {
			kernel_base_addr = get_kernel_base(line);
		}
	}
	fclose(fp);

	symtabs->kernel_base = kernel_base_addr;
}
