/*
 * symbol management routines for ftrace
 *
 * Copyright (C) 2014-2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <gelf.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT  "ftrace"

#include "symbol.h"
#include "utils.h"

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
	unsigned long addr = (unsigned long) a;
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

#define FTRACE_MSG  "Can't find '%s' file.\n" 					\
"\tPlease check your binary is instrumented.\n"					\
"\tIf you run the binary under $PATH (like /usr/bin/%s),\n"			\
"\tit probably wasn't compiled with -pg or -finstrument-functions flag\n" 	\
"\twhich generates traceable code.\n"						\
"\tIf so, recompile and run it with full pathname.\n"

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
	__unload_symtab(&symtabs->symtab);
	__unload_symtab(&symtabs->dsymtab);
}

int load_symtab(struct symtabs *symtabs, const char *filename, unsigned long offset)
{
	int fd;
	Elf *elf;
	int ret = -1;
	size_t i, nr_sym = 0;
	Elf_Scn *sym_sec, *sec;
	Elf_Data *sym_data;
	size_t shstr_idx, symstr_idx = 0;
	struct symtab *symtab = &symtabs->symtab;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg("error during load symtab: %s: %m\n", filename);
		return -1;
	}

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto elf_error;

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto elf_error;

	sec = sym_sec = NULL;
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
	}

	if (sym_sec == NULL)
		goto out;

	sym_data = elf_getdata(sym_sec, NULL);
	if (sym_data == NULL)
		goto elf_error;

	for (i = 0; i < nr_sym; i++) {
		GElf_Sym elf_sym;
		struct sym *sym;
		char *name, *ver;

		if (gelf_getsym(sym_data, i, &elf_sym) == NULL)
			goto elf_error;

		if (elf_sym.st_size == 0)
			continue;

		if (GELF_ST_TYPE(elf_sym.st_info) != STT_FUNC)
			continue;

		if (symtab->nr_sym >= symtab->nr_alloc) {
			symtab->nr_alloc += SYMTAB_GROW;
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

		/* Removing version info from undefined symbols */
		ver = strchr(name, '@');
		if (ver)
			name = xstrndup(name, ver - name);

		sym->name = demangle(name);
		if (ver)
			free(name);
	}

	qsort(symtab->sym, symtab->nr_sym, sizeof(*symtab->sym), addrsort);

	symtab->sym_names = xrealloc(symtab->sym_names,
				     sizeof(*symtab->sym_names) * symtab->nr_sym);

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
	pr_log("ELF error during symbol loading: %s\n",
	       elf_errmsg(elf_errno()));
	goto out;
}

/* This functions is also called from libmcount.so */
int load_dynsymtab(struct symtabs *symtabs, const char *filename)
{
	int fd;
	int ret = -1;
	int idx, nr_rels = 0;
	Elf *elf;
	Elf_Scn *dynsym_sec, *relplt_sec, *sec;
	Elf_Data *dynsym_data, *relplt_data;
	size_t shstr_idx, dynstr_idx = 0;
	GElf_Addr plt_addr = 0;
	size_t plt_entsize = 1;
	int rel_type = SHT_NULL;
	struct symtab *dsymtab = &symtabs->dsymtab;
	unsigned i, k;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg("error during load dynsymtab: %s: %m\n", filename);
		return -1;
	}

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto elf_error;

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto elf_error;

	sec = dynsym_sec = relplt_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *shstr;
		GElf_Shdr shdr;

		if (gelf_getshdr(sec, &shdr) == NULL)
			goto elf_error;

		shstr = elf_strptr(elf, shstr_idx, shdr.sh_name);

		if (strcmp(shstr, ".dynsym") == 0) {
			dynsym_sec = sec;
			dynstr_idx = shdr.sh_link;
		} else if (strcmp(shstr, ".rela.plt") == 0) {
			relplt_sec = sec;
			nr_rels = shdr.sh_size / shdr.sh_entsize;
			rel_type = SHT_RELA;
		} else if (strcmp(shstr, ".rel.plt") == 0) {
			relplt_sec = sec;
			nr_rels = shdr.sh_size / shdr.sh_entsize;
			rel_type = SHT_REL;
		} else if (strcmp(shstr, ".plt") == 0) {
			plt_addr = shdr.sh_addr;
			plt_entsize = shdr.sh_entsize;
		}
	}

	if (dynsym_sec == NULL || plt_addr == 0) {
		pr_log("cannot find dynamic symbols.. skipping\n");
		ret = 0;
		goto out;
	}

	if (rel_type != SHT_RELA && rel_type != SHT_REL) {
		pr_log("cannot find relocation info for PLT\n");
		goto out;
	}

	relplt_data = elf_getdata(relplt_sec, NULL);
	if (relplt_data == NULL)
		goto elf_error;

	dynsym_data = elf_getdata(dynsym_sec, NULL);
	if (dynsym_data == NULL)
		goto elf_error;

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
			dsymtab->nr_alloc += SYMTAB_GROW;
			dsymtab->sym = realloc(dsymtab->sym,
					       dsymtab->nr_alloc * sizeof(*sym));

			if (dsymtab->sym == NULL) {
				pr_log("not enough memory\n");
				goto out;
			}
		}

		sym = &dsymtab->sym[dsymtab->nr_sym++];

		sym->addr = esym.st_value ?: plt_addr + (idx+1) * plt_entsize;
		sym->size = plt_entsize;
		sym->type = ST_PLT,
		sym->name = demangle(name);
	}

	/*
	 * abuse ->sym_names[] to save original index
	 */
	dsymtab->sym_names = xrealloc(dsymtab->sym_names,
				      sizeof(*dsymtab->sym_names) * dsymtab->nr_sym);

	/* save current address for each symbol */
	for (i = 0; i < dsymtab->nr_sym; i++)
		dsymtab->sym_names[i] = (void *)dsymtab->sym[i].addr;

	/* sort ->sym by address now */
	qsort(dsymtab->sym, dsymtab->nr_sym, sizeof(*dsymtab->sym), addrsort);

	/* find position of sorted symbol */
	for (i = 0; i < dsymtab->nr_sym; i++) {
		for (k = 0; k < dsymtab->nr_sym; k++) {
			if (dsymtab->sym_names[i] == (void *)dsymtab->sym[k].addr)
				dsymtab->sym_names[i] = &dsymtab->sym[k];
		}
	}

	dsymtab->name_sorted = false;
	ret = 0;

out:
	elf_end(elf);
	close(fd);
	return ret;

elf_error:
	printf("ELF error during load dynsymtab: %s\n",
	       elf_errmsg(elf_errno()));
	__unload_symtab(dsymtab);
	goto out;
}

void load_symtabs(struct symtabs *symtabs, const char *dirname,
		  const char *filename)
{
	if (symtabs->loaded)
		return;

	/* try .sym files first */
	if (dirname != NULL) {
		char *symfile = NULL;

		xasprintf(&symfile, "%s/%s.sym", dirname, basename(filename));
		if (access(symfile, F_OK) == 0)
			load_symbol_file(symfile, symtabs);

		free(symfile);
	}

	if (symtabs->symtab.nr_sym == 0)
		load_symtab(symtabs, filename, 0);
	if (symtabs->dsymtab.nr_sym == 0)
		load_dynsymtab(symtabs, filename);

	symtabs->loaded = true;
}

int load_symbol_file(const char *symfile, struct symtabs *symtabs)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	unsigned int i;
	struct symtab *stab = &symtabs->symtab;
	char allowed_types[] = "TtwPK";

	fp = fopen(symfile, "r");
	if (fp == NULL) {
		pr_log("reading %s failed\n", symfile);
		return -1;
	}

	while (getline(&line, &len, fp) > 0) {
		struct sym *sym;
		uint64_t addr;
		char type;
		char *name;
		char *pos;

		pos = strchr(line, '\n');
		if (pos)
			*pos = '\0';

		addr = strtoul(line, &pos, 16);

		if (*pos++ != ' ') {
			pr_log("invalid symbol file format before type\n");
			continue;
		}
		type = *pos++;

		if (*pos++ != ' ') {
			pr_log("invalid symbol file format after type\n");
			continue;
		}
		name = pos;

		if (strchr(allowed_types, type) == NULL)
			continue;

		if (type == ST_PLT)
			stab = &symtabs->dsymtab;
		else
			stab = &symtabs->symtab;

		if (stab->nr_sym >= stab->nr_alloc) {
			stab->nr_alloc += SYMTAB_GROW;
			stab->sym = xrealloc(stab->sym,
					       stab->nr_alloc * sizeof(*sym));
		}

		sym = &stab->sym[stab->nr_sym++];

		sym->addr = addr;
		sym->type = type;
		sym->name = demangle(name);

		if (stab->nr_sym > 1)
			sym[-1].size = addr - sym[-1].addr;
	}
	free(line);

	stab = &symtabs->symtab;
	qsort(stab->sym, stab->nr_sym, sizeof(*stab->sym), addrsort);

	stab->sym_names = xrealloc(stab->sym_names,
				   sizeof(*stab->sym_names) * stab->nr_sym);

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

	stab->sym_names = xrealloc(stab->sym_names,
				   sizeof(*stab->sym_names) * stab->nr_sym);

	for (i = 0; i < stab->nr_sym; i++)
		stab->sym_names[i] = &stab->sym[i];

	qsort(stab->sym, stab->nr_sym, sizeof(*stab->sym), addrsort);

	for (i = 0; i < stab->nr_sym - 1; i++) {
		struct sym *sym = &stab->sym[i];
		sym->size = stab->sym[i + 1].addr - sym->addr;
	}
	stab->sym_names[i]->size = stab->sym_names[i - 1]->size;

	stab->name_sorted = false;
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

	xasprintf(&symfile, "%s/%s.sym", dirname, basename(exename));

	fp = fopen(symfile, "w");
	if (fp == NULL)
		pr_err("cannot open %s file", symfile);

	/* dynamic symbols */
	for (i = 0; i < dtab->nr_sym; i++)
		fprintf(fp, "%016lx %c %s\n", dtab->sym_names[i]->addr,
		       (char) dtab->sym_names[i]->type, dtab->sym_names[i]->name);
	/* this last entry should come from ->sym[] to know the real end */
	fprintf(fp, "%016lx %c %s\n", dtab->sym[i-1].addr + dtab->sym[i-1].size,
		(char) dtab->sym[i-1].type, "__dynsym_end");

	/* normal symbols */
	for (i = 0; i < stab->nr_sym; i++)
		fprintf(fp, "%016lx %c %s\n", stab->sym[i].addr,
		       (char) stab->sym[i].type, stab->sym[i].name);
	fprintf(fp, "%016lx %c %s\n", stab->sym[i-1].addr + stab->sym[i-1].size,
		(char) stab->sym[i-1].type, "__sym_end");

	free(symfile);
	fclose(fp);
}

int load_kernel_symbol(void)
{
	unsigned i;

	if (ksymtabs.loaded)
		return 0;

	if (load_symbol_file("/proc/kallsyms", &ksymtabs) < 0)
		return -1;

	for (i = 0; i < ksymtabs.symtab.nr_sym; i++)
		ksymtabs.symtab.sym[i].type = ST_KERNEL;

	ksymtabs.loaded = true;
	return 0;
}

struct symtab * get_kernel_symtab(void)
{
	if (ksymtabs.loaded)
		return &ksymtabs.symtab;

	return NULL;
}

void build_dynsym_idxlist(struct symtabs *symtabs, struct dynsym_idxlist *idxlist,
			  const char *symlist[], unsigned symcount)
{
	unsigned i, k;
	unsigned *idx = NULL;
	unsigned count = 0;
	struct symtab *dsymtab = &symtabs->dsymtab;

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

unsigned long get_real_address(unsigned long addr)
{
	if (is_kernel_address(addr))
		return addr | (-1UL << KADDR_SHIFT);
	return addr;
}

struct sym * find_symtabs(struct symtabs *symtabs, unsigned long addr,
			  struct ftrace_proc_maps *maps)
{
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	struct sym *sym;

	if (is_kernel_address(addr)) {
		struct symtab *ktab = get_kernel_symtab();
		const void *kaddr = (const void *)get_real_address(addr);

		if (!ktab)
			return NULL;

		sym = bsearch(kaddr, ktab->sym, ktab->nr_sym,
			      sizeof(*ktab->sym), addrfind);
		return sym;
	}

	sym = bsearch((const void *)addr, stab->sym, stab->nr_sym,
		      sizeof(*sym), addrfind);
	if (sym)
		return sym;

	/* try dynamic symbols if failed */
	sym = bsearch((const void *)addr, dtab->sym, dtab->nr_sym,
		      sizeof(*sym), addrfind);
	if (sym)
		return sym;

	while (maps) {
		if (maps->start <= addr && addr < maps->end)
			break;

		maps = maps->next;
	}

	if (maps) {
		load_symtab(symtabs, maps->libname, maps->start);

		sym = bsearch((const void *)addr, stab->sym, stab->nr_sym,
			      sizeof(*sym), addrfind);
	}

	return sym;
}

struct sym * find_symname(struct symtab *symtab, const char *name)
{
	size_t i;

	if (!strchr(name, ':') && symtab->name_sorted) {
		struct sym **psym;

		psym = bsearch(name, symtab->sym_names, symtab->nr_sym,
			       sizeof(*psym), namefind);
		if (psym)
			return *psym;

		return NULL;
	}

	for (i = 0; i < symtab->nr_sym; i++) {
		struct sym *sym = &symtab->sym[i];
		char *symname;
		int ret;

		symname = symbol_getname(sym, sym->addr);
		ret = strcmp(name, symname);
		symbol_putname(sym, symname);

		if (ret == 0)
			return sym;
	}

	return NULL;
}

char *symbol_getname(struct sym *sym, unsigned long addr)
{
	char *name;
	char *symname;
	bool has_gsi = false;
	static const size_t size_of_gsi = sizeof("_GLOBAL__sub_I") - 1;

	if (sym == NULL) {
		if (asprintf(&name, "<%lx>", addr) < 0)
			name = "<unknown>";
		return name;
	}

	symname = sym->name;

	/* skip global initialize (constructor?) functions */
	if (strncmp(symname, "_GLOBAL__sub_I", size_of_gsi) == 0) {
		symname += size_of_gsi;

		while (*symname++ != '_')
			continue;

		has_gsi = true;
	}

	if (symname[0] == '_' && symname[1] == 'Z') {
		name = demangle(symname);

		/* demangle failed: restore original name */
		if (name == symname && has_gsi)
			name = sym->name;
	} else {
		if (has_gsi)
			name = xstrdup(symname);
		else
			name = symname;
	}

	return name;
}

/* must be used in pair with symbol_getname() */
void symbol_putname(struct sym *sym, char *name)
{
	if (sym == NULL)
		goto free;

	if (name == sym->name)
		return;

free:
	if (strcmp(name, "<unknown>"))
		free(name);
}

void print_symtabs(struct symtabs *symtabs)
{
	size_t i;
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	char *name;

	printf("Normal symbols\n");
	printf("==============\n");
	for (i = 0; i < stab->nr_sym; i++) {
		name = symbol_getname(&stab->sym[i], stab->sym[i].addr);
		printf("[%2zd] %#lx: %s (size: %u)\n", i, stab->sym[i].addr,
		       name, stab->sym[i].size);
		symbol_putname(&stab->sym[i], name);
	}

	printf("\n\n");
	printf("Dynamic symbols\n");
	printf("===============\n");
	for (i = 0; i < dtab->nr_sym; i++) {
		name = symbol_getname(&dtab->sym[i], dtab->sym[i].addr);
		printf("[%2zd] %#lx: %s (size: %u)\n", i, dtab->sym_names[i]->addr,
		       name, dtab->sym_names[i]->size);
		symbol_putname(&dtab->sym[i], name);
	}
}
