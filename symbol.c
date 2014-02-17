#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <gelf.h>
#include <unistd.h>

#include "symbol.h"
#include "utils.h"

static struct symtab symtab;
static struct symtab dynsymtab;

static bool use_demangle = true;
/* copied from /usr/include/c++/4.7.2/cxxabi.h */
extern char * __cxa_demangle(const char *mangled_name, char *output_buffer,
			     size_t *length, int *status);

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

static const char ftrace_msg[] =
	"ERROR: Can't find '%s' file.  Please check your binary.\n"
	"If you run the binary under $PATH (like /usr/bin/%s),\n"
	"it probably wasn't compiled with -pg which generates traceable code.\n"
	"If so, recompile and run it with full pathname.\n";

void unload_symtabs(void)
{
	size_t i;

	for (i = 0; i < symtab.nr_sym; i++) {
		struct sym *sym = symtab.sym + i;
		free(sym->name);
	}

	free(symtab.sym_names);
	free(symtab.sym);

	symtab.nr_sym = 0;
	symtab.sym = NULL;
	symtab.sym_names = NULL;

	for (i = 0; i < dynsymtab.nr_sym; i++) {
		struct sym *sym = dynsymtab.sym + i;
		free(sym->name);
	}

	free(dynsymtab.sym_names);
	free(dynsymtab.sym);

	dynsymtab.nr_sym = 0;
	dynsymtab.sym = NULL;
	dynsymtab.sym_names = NULL;
}

int load_symtabs(const char *filename)
{
	int fd;
	int ret = -1;
	Elf *elf;
	size_t i, nr_sym = 0, nr_rels = 0;
	Elf_Scn *sym_sec, *dynsym_sec, *relplt_sec, *sec;
	Elf_Data *sym_data, *dynsym_data, *relplt_data;
	size_t shstr_idx, symstr_idx = 0, dynstr_idx = 0;
	GElf_Addr plt_addr = 0;
	size_t plt_entsize = 1;
	int rel_type = SHT_NULL;

	/* already loaded */
	if (symtab.nr_sym)
		return 0;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			printf(ftrace_msg, filename, filename);
		else
			perror("ftrace:load_symtab");
		return ret;
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
		} else if (strcmp(shstr, ".dynsym") == 0) {
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
			//plt_addr += shdr.sh_entsize; /* skip first entry */
		}
	}

	if (sym_sec == NULL) {
		printf("ftrace: cannot find symbol information in '%s'.\n"
		       "Is it stripped?\n", filename);
		goto out;
	}

	if (dynsym_sec == NULL || plt_addr == 0) {
		printf("ftrace: cannot find dynamic symbols.. skipping\n");
		goto out;
	}

	if (rel_type != SHT_RELA && rel_type != SHT_REL) {
		printf("ftrace: cannot find relocation info for PLT\n");
		goto out;
	}

	sym_data = elf_getdata(sym_sec, NULL);
	if (sym_data == NULL)
		goto elf_error;

	relplt_data = elf_getdata(relplt_sec, NULL);
	if (relplt_data == NULL)
		goto elf_error;

	dynsym_data = elf_getdata(dynsym_sec, NULL);
	if (dynsym_data == NULL)
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

		if (symtab.nr_sym >= symtab.nr_alloc) {
			symtab.nr_alloc += SYMTAB_GROW;
			symtab.sym = realloc(symtab.sym,
					     symtab.nr_alloc * sizeof(*sym));

			if (symtab.sym == NULL) {
				perror("ftrace:load_symtab");
				goto out;
			}
		}

		sym = &symtab.sym[symtab.nr_sym++];

		sym->addr = elf_sym.st_value;
		sym->size = elf_sym.st_size;

		name = elf_strptr(elf, symstr_idx, elf_sym.st_name);

		/* Removing version info from undefined symbols */
		ver = strchr(name, '@');
		if (ver)
			sym->name = strndup(name, ver - name);
		else
			sym->name = strdup(name);

		if (sym->name == NULL) {
			perror("load_symtab");
			goto out;
		}
	}

	qsort(symtab.sym, symtab.nr_sym, sizeof(*symtab.sym), addrsort);

	symtab.sym_names = malloc(sizeof(*symtab.sym_names) * symtab.nr_sym);
	if (symtab.sym_names == NULL)
		goto out;

	for (i = 0; i < symtab.nr_sym; i++)
		symtab.sym_names[i] = &symtab.sym[i];
	qsort(symtab.sym_names, symtab.nr_sym, sizeof(*symtab.sym_names), namesort);

	for (i = 0; i < nr_rels; i++) {
		GElf_Sym esym;
		struct sym *sym;
		int symidx;
		char *name;

		if (rel_type == SHT_RELA) {
			GElf_Rela rela;

			if (gelf_getrela(relplt_data, i, &rela) == NULL)
				goto elf_error;

			symidx = GELF_R_SYM(rela.r_info);
		} else {
			GElf_Rel rel;

			if (gelf_getrel(relplt_data, i, &rel) == NULL)
				goto elf_error;

			symidx = GELF_R_SYM(rel.r_info);
		}

		gelf_getsym(dynsym_data, symidx, &esym);
		name = elf_strptr(elf, dynstr_idx, esym.st_name);

		if (dynsymtab.nr_sym >= dynsymtab.nr_alloc) {
			dynsymtab.nr_alloc += SYMTAB_GROW;
			dynsymtab.sym = realloc(dynsymtab.sym,
						dynsymtab.nr_alloc * sizeof(*sym));

			if (dynsymtab.sym == NULL) {
				perror("ftrace:load_dynsymtab");
				goto out;
			}
		}

		sym = &dynsymtab.sym[dynsymtab.nr_sym++];

		sym->addr = plt_addr + (i + 1) * plt_entsize;
		sym->size = plt_entsize;
		sym->name = xstrdup(name);
	}
	ret = 0;
out:
	elf_end(elf);
	close(fd);
	return ret;

elf_error:
	printf("ftrace:load_symtab: %s\n", elf_errmsg(elf_errno()));
	unload_symtabs();
	goto out;
}

void unload_dynsymtab(void)
{
	size_t i;

	for (i = 0; i < dynsymtab.nr_sym; i++) {
		struct sym *sym = dynsymtab.sym + i;
		free(sym->name);
	}

	free(dynsymtab.sym_names);
	free(dynsymtab.sym);

	dynsymtab.nr_sym = 0;
	dynsymtab.sym = NULL;
	dynsymtab.sym_names = NULL;
}

int load_dynsymtab(const char *filename)
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

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			printf(ftrace_msg, filename, filename);
		else
			perror("ftrace");
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
			//plt_addr += shdr.sh_entsize; /* skip first entry */
		}
	}

	if (dynsym_sec == NULL || plt_addr == 0) {
		printf("ftrace: cannot find dynamic symbols.. skipping\n");
		ret = 0;
		goto out;
	}

	if (rel_type != SHT_RELA && rel_type != SHT_REL) {
		printf("ftrace: cannot find relocation info for PLT\n");
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

		if (dynsymtab.nr_sym >= dynsymtab.nr_alloc) {
			dynsymtab.nr_alloc += SYMTAB_GROW;
			dynsymtab.sym = realloc(dynsymtab.sym,
						dynsymtab.nr_alloc * sizeof(*sym));

			if (dynsymtab.sym == NULL) {
				perror("ftrace:load_dynsymtab");
				goto out;
			}
		}

		sym = &dynsymtab.sym[dynsymtab.nr_sym++];

		sym->addr = plt_addr + (idx + 1) * plt_entsize;
		sym->size = plt_entsize;
		sym->name = xstrdup(name);
	}
	ret = 0;

out:
	elf_end(elf);
	close(fd);
	return ret;

elf_error:
	printf("ftrace:load_dynsymtab: %s\n", elf_errmsg(elf_errno()));
	unload_dynsymtab();
	goto out;
}

struct sym * find_dynsym(size_t idx)
{
	if (idx >= dynsymtab.nr_sym)
		return NULL;

	return &dynsymtab.sym[idx];
}

size_t count_dynsym(void)
{
	return dynsymtab.nr_sym;
}

struct sym * find_symtab(unsigned long addr)
{
	struct sym *sym;
	sym = bsearch((const void *)addr, symtab.sym, symtab.nr_sym,
		      sizeof(*symtab.sym), addrfind);

	if (sym)
		return sym;

	/* try dynamic symbols if failed */
	sym = bsearch((const void *)addr, dynsymtab.sym, dynsymtab.nr_sym,
		      sizeof(*dynsymtab.sym), addrfind);

	return sym;
}

struct sym * find_symname(const char *name)
{
	struct sym **psym;
	size_t i;

	psym = bsearch(name, symtab.sym_names, symtab.nr_sym,
		       sizeof(*symtab.sym_names), namefind);
	if (psym)
		return *psym;

	for (i = 0; i < dynsymtab.nr_sym; i++)
		if (!strcmp(name, dynsymtab.sym[i].name))
			return &dynsymtab.sym[i];

	return NULL;
}

char *symbol_getname(struct sym *sym, unsigned long addr)
{
	char *name;

	if (sym == NULL) {
		if (asprintf(&name, "<%lx>", addr) < 0)
			name = "<unknown>";
		return name;
	}

	if (use_demangle && sym->name[0] == '_' && sym->name[1] == 'Z') {
		int status = -1;

		name = __cxa_demangle(sym->name, NULL, NULL, &status);
		if (status != 0)
			name = sym->name;
	} else
		name = sym->name;

	return name;
}

/* must be used in pair with symbol_getname() */
void symbol_putname(struct sym *sym, char *name)
{
	if (sym == NULL)
		goto free;

	if (!use_demangle)
		return;

	if (!strcmp(name, "<unknown>") || !strcmp(name, sym->name))
		return;

free:
	free(name);
}

void print_symtabs(void)
{
	size_t i;

	printf("Normal symbols\n");
	printf("==============\n");
	for (i = 0; i < symtab.nr_sym; i++)
		printf("[%2zd] %s (%#lx) size: %lu\n", i, symtab.sym[i].name,
		       symtab.sym[i].addr, symtab.sym[i].size);

	printf("\n\n");
	printf("Dynamic symbols\n");
	printf("===============\n");
	for (i = 0; i < dynsymtab.nr_sym; i++)
		printf("[%2zd] %s (%#lx) size: %lu\n", i, dynsymtab.sym[i].name,
		       dynsymtab.sym[i].addr, dynsymtab.sym[i].size);

}


