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

#ifdef HAVE_LIBIBERTY
# include <libiberty.h>
#endif

/* This should be defined before #include "utils.h" */
#define PR_FMT  "ftrace"

#include "symbol.h"
#include "utils.h"

#if defined(HAVE_LIBIBERTY_DEMANGLE) || defined(HAVE_CXA_DEMANGLE)
static bool use_demangle = true;

# ifdef HAVE_LIBIBERTY_DEMANGLE
extern char * cplus_demangle_v3(const char *mangled_name, int options);
# endif

# ifdef HAVE_CXA_DEMANGLE
/* copied from /usr/include/c++/4.7.2/cxxabi.h */
extern char * __cxa_demangle(const char *mangled_name, char *output_buffer,
			     size_t *length, int *status);
# endif

#else /* NO DEMANGLER */
static bool use_demangle = false;
#endif

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
		if (errno == ENOENT)
			pr_err_ns(FTRACE_MSG, filename, basename(filename));
		else
			pr_err("cannot load symbol table");
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

		name = elf_strptr(elf, symstr_idx, elf_sym.st_name);

		/* Removing version info from undefined symbols */
		ver = strchr(name, '@');
		if (ver)
			sym->name = xstrndup(name, ver - name);
		else
			sym->name = xstrdup(name);
	}

	qsort(symtab->sym, symtab->nr_sym, sizeof(*symtab->sym), addrsort);

	symtab->sym_names = xrealloc(symtab->sym_names,
				     sizeof(*symtab->sym_names) * symtab->nr_sym);

	for (i = 0; i < symtab->nr_sym; i++)
		symtab->sym_names[i] = &symtab->sym[i];
	qsort(symtab->sym_names, symtab->nr_sym, sizeof(*symtab->sym_names), namesort);

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
	char buf[256];
	const char *errmsg;
	struct symtab *dsymtab = &symtabs->dsymtab;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		errmsg = strerror_r(errno, buf, sizeof(buf));
		if (errmsg == NULL)
			errmsg = filename;

		pr_log("error during load dynsymtab: %s\n", errmsg);
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

		sym->addr = esym.st_value ?: plt_addr + symidx * plt_entsize;
		sym->size = plt_entsize;
		sym->name = strdup(name);
	}
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

void load_symtabs(struct symtabs *symtabs, const char *filename)
{
	if (symtabs->loaded)
		return;

	load_symtab(symtabs, filename, 0);
	load_dynsymtab(symtabs, filename);

	symtabs->loaded = true;
}

static const char *skip_syms[] = {
	"mcount",
	"__fentry__",
	"__gnu_mcount_nc",
	"__cyg_profile_func_enter",
	"__cyg_profile_func_exit",
	"_mcleanup",
	"mcount_restore",
	"mcount_reset",
	"__libc_start_main",
};
static unsigned *skip_idx;
static unsigned skip_idx_nr;

void setup_skip_idx(struct symtabs *symtabs)
{
	unsigned i, j;
	struct symtab *dsymtab = &symtabs->dsymtab;

	for (i = 0; i < dsymtab->nr_sym; i++) {
		for (j = 0; j < ARRAY_SIZE(skip_syms); j++) {
			if (!strcmp(dsymtab->sym[i].name, skip_syms[j])) {
				skip_idx = xrealloc(skip_idx,
					(skip_idx_nr+1) * sizeof(*skip_idx));

				skip_idx[skip_idx_nr++] = i;
				break;
			}
		}
	}
}

void destroy_skip_idx(void)
{
	free(skip_idx);
	skip_idx = NULL;
	skip_idx_nr = 0;
}

bool should_skip_idx(unsigned idx)
{
	size_t i;

	for (i = 0; i < skip_idx_nr; i++) {
		if (idx == skip_idx[i])
			return true;
	}
	return false;
}

struct sym * find_dynsym(struct symtabs *symtabs, size_t idx)
{
	struct symtab *dsymtab = &symtabs->dsymtab;

	if (idx >= dsymtab->nr_sym)
		return NULL;

	return &dsymtab->sym[idx];
}

size_t count_dynsym(struct symtabs *symtabs)
{
	struct symtab *dsymtab = &symtabs->dsymtab;

	return dsymtab->nr_sym;
}

struct sym * find_symtab(struct symtabs *symtabs, unsigned long addr,
			 struct ftrace_proc_maps *maps)
{
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	struct sym *sym;

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

struct sym * find_symname(struct symtabs *symtabs, const char *name)
{
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	struct sym **psym;
	size_t i;

	psym = bsearch(name, stab->sym_names, stab->nr_sym,
		       sizeof(*psym), namefind);
	if (psym)
		return *psym;

	for (i = 0; i < dtab->nr_sym; i++)
		if (!strcmp(name, dtab->sym[i].name))
			return &dtab->sym[i];

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

	if (!use_demangle)
		return sym->name;

	symname = sym->name;

	/* skip global initialze (constructor?) functions */
	if (strncmp(symname, "_GLOBAL__sub_I", size_of_gsi) == 0) {
		symname += size_of_gsi;

		while (*symname++ != '_')
			continue;

		has_gsi = true;
	}

	if (symname[0] == '_' && symname[1] == 'Z') {
		int status = -1;

#ifdef HAVE_LIBIBERTY_DEMANGLE

		name = cplus_demangle_v3(symname, 0);
		if (name != NULL)
			status = 0;

#elif defined(HAVE_CXA_DEMANGLE)

		name = __cxa_demangle(symname, NULL, NULL, &status);

#endif
		if (status != 0)
			name = symname;

		/* omit template and/or argument part */
		symname = strchr(name, '<');
		if (symname == NULL)
			symname = strchr(name, '(');
		if (symname)
			*symname = '\0';

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

	if (!use_demangle)
		return;

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

	printf("Normal symbols\n");
	printf("==============\n");
	for (i = 0; i < stab->nr_sym; i++)
		printf("[%2zd] %s (%#lx) size: %lu\n", i, stab->sym[i].name,
		       stab->sym[i].addr, stab->sym[i].size);

	printf("\n\n");
	printf("Dynamic symbols\n");
	printf("===============\n");
	for (i = 0; i < dtab->nr_sym; i++)
		printf("[%2zd] %s (%#lx) size: %lu\n", i, dtab->sym[i].name,
		       dtab->sym[i].addr, dtab->sym[i].size);
}


