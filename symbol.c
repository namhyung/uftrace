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

#include "symbol.h"
#include "utils.h"

static struct symtab symtab;
static struct symtab dynsymtab;

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

static const char ftrace_msg[] =
	"ftrace: ERROR: Can't find '%s' file.\n"
	"\tPlease check your binary.\n"
	"\tIf you run the binary under $PATH (like /usr/bin/%s),\n"
	"\tit probably wasn't compiled with -pg or -finstrument-functions flag\n"
	"\twhich generates traceable code.\n"
	"\tIf so, recompile and run it with full pathname.\n";

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

void __load_symtab(const char *filename, unsigned long offset)
{
	int fd;
	Elf *elf;
	size_t i, nr_sym = 0;
	Elf_Scn *sym_sec, *sec;
	Elf_Data *sym_data;
	size_t shstr_idx, symstr_idx = 0;
	char buf[256];
	const char *errmsg;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			pr_err(ftrace_msg, filename, basename(filename));
		else {
			errmsg = strerror_r(errno, buf, sizeof(buf));
			if (errmsg == NULL)
				errmsg = filename;

			pr_err("ftrace: ERROR: cannot load symbol table: %s\n",
			       errmsg);
		}
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
		pr_err("ftrace: ERROR: cannot find symbol information in '%s'.\n"
		       "Is it stripped?\n", filename);

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

		if (symtab.nr_sym >= symtab.nr_alloc) {
			symtab.nr_alloc += SYMTAB_GROW;
			symtab.sym = xrealloc(symtab.sym,
					      symtab.nr_alloc * sizeof(*sym));
		}

		sym = &symtab.sym[symtab.nr_sym++];

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

	qsort(symtab.sym, symtab.nr_sym, sizeof(*symtab.sym), addrsort);

	symtab.sym_names = xrealloc(symtab.sym_names,
				    sizeof(*symtab.sym_names) * symtab.nr_sym);

	for (i = 0; i < symtab.nr_sym; i++)
		symtab.sym_names[i] = &symtab.sym[i];
	qsort(symtab.sym_names, symtab.nr_sym, sizeof(*symtab.sym_names), namesort);

	elf_end(elf);
	close(fd);
	return;

elf_error:
	pr_err("ftrace: ELF error during symbol loading: %s\n",
	       elf_errmsg(elf_errno()));
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

/* This functions is also called from libmcount.so */
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
	char buf[256];
	const char *errmsg;

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
			//plt_addr += shdr.sh_entsize; /* skip first entry */
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

		if (dynsymtab.nr_sym >= dynsymtab.nr_alloc) {
			dynsymtab.nr_alloc += SYMTAB_GROW;
			dynsymtab.sym = realloc(dynsymtab.sym,
						dynsymtab.nr_alloc * sizeof(*sym));

			if (dynsymtab.sym == NULL) {
				pr_log("%s: not enough memory\n", __func__);
				goto out;
			}
		}

		sym = &dynsymtab.sym[dynsymtab.nr_sym++];

		sym->addr = plt_addr + (idx + 1) * plt_entsize;
		sym->size = plt_entsize;
		sym->name = strdup(name);
	}
	ret = 0;

out:
	elf_end(elf);
	close(fd);
	return ret;

elf_error:
	printf("%s: ELF error during load dynsymtab: %s\n",
	       __func__, elf_errmsg(elf_errno()));
	unload_dynsymtab();
	goto out;
}

void load_symtabs(const char *filename)
{
	/* already loaded */
	if (symtab.nr_sym)
		return;

	__load_symtab(filename, 0);
	load_dynsymtab(filename);
}

static const char *skip_syms[] = {
	"mcount",
	"__fentry__",
	"__gnu_mcount_nc",
	"__cyg_profile_func_enter",
	"__cyg_profile_func_exit",
	"_mcleanup",
	"__libc_start_main",
};
static unsigned *skip_idx;
static unsigned skip_idx_nr;

void setup_skip_idx(void)
{
	unsigned i, j;

	for (i = 0; i < dynsymtab.nr_sym; i++) {
		for (j = 0; j < ARRAY_SIZE(skip_syms); j++) {
			if (!strcmp(dynsymtab.sym[i].name, skip_syms[j])) {
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

struct sym * find_symtab(unsigned long addr, struct ftrace_proc_maps *maps)
{
	struct sym *sym;
	sym = bsearch((const void *)addr, symtab.sym, symtab.nr_sym,
		      sizeof(*symtab.sym), addrfind);

	if (sym)
		return sym;

	/* try dynamic symbols if failed */
	sym = bsearch((const void *)addr, dynsymtab.sym, dynsymtab.nr_sym,
		      sizeof(*dynsymtab.sym), addrfind);

	if (sym)
		return sym;

	while (maps) {
		if (maps->start <= addr && addr < maps->end)
			break;

		maps = maps->next;
	}

	if (maps) {
		__load_symtab(maps->libname, maps->start);

		sym = bsearch((const void *)addr, symtab.sym, symtab.nr_sym,
			      sizeof(*symtab.sym), addrfind);
	}

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

#ifdef HAVE_LIBIBERTY_DEMANGLE

		name = cplus_demangle_v3(sym->name, 0);
		if (name != NULL)
			status = 0;

#elif defined(HAVE_CXA_DEMANGLE)

		name = __cxa_demangle(sym->name, NULL, NULL, &status);

#endif
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

	if (!strcmp(name, sym->name))
		return;

free:
	if (strcmp(name, "<unknown>"))
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


