#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <gelf.h>
#include <unistd.h>

#include "symbol.h"

static struct symtab symtab;

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

int load_symtab(const char *filename)
{
	int fd;
	int ret = -1;
	Elf *elf;
	size_t shstr_idx, symstr_idx;
	Elf_Scn *sym_sec;
	Elf_Data *sym_data;
	Elf_Scn *sec;
	size_t i, nr_sym = 0;

	/* already loaded */
	if (symtab.nr_sym)
		return 0;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			printf(ftrace_msg, filename, filename);
		else
			perror("ftrace");
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
			break;
		}
	}

	if (sym_sec == NULL) {
		printf("ftrace: cannot find symbol information in '%s'.\n"
		       "Is it stripped?\n", filename);
		goto out;
	}

	sym_data = elf_getdata(sym_sec, NULL);

	if (sym_data == NULL)
		goto elf_error;

	symtab.sym = NULL;
	symtab.nr_sym = 0;
	symtab.nr_alloc = 0;

	for (i = 0; i < nr_sym; i++) {
		GElf_Sym elf_sym;
		struct sym *sym;
		char *name, *ver;

		if (gelf_getsym(sym_data, i, &elf_sym) == NULL)
			goto elf_error;

		if (GELF_ST_TYPE(elf_sym.st_info) != STT_FUNC)
			continue;

		if (symtab.nr_sym >= symtab.nr_alloc) {
			symtab.nr_alloc += SYMTAB_GROW;
			symtab.sym = realloc(symtab.sym,
					     symtab.nr_alloc * sizeof(*sym));

			if (symtab.sym == NULL) {
				perror("load_symtab");
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

	ret = 0;
out:
	elf_end(elf);
	close(fd);
	return ret;

elf_error:
	printf("ftrace:load_symtab: %s\n", elf_errmsg(elf_errno()));
	goto out;
}

struct sym * find_symtab(unsigned long addr)
{
	return bsearch((const void *)addr, symtab.sym, symtab.nr_sym,
		       sizeof(*symtab.sym), addrfind);
}

struct sym * find_symname(const char *name)
{
	struct sym **psym;

	psym = bsearch(name, symtab.sym_names, symtab.nr_sym,
		       sizeof(*symtab.sym_names), namefind);
	return psym ? *psym : NULL;
}

void unload_symtab(void)
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
}
