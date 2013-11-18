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
	size_t shstr_idx;
	Elf_Scn *shstr_sec, *sym_sec, *str_sec;
	Elf_Data *shstr_data, *sym_data, *str_data;
	Elf_Scn *sec;
	Elf_Data *data;
	size_t i, nr_sym;

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
		goto error;

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto error;

	shstr_sec = elf_getscn(elf, shstr_idx);
	if (shstr_sec == NULL)
		goto error;

	shstr_data = elf_getdata(shstr_sec, NULL);
	if (shstr_data == NULL)
		goto error;

	sec = sym_sec = str_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *shstr;
		GElf_Shdr shdr;

		if (gelf_getshdr(sec, &shdr) == NULL)
			goto error;

		shstr = ((char *)shstr_data->d_buf) + shdr.sh_name;

		if (strcmp(shstr, ".symtab") == 0) {
			sym_sec = sec;
			nr_sym = shdr.sh_size / shdr.sh_entsize;
		}
		if (strcmp(shstr, ".strtab") == 0)
			str_sec = sec;
	}

	if (sym_sec == NULL || str_sec == NULL) {
		printf("ftrace: cannot find symbol information in '%s'.  Is it stripped?\n",
		       filename);
		goto out;
	}

	sym_data = elf_getdata(sym_sec, NULL);
	str_data = elf_getdata(str_sec, NULL);

	if (sym_data == NULL || str_data == NULL) {
		printf("ftrace: cannot find symbol information in '%s'.\n", filename);
		goto error;
	}

	symtab.sym = NULL;
	symtab.nr_sym = 0;
	symtab.nr_alloc = 0;

	for (i = 0; i < nr_sym; i++) {
		GElf_Sym elf_sym;
		struct sym *sym;
		char *name;

		if (symtab.nr_sym >= symtab.nr_alloc) {
			symtab.nr_alloc += SYMTAB_GROW;
			symtab.sym = realloc(symtab.sym,
					     symtab.nr_alloc * sizeof(*sym));

			if (symtab.sym == NULL) {
				perror("load_symtab");
				goto out;
			}
		}
		if (gelf_getsym(sym_data, i, &elf_sym) == NULL)
			goto error;
		if (elf_sym.st_size == 0)
			continue;
		if (GELF_ST_TYPE(elf_sym.st_info) != STT_FUNC)
			continue;

		sym = &symtab.sym[symtab.nr_sym++];

		name = ((char *)str_data->d_buf) + elf_sym.st_name;
		sym->addr = elf_sym.st_value;
		sym->size = elf_sym.st_size;
		sym->name = strdup(name);
		if (sym->name == NULL) {
			perror("load_symtab");
			goto out;
		}
	}

	qsort(symtab.sym, symtab.nr_sym, sizeof(*symtab.sym), addrsort);
#if 0
	puts("symbol sorted by addr");
	for (i = 0; i < symtab.nr_sym; i++) {
		struct sym *sym = &symtab.sym[i];
		printf("  %s: %lx - %lx\n", sym->name, sym->addr, sym->addr+sym->size);
	}
#endif

	symtab.sym_names = malloc(sizeof(*symtab.sym_names) * symtab.nr_sym);
	if (symtab.sym_names == NULL)
		goto out;

	for (i = 0; i < symtab.nr_sym; i++)
		symtab.sym_names[i] = &symtab.sym[i];
	qsort(symtab.sym_names, symtab.nr_sym, sizeof(*symtab.sym_names), namesort);
#if 0
	puts("symbol sorted by name");
	for (i = 0; i < symtab.nr_sym; i++) {
		struct sym *sym = symtab.sym_names[i];
		printf("  %s: %lx - %lx\n", sym->name, sym->addr, sym->addr+sym->size);
	}
#endif

	ret = 0;
out:
	elf_end(elf);
	close(fd);
	return ret;

error:
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
	return *psym;
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
}
