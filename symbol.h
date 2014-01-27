#ifndef FTRACE_SYMBOL_H
#define FTRACE_SYMBOL_H

struct sym {
	unsigned long addr;
	unsigned long size;
	char *name;
};

#define SYMTAB_GROW  16

struct symtab {
	struct sym *sym;
	struct sym **sym_names;
	size_t nr_sym;
	size_t nr_alloc;
};

struct sym * find_symtab(unsigned long addr);
struct sym * find_symname(const char *name);
int load_symtabs(const char *filename);
void unload_symtabs(void);

struct sym * find_dynsym(size_t idx);
size_t count_dynsym(void);
int load_dynsymtab(const char *filename);
void unload_dynsymtab(void);

#endif /* FTRACE_SYMBOL_H */
