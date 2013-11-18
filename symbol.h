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
int load_symtab(const char *filename);
void unload_symtab(void);

#endif /* FTRACE_SYMBOL_H */
