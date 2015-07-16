/*
 * symbol management data structures for ftrace
 *
 * Copyright (C) 2014-2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

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

struct symtabs {
	struct symtab symtab;
	struct symtab dsymtab;
};

struct ftrace_proc_maps {
	struct ftrace_proc_maps *next;
	uint64_t start;
	uint64_t end;
	char prot[4];
	uint32_t len;
	char libname[];
};

struct sym * find_symtab(struct symtabs *symtabs, unsigned long addr,
			 struct ftrace_proc_maps *maps);
struct sym * find_symname(struct symtabs *symtabs, const char *name);
void load_symtabs(struct symtabs *symtabs, const char *filename);
void unload_symtabs(struct symtabs *symtabs);
void print_symtabs(struct symtabs *symtabs);

struct sym * find_dynsym(struct symtabs *symtabs, size_t idx);
size_t count_dynsym(struct symtabs *symtabs);
int load_dynsymtab(struct symtabs *symtabs, const char *filename);
void unload_dynsymtab(struct symtabs *symtabs);

char *symbol_getname(struct sym *sym, unsigned long addr);
void symbol_putname(struct sym *sym, char *name);

void setup_skip_idx(struct symtabs *symtabs);
void destroy_skip_idx(void);
bool should_skip_idx(unsigned idx);

#endif /* FTRACE_SYMBOL_H */
