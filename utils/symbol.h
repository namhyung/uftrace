/*
 * symbol management data structures for ftrace
 *
 * Copyright (C) 2014-2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef FTRACE_SYMBOL_H
#define FTRACE_SYMBOL_H

#include <stdint.h>


enum symtype {
	ST_UNKNOWN,
	ST_LOCAL	= 't',
	ST_GLOBAL	= 'T',
	ST_WEAK		= 'w',
	ST_PLT		= 'P',
	ST_KERNEL	= 'K',
};

struct sym {
	unsigned long addr;
	unsigned size;
	enum symtype type;
	char *name;
};

#define SYMTAB_GROW  16

struct symtab {
	struct sym *sym;
	struct sym **sym_names;
	size_t nr_sym;
	size_t nr_alloc;
	bool name_sorted;
};

struct symtabs {
	bool loaded;
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

#if __SIZEOF_LONG__ == 8
# define KADDR_SHIFT  47
#else
# define KADDR_SHIFT  31
#endif

static inline bool is_kernel_address(unsigned long addr)
{
	return !!(addr & (1UL << KADDR_SHIFT));
}

struct sym * find_symtabs(struct symtabs *symtabs, unsigned long addr,
			 struct ftrace_proc_maps *maps);
struct sym * find_symname(struct symtabs *symtabs, const char *name);
void load_symtabs(struct symtabs *symtabs, const char *dirname,
		  const char *filename);
void unload_symtabs(struct symtabs *symtabs);
void print_symtabs(struct symtabs *symtabs);

struct sym * find_dynsym(struct symtabs *symtabs, size_t idx);
size_t count_dynsym(struct symtabs *symtabs);
int load_dynsymtab(struct symtabs *symtabs, const char *filename);
void unload_dynsymtab(struct symtabs *symtabs);

int load_kernel_symbol(void);
struct symtab * get_kernel_symtab(void);
int load_symbol_file(const char *symfile, struct symtabs *symtabs);
void save_symbol_file(struct symtabs *symtabs, const char *dirname,
		      const char *exename);

char *symbol_getname(struct sym *sym, unsigned long addr);
void symbol_putname(struct sym *sym, char *name);

struct dynsym_idxlist {
	unsigned *idx;
	unsigned count;
};

void build_dynsym_idxlist(struct symtabs *symtabs, struct dynsym_idxlist *idxlist,
			  const char *symlist[], unsigned symcount);
void destroy_dynsym_idxlist(struct dynsym_idxlist *idxlist);
bool check_dynsym_idxlist(struct dynsym_idxlist *idxlist, unsigned idx);

void setup_skip_idx(struct symtabs *symtabs);
void destroy_skip_idx(void);
bool should_skip_idx(unsigned idx);

#endif /* FTRACE_SYMBOL_H */
