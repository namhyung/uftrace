/*
 * symbol management data structures for ftrace
 *
 * Copyright (C) 2014-2016, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef FTRACE_SYMBOL_H
#define FTRACE_SYMBOL_H

#include <stdint.h>

#include "utils.h"
#include "list.h"

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

struct ftrace_proc_maps {
	struct ftrace_proc_maps *next;
	uint64_t start;
	uint64_t end;
	char prot[4];
	uint32_t len;
	struct symtab symtab;
	char libname[];
};

enum symtab_flag {
	SYMTAB_FL_DEMANGLE	= (1U << 0),
	SYMTAB_FL_USE_SYMFILE	= (1U << 1),
	SYMTAB_FL_ADJ_OFFSET	= (1U << 2),
	SYMTAB_FL_SKIP_NORMAL	= (1U << 3),
	SYMTAB_FL_SKIP_DYNAMIC	= (1U << 4),
};

struct symtabs {
	bool loaded;
	const char *dirname;
	const char *filename;
	enum symtab_flag flags;
	struct symtab symtab;
	struct symtab dsymtab;
	struct ftrace_proc_maps *maps;
};

#if __SIZEOF_LONG__ == 8
# define KADDR_SHIFT  47
#else
# define KADDR_SHIFT  31
#endif

bool is_kernel_address(unsigned long addr);
unsigned long get_real_address(unsigned long addr);
void set_kernel_base(char *dirname, const char *session_id);

struct sym * find_symtabs(struct symtabs *symtabs, unsigned long addr);
struct sym * find_symname(struct symtab *symtab, const char *name);
void load_symtabs(struct symtabs *symtabs, const char *dirname,
		  const char *filename);
void unload_symtabs(struct symtabs *symtabs);
void print_symtabs(struct symtabs *symtabs);

void load_module_symtabs(struct symtabs *symtabs, struct list_head *head);
void save_module_symtabs(struct symtabs *symtabs, struct list_head *head);
void load_dlopen_symtabs(struct symtabs *symtabs, unsigned long offset,
			 const char *filename);

bool check_libpthread(const char *filename);
int check_trace_functions(const char *filename);

struct sym * find_dynsym(struct symtabs *symtabs, size_t idx);
size_t count_dynsym(struct symtabs *symtabs);

struct ftrace_proc_maps *find_map_by_name(struct symtabs *symtabs,
					  const char *prefix);

int save_kernel_symbol(char *dirname);
int load_kernel_symbol(char *dirname);

struct symtab * get_kernel_symtab(void);
int load_symbol_file(struct symtabs *symtabs, const char *symfile,
		     unsigned long offset);
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

enum symbol_demangler {
	DEMANGLE_ERROR		= -2,
	DEMANGLE_NOT_SUPPORTED,
	DEMANGLE_NONE,
	DEMANGLE_SIMPLE,
	DEMANGLE_FULL,
};

extern enum symbol_demangler demangler;

char *demangle(char *str);

#ifdef HAVE_CXA_DEMANGLE
/* copied from /usr/include/c++/4.7.2/cxxabi.h */
extern char * __cxa_demangle(const char *mangled_name, char *output_buffer,
			     size_t *length, int *status);

static inline bool support_full_demangle(void)
{
	return true;
}
#else
static inline bool support_full_demangle(void)
{
	return false;
}

static inline char *demangle_full(char *str)
{
	pr_log("full demangle is not supported\n");
	return str;
}
#endif /* HAVE_CXA_DEMANGLE */

#endif /* FTRACE_SYMBOL_H */
