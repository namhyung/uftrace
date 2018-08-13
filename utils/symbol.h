/*
 * symbol management data structures for uftrace
 *
 * Copyright (C) 2014-2017, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef UFTRACE_SYMBOL_H
#define UFTRACE_SYMBOL_H

#include <stdint.h>
#include <elf.h>

#include "utils/utils.h"
#include "utils/list.h"
#include "utils/dwarf.h"

#ifdef HAVE_LIBELF
# include "utils/symbol-libelf.h"
#else
# include "utils/symbol-rawelf.h"
#endif

#ifndef  STT_GNU_IFUNC
# define STT_GNU_IFUNC  10
#endif

enum symtype {
	ST_UNKNOWN,
	ST_LOCAL	= 't',
	ST_GLOBAL	= 'T',
	ST_WEAK		= 'w',
	ST_PLT		= 'P',
	ST_KERNEL	= 'K',
};

struct sym {
	uint64_t addr;
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

struct uftrace_mmap {
	struct uftrace_mmap *next;
	uint64_t start;
	uint64_t end;
	char prot[4];
	uint32_t len;
	struct symtab symtab;
	struct debug_info dinfo;
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
	bool loaded_debug;
	const char *dirname;
	const char *filename;
	enum symtab_flag flags;
	struct symtab symtab;
	struct symtab dsymtab;
	struct debug_info dinfo;
	uint64_t kernel_base;
	uint64_t exec_base;
	struct uftrace_mmap *maps;
};

/* only meaningful for 64-bit systems */
#define KADDR_SHIFT  47

static inline bool is_kernel_address(struct symtabs *symtabs, uint64_t addr)
{
	return addr >= symtabs->kernel_base;
}

static inline uint64_t get_real_address(uint64_t addr)
{
	if (addr & (1ULL << KADDR_SHIFT))
		return addr | (-1ULL << KADDR_SHIFT);
	return addr;
}

uint64_t get_kernel_base(char *str);

extern struct sym sched_sym;

struct sym * find_symtabs(struct symtabs *symtabs, uint64_t addr);
struct sym * find_sym(struct symtab *symtab, uint64_t addr);
struct sym * find_symname(struct symtab *symtab, const char *name);
void load_symtabs(struct symtabs *symtabs, const char *dirname,
		  const char *filename);
void unload_symtabs(struct symtabs *symtabs);
void print_symtabs(struct symtabs *symtabs);

int arch_load_dynsymtab_bindnow(struct symtab *dsymtab,
				struct uftrace_elf_data *elf,
				unsigned long offset, unsigned long flags);
int load_elf_dynsymtab(struct symtab *dsymtab, struct uftrace_elf_data *elf,
		       unsigned long offset, unsigned long flags);

void load_module_symtabs(struct symtabs *symtabs);
void save_module_symtabs(struct symtabs *symtabs);
void load_dlopen_symtabs(struct symtabs *symtabs, unsigned long offset,
			 const char *filename);

enum uftrace_trace_type {
	TRACE_ERROR   = -1,
	TRACE_NONE,
	TRACE_MCOUNT,
	TRACE_CYGPROF,
};

bool check_libpthread(const char *filename);
enum uftrace_trace_type check_trace_functions(const char *filename);
int check_static_binary(const char *filename);

struct sym * find_dynsym(struct symtabs *symtabs, size_t idx);
size_t count_dynsym(struct symtabs *symtabs);

/* map for main executable */
#define MAP_MAIN (struct uftrace_mmap *)1

/* pseudo-map for kernel image */
#define MAP_KERNEL (struct uftrace_mmap *)2

struct uftrace_mmap * find_map(struct symtabs *symtabs, uint64_t addr);
struct uftrace_mmap * find_map_by_name(struct symtabs *symtabs,
				       const char *prefix);
struct uftrace_mmap * find_symbol_map(struct symtabs *symtabs, char *name);

int save_kernel_symbol(char *dirname);
int load_kernel_symbol(char *dirname);

struct symtab * get_kernel_symtab(void);
int load_symbol_file(struct symtabs *symtabs, const char *symfile,
		     uint64_t offset);
void save_symbol_file(struct symtabs *symtabs, const char *dirname,
		      const char *exename);

char *symbol_getname(struct sym *sym, uint64_t addr);
void symbol_putname(struct sym *sym, char *name);

struct dynsym_idxlist {
	unsigned *idx;
	unsigned count;
};

void build_dynsym_idxlist(struct symtab *dsymtab, struct dynsym_idxlist *idxlist,
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
	pr_warn("full demangle is not supported\n");
	return str;
}
#endif /* HAVE_CXA_DEMANGLE */

#endif /* UFTRACE_SYMBOL_H */
