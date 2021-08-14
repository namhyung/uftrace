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
#include "utils/rbtree.h"
#include "utils/dwarf.h"

#ifdef HAVE_LIBELF
# include "utils/symbol-libelf.h"
#else
# include "utils/symbol-rawelf.h"
#endif

#ifndef  STT_GNU_IFUNC
# define STT_GNU_IFUNC  10
#endif

#ifndef  STB_GNU_UNIQUE
# define STB_GNU_UNIQUE  10
#endif

#define BUILD_ID_SIZE 20
#define BUILD_ID_STR_SIZE (BUILD_ID_SIZE * 2 + 1)

enum symtype {
	ST_UNKNOWN	= '?',
	ST_LOCAL_FUNC	= 't',
	ST_GLOBAL_FUNC	= 'T',
	ST_WEAK_FUNC	= 'w',
	ST_PLT_FUNC	= 'P',
	ST_KERNEL_FUNC	= 'K',
	ST_LOCAL_DATA	= 'd',
	ST_GLOBAL_DATA	= 'D',
	ST_WEAK_DATA	= 'v',
	ST_UNIQUE_DATA	= 'u',
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

struct uftrace_module {
	struct rb_node node;
	struct symtab symtab;
	struct debug_info dinfo;
	char build_id[BUILD_ID_STR_SIZE];
	char name[];
};

struct uftrace_mmap {
	struct uftrace_mmap *next;
	struct uftrace_module *mod;
	uint64_t start;
	uint64_t end;
	char prot[4];
	uint32_t len;
	char build_id[BUILD_ID_STR_SIZE];
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
	uint64_t kernel_base;
	struct uftrace_mmap *exec_map;
	struct uftrace_mmap *maps;
};

#define for_each_map(symtabs, map)					\
	for ((map) = (symtabs)->maps; (map) != NULL; (map) = (map)->next)

/* addr should be from fstack or something other than rstack (rec) */
static inline bool is_kernel_address(struct symtabs *symtabs, uint64_t addr)
{
	return addr >= symtabs->kernel_base;
}

/* convert rstack->addr (or rec->addr) to full 64-bit address */
static inline uint64_t get_kernel_address(struct symtabs *symtabs, uint64_t addr)
{
	return addr | symtabs->kernel_base;
}

uint64_t guess_kernel_base(char *str);

extern struct sym sched_sym;

struct sym * find_symtabs(struct symtabs *symtabs, uint64_t addr);
struct sym * find_sym(struct symtab *symtab, uint64_t addr);
struct sym * find_symname(struct symtab *symtab, const char *name);
void print_symtab(struct symtab *symtab);

int arch_load_dynsymtab_noplt(struct symtab *dsymtab,
			      struct uftrace_elf_data *elf,
			      unsigned long offset, unsigned long flags);
int load_elf_dynsymtab(struct symtab *dsymtab, struct uftrace_elf_data *elf,
		       unsigned long offset, unsigned long flags);

void load_module_symtabs(struct symtabs *symtabs);
struct uftrace_module * load_module_symtab(struct symtabs *symtabs,
					   const char *mod_name,
					   char *build_id);
void save_module_symtabs(const char *dirname);
void unload_module_symtabs(void);

enum uftrace_trace_type {
	TRACE_ERROR   = -1,
	TRACE_NONE,
	TRACE_MCOUNT,
	TRACE_CYGPROF,
	TRACE_FENTRY,
};

char * get_soname(const char *filename);
bool has_dependency(const char *filename, const char *libname);
enum uftrace_trace_type check_trace_functions(const char *filename);
int check_static_binary(const char *filename);
char * check_script_file(const char *filename);

/* pseudo-map for kernel image */
#define MAP_KERNEL (struct uftrace_mmap *)1

struct uftrace_mmap * find_map(struct symtabs *symtabs, uint64_t addr);
struct uftrace_mmap * find_map_by_name(struct symtabs *symtabs,
				       const char *prefix);
struct uftrace_mmap * find_symbol_map(struct symtabs *symtabs, char *name);

int save_kernel_symbol(char *dirname);
int load_kernel_symbol(char *dirname);

struct symtab * get_kernel_symtab(void);
struct uftrace_module * get_kernel_module(void);

int load_symbol_file(struct symtabs *symtabs, const char *symfile,
		     uint64_t offset);
void save_symbol_file(struct symtabs *symtabs, const char *dirname,
		      const char *exename);
int check_symbol_file(const char *symfile, char *pathname, int pathlen,
		      char *build_id, int build_id_len);
char * make_new_symbol_filename(const char *symfile, const char *pathname,
				char *build_id);

char *symbol_getname(struct sym *sym, uint64_t addr);
void symbol_putname(struct sym *sym, char *name);

char *symbol_getname_offset(struct sym *sym, uint64_t addr);

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

int read_build_id(const char *filename, char *buf, int len);

#endif /* UFTRACE_SYMBOL_H */
