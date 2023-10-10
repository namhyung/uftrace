/*
 * symbol management data structures for uftrace
 *
 * Copyright (C) 2014-2017, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef UFTRACE_SYMBOL_H
#define UFTRACE_SYMBOL_H

#include <elf.h>
#include <stdint.h>

#include "utils/dwarf.h"
#include "utils/list.h"
#include "utils/rbtree.h"
#include "utils/utils.h"

#ifdef HAVE_LIBELF
#include "utils/symbol-libelf.h"
#else
#include "utils/symbol-rawelf.h"
#endif

#ifndef STT_GNU_IFUNC
#define STT_GNU_IFUNC 10
#endif

#ifndef STB_GNU_UNIQUE
#define STB_GNU_UNIQUE 10
#endif

#define BUILD_ID_SIZE 20
#define BUILD_ID_STR_SIZE (BUILD_ID_SIZE * 2 + 1)

#define UFTRACE_PYTHON_MODULE_NAME "uftrace_python"
#define UFTRACE_PYTHON_SYMTAB_NAME "python.fake"

enum uftrace_symtype {
	ST_UNKNOWN = '?',
	ST_LOCAL_FUNC = 't',
	ST_GLOBAL_FUNC = 'T',
	ST_WEAK_FUNC = 'w',
	ST_PLT_FUNC = 'P',
	ST_KERNEL_FUNC = 'K',
	ST_LOCAL_DATA = 'd',
	ST_GLOBAL_DATA = 'D',
	ST_WEAK_DATA = 'v',
	ST_UNIQUE_DATA = 'u',
};

struct uftrace_symbol {
	uint64_t addr;
	unsigned size;
	enum uftrace_symtype type;
	char *name;
};

/* initial factor to resize the symbol table */
#define SYMTAB_GROW 16

struct uftrace_symtab {
	/* array of symbols sorted by addr */
	struct uftrace_symbol *sym;
	/*
	 * array of symbols sorted by name when name_sorted is %true.
	 * but plthook_data.dsymtab uses this differently so that it keeps
	 * PLT index.  In that case name_sorted should be %false.
	 */
	struct uftrace_symbol **sym_names;
	/* number of actual symbols in the array */
	size_t nr_sym;
	/* number of allocated symbols */
	size_t nr_alloc;
	/* indicates whether it's sorted by name */
	bool name_sorted;
};

struct uftrace_module {
	struct rb_node node;
	struct uftrace_symtab symtab;
	struct uftrace_dbg_info dinfo;
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

enum uftrace_symtab_flag {
	SYMTAB_FL_DEMANGLE = (1U << 0),
	SYMTAB_FL_USE_SYMFILE = (1U << 1),
	SYMTAB_FL_ADJ_OFFSET = (1U << 2),
	SYMTAB_FL_SKIP_NORMAL = (1U << 3),
	SYMTAB_FL_SKIP_DYNAMIC = (1U << 4),
	SYMTAB_FL_SYMS_DIR = (1U << 5),
};

struct uftrace_sym_info {
	/* mmap and symtab info was loaded */
	bool loaded;
	/* name of directory which has data files */
	const char *dirname;
	/* name of the main executable file of this process */
	const char *filename;
	/*
	 * name of directory containing symbol info.
	 * mostly same as dirname, but could be different if --with-sym is given.
	 */
	const char *symdir;
	/* symbol table flags: see above */
	enum uftrace_symtab_flag flags;
	/* start address of kernel address space */
	uint64_t kernel_base;
	/* map for the main executable (cached) */
	struct uftrace_mmap *exec_map;
	/* list of memory mapping info for executable and libraries */
	struct uftrace_mmap *maps;
};

#define for_each_map(sym_info, map)                                                                \
	for ((map) = (sym_info)->maps; (map) != NULL; (map) = (map)->next)

/* addr should be from fstack or something other than rstack (rec) */
static inline bool is_kernel_address(struct uftrace_sym_info *sinfo, uint64_t addr)
{
	return addr >= sinfo->kernel_base;
}

/* convert rstack->addr (or rec->addr) to full 64-bit address */
static inline uint64_t get_kernel_address(struct uftrace_sym_info *sinfo, uint64_t addr)
{
	return addr | sinfo->kernel_base;
}

uint64_t guess_kernel_base(char *str);

extern struct uftrace_symbol sched_sym;
extern struct uftrace_symbol sched_preempt_sym;

struct uftrace_symbol *find_symtabs(struct uftrace_sym_info *sinfo, uint64_t addr);
struct uftrace_symbol *find_sym(struct uftrace_symtab *symtab, uint64_t addr);
struct uftrace_symbol *find_symname(struct uftrace_symtab *symtab, const char *name);
void print_symtab(struct uftrace_symtab *symtab);

int arch_load_dynsymtab_noplt(struct uftrace_symtab *dsymtab, struct uftrace_elf_data *elf,
			      unsigned long offset, unsigned long flags);
int load_elf_dynsymtab(struct uftrace_symtab *dsymtab, struct uftrace_elf_data *elf,
		       unsigned long offset, unsigned long flags);

void load_module_symtabs(struct uftrace_sym_info *sinfo);
struct uftrace_module *load_module_symtab(struct uftrace_sym_info *sinfo, const char *mod_name,
					  char *build_id);
void save_module_symtabs(const char *dirname);
void unload_module_symtabs(void);
void sort_dynsymtab(struct uftrace_symtab *dsymtab);

enum uftrace_trace_type {
	TRACE_ERROR = -1,
	TRACE_NONE,
	TRACE_MCOUNT,
	TRACE_CYGPROF,
	TRACE_FENTRY,
};

char *get_soname(const char *filename);
bool has_dependency(const char *filename, const char *libname);
enum uftrace_trace_type check_trace_functions(const char *filename);
int check_static_binary(const char *filename);
bool check_script_file(const char *filename, char *buf, size_t len);

/* pseudo-map for kernel image */
#define MAP_KERNEL (struct uftrace_mmap *)1

struct uftrace_mmap *find_map(struct uftrace_sym_info *sinfo, uint64_t addr);
struct uftrace_mmap *find_map_by_name(struct uftrace_sym_info *sinfo, const char *prefix);
struct uftrace_mmap *find_symbol_map(struct uftrace_sym_info *sinfo, char *name);

int save_kernel_symbol(char *dirname);
int load_kernel_symbol(char *dirname);

struct uftrace_symtab *get_kernel_symtab(void);
struct uftrace_module *get_kernel_module(void);

int load_symbol_file(struct uftrace_sym_info *sinfo, const char *symfile, uint64_t offset);
void save_symbol_file(struct uftrace_sym_info *sinfo, const char *dirname, const char *exename);
int check_symbol_file(const char *symfile, char *pathname, int pathlen, char *build_id,
		      int build_id_len);
char *make_new_symbol_filename(const char *symfile, const char *pathname, char *build_id);

char *symbol_getname(struct uftrace_symbol *sym, uint64_t addr);
void symbol_putname(struct uftrace_symbol *sym, char *name);

char *symbol_getname_offset(struct uftrace_symbol *sym, uint64_t addr);

struct dynsym_idxlist {
	unsigned *idx;
	unsigned count;
};

void build_dynsym_idxlist(struct uftrace_symtab *dsymtab, struct dynsym_idxlist *idxlist,
			  const char *symlist[], unsigned symcount);
void destroy_dynsym_idxlist(struct dynsym_idxlist *idxlist);
bool check_dynsym_idxlist(struct dynsym_idxlist *idxlist, unsigned idx);

void setup_skip_idx(struct uftrace_sym_info *sinfo);
void destroy_skip_idx(void);
bool should_skip_idx(unsigned idx);

enum symbol_demangler {
	DEMANGLE_ERROR = -2,
	DEMANGLE_NOT_SUPPORTED,
	DEMANGLE_NONE,
	DEMANGLE_SIMPLE,
	DEMANGLE_FULL,
};

extern enum symbol_demangler demangler;

char *demangle(char *str);

#ifdef HAVE_CXA_DEMANGLE
/* copied from /usr/include/c++/4.7.2/cxxabi.h */
extern char *__cxa_demangle(const char *mangled_name, char *output_buffer, size_t *length,
			    int *status);

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
