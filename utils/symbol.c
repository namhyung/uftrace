/*
 * symbol management routines for uftrace
 *
 * Copyright (C) 2014-2018, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "symbol"
#define PR_DOMAIN  DBG_SYMBOL

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/rbtree.h"

#ifndef  EM_AARCH64
# define EM_AARCH64  183
#endif

/* (global) symbol for kernel */
static struct uftrace_module kernel;

/* prevent duplicate symbols table loading */
static struct rb_root modules = RB_ROOT;

struct sym sched_sym = {
	.addr = EVENT_ID_PERF_SCHED_BOTH,
	.size = 1,
	.type = ST_LOCAL_FUNC,
	.name = "linux:schedule",
};

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
	uint64_t addr = *(uint64_t *) a;
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

bool has_dependency(const char *filename, const char *libname)
{
	bool ret = false;
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;

	if (elf_init(filename, &elf) < 0) {
		pr_dbg("error during open symbol file: %s: %m\n", filename);
		return false;
	}

	elf_for_each_shdr(&elf, &iter) {
		if (iter.shdr.sh_type == SHT_DYNAMIC)
			break;
	}

	elf_for_each_dynamic(&elf, &iter) {
		char *soname;

		if (iter.dyn.d_tag != DT_NEEDED)
			continue;

		soname = elf_get_name(&elf, &iter, iter.dyn.d_un.d_ptr);
		if (!strcmp(soname, libname)) {
			ret = true;
			break;
		}
	}

	elf_finish(&elf);
	return ret;
}

int check_static_binary(const char *filename)
{
	int ret = 1;
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;

	if (elf_init(filename, &elf) < 0) {
		pr_dbg("error during open symbol file: %s: %m\n", filename);
		return -1;
	}

	elf_for_each_phdr(&elf, &iter) {
		if (iter.phdr.p_type == PT_DYNAMIC) {
			ret = 0;
			break;
		}
	}

	elf_finish(&elf);
	return ret;
}

/* caller should free the result */
char * check_script_file(const char *filename)
{
	char *shebang = NULL;
	char magic[2];
	int fd;
	char *p;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (read(fd, magic, sizeof(magic)) < 0)
		goto out;

	if (magic[0] != '#' || magic[1] != '!')
		goto out;

	shebang = xmalloc(1024);
	if (read(fd, shebang, 1024) < 0) {
		free(shebang);
		shebang = NULL;
		goto out;
	}
	shebang[1023] = '\0';

	p = strchr(shebang, '\n');
	if (p)
		*p = '\0';

out:
	close(fd);
	return shebang;
}

void unload_symtab(struct symtab *symtab)
{
	size_t i;

	for (i = 0; i < symtab->nr_sym; i++) {
		struct sym *sym = symtab->sym + i;
		free(sym->name);
	}

	free(symtab->sym_names);
	free(symtab->sym);

	symtab->nr_sym = 0;
	symtab->sym = NULL;
	symtab->sym_names = NULL;
}

void unload_symtabs(struct symtabs *symtabs)
{
	pr_dbg2("unload symbol tables\n");
	unload_symtab(&symtabs->symtab);
	unload_symtab(&symtabs->dsymtab);

	symtabs->loaded = false;
}

static int load_symbol(struct symtab *symtab, unsigned long prev_sym_value,
		       unsigned long offset, unsigned long flags,
		       struct uftrace_elf_data *elf,
		       struct uftrace_elf_iter *iter)
{
	char *name;
	struct sym *sym;
	typeof(iter->sym) *elf_sym = &iter->sym;

	if (elf_sym->st_shndx == STN_UNDEF)
		return 0;

	if (elf_sym->st_size == 0)
		return 0;

	if (elf_symbol_type(elf_sym) != STT_FUNC &&
	    elf_symbol_type(elf_sym) != STT_GNU_IFUNC &&
	    elf_symbol_type(elf_sym) != STT_OBJECT)
		return 0;

	/* skip aliases */
	if (prev_sym_value == elf_sym->st_value)
		return 0;

	sym = &symtab->sym[symtab->nr_sym++];

	sym->addr = elf_sym->st_value + offset;
	sym->size = elf_sym->st_size;

	switch (elf_symbol_bind(elf_sym)) {
	case STB_LOCAL:
		if (elf_symbol_type(elf_sym) == STT_OBJECT)
			sym->type = ST_LOCAL_DATA;
		else
			sym->type = ST_LOCAL_FUNC;
		break;
	case STB_GLOBAL:
		if (elf_symbol_type(elf_sym) == STT_OBJECT)
			sym->type = ST_GLOBAL_DATA;
		else
			sym->type = ST_GLOBAL_FUNC;
		break;
	case STB_WEAK:
		if (elf_symbol_type(elf_sym) == STT_OBJECT)
			sym->type = ST_WEAK_DATA;
		else
			sym->type = ST_WEAK_FUNC;
		break;
	case STB_GNU_UNIQUE:
		if (elf_symbol_type(elf_sym) == STT_OBJECT) {
			sym->type = ST_UNIQUE_DATA;
			break;
		}
		/* fall through */
	default:
		sym->type = ST_UNKNOWN;
		break;
	}

	name = elf_get_name(elf, iter, elf_sym->st_name);

	if (flags & SYMTAB_FL_DEMANGLE)
		sym->name = demangle(name);
	else
		sym->name = xstrdup(name);

	pr_dbg3("[%zd] %c %"PRIx64" + %-5u %s\n", symtab->nr_sym,
		sym->type, sym->addr, sym->size, sym->name);
	return 1;
}

static void sort_symtab(struct symtab *symtab)
{
	unsigned i;
	int dup_syms = 0;

	qsort(symtab->sym, symtab->nr_sym, sizeof(*symtab->sym), addrsort);

	/* remove duplicated (overlapped?) symbols */
	for (i = 0; i < symtab->nr_sym - 1; i++) {
		struct sym *curr = &symtab->sym[i];
		struct sym *next = &symtab->sym[i + 1];
		int count = 0;
		char *bestname = curr->name;

		while (curr->addr == next->addr &&
		       next < &symtab->sym[symtab->nr_sym]) {

			/* prefer names not started by '_' (if not mangled) */
			if (bestname[0] == '_' && bestname[1] != 'Z' &&
			    next->name[0] != '_')
				bestname = next->name;

			count++;
			next++;
		}

		if (count) {
			struct sym *tmp = curr;

			bestname = xstrdup(bestname);

			while (tmp < next - 1) {
				free(tmp->name);
				tmp++;
			}

			memmove(curr, next - 1,
				(symtab->nr_sym - i - count) * sizeof(*next));

			free(curr->name);
			curr->name = bestname;

			symtab->nr_sym -= count;
			dup_syms += count;
		}
	}

	if (dup_syms)
		pr_dbg2("removed %d duplicates\n", dup_syms);

	symtab->nr_alloc = symtab->nr_sym;
	symtab->sym = xrealloc(symtab->sym, symtab->nr_sym * sizeof(*symtab->sym));

	symtab->sym_names = xmalloc(sizeof(*symtab->sym_names) * symtab->nr_sym);

	for (i = 0; i < symtab->nr_sym; i++)
		symtab->sym_names[i] = &symtab->sym[i];
	qsort(symtab->sym_names, symtab->nr_sym, sizeof(*symtab->sym_names), namesort);

	symtab->name_sorted = true;
}

static int load_symtab(struct symtab *symtab, const char *filename,
		       unsigned long offset, unsigned long flags)
{
	int ret = -1;
	unsigned long prev_sym_value = -1;
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;

	if (elf_init(filename, &elf) < 0) {
		pr_dbg("error during open symbol file: %s: %m\n", filename);
		return -1;
	}

	if (flags & SYMTAB_FL_ADJ_OFFSET) {
		elf_for_each_phdr(&elf, &iter) {
			if (iter.phdr.p_type == PT_LOAD) {
				offset -= iter.phdr.p_vaddr;
				break;
			}
		}
	}

	elf_for_each_shdr(&elf, &iter) {
		if (iter.shdr.sh_type == SHT_SYMTAB)
			break;
	}

	if (iter.shdr.sh_type != SHT_SYMTAB) {
		/*
		 * fallback to dynamic symbol table when there's no symbol table
		 * (e.g. stripped binary built with -rdynamic option)
		 */
		elf_for_each_shdr(&elf, &iter) {
			if (iter.shdr.sh_type == SHT_DYNSYM)
				break;
		}

		if (iter.shdr.sh_type != SHT_DYNSYM) {
			pr_dbg("no symbol table was found\n");
			goto out;
		}

		pr_dbg2("no symtab, using dynsyms instead\n");
	}

	/* pre-allocate enough symbol table entries */
	symtab->nr_alloc = iter.shdr.sh_size / iter.shdr.sh_entsize;
	symtab->sym = malloc(symtab->nr_alloc * sizeof(*symtab->sym));

	pr_dbg2("loading symbols from %s (offset: %#lx)\n", filename, offset);
	if (iter.shdr.sh_type == SHT_SYMTAB) {
		elf_for_each_symbol(&elf, &iter) {
			if (load_symbol(symtab, prev_sym_value, offset, flags,
					&elf, &iter))
				prev_sym_value = iter.sym.st_value;
		}
	}
	else {
		elf_for_each_dynamic_symbol(&elf, &iter) {
			if (load_symbol(symtab, prev_sym_value, offset, flags,
					&elf, &iter))
				prev_sym_value = iter.sym.st_value;
		}
	}
	pr_dbg2("loaded %zd symbols\n", symtab->nr_sym);

	if (symtab->nr_sym == 0)
		goto out;

	/* also fixup the size of symbol table */
	sort_symtab(symtab);
	ret = 0;
out:
	elf_finish(&elf);
	return ret;
}

static int load_dyn_symbol(struct symtab *dsymtab, int sym_idx,
			   unsigned long offset, unsigned long flags,
			   unsigned long plt_entsize, unsigned long prev_addr,
			   struct uftrace_elf_data *elf,
			   struct uftrace_elf_iter *iter)
{
	char *name;
	struct sym *sym;

	elf_get_symbol(elf, iter, sym_idx);
	name = elf_get_name(elf, iter, iter->sym.st_name);

	if (*name == '\0')
		return 0;

	sym = &dsymtab->sym[dsymtab->nr_sym++];

	if (iter->sym.st_value && iter->sym.st_shndx == STN_UNDEF)
		sym->addr = iter->sym.st_value + offset;
	else
		sym->addr = prev_addr + plt_entsize;

	sym->size = plt_entsize;
	sym->type = ST_PLT_FUNC;

	if (flags & SYMTAB_FL_DEMANGLE)
		sym->name = demangle(name);
	else
		sym->name = xstrdup(name);

	pr_dbg3("[%zd] %c %"PRIx64" + %-5u %s\n", dsymtab->nr_sym,
		sym->type, sym->addr, sym->size, sym->name);
	return 1;
}

static void sort_dynsymtab(struct symtab *dsymtab)
{
	unsigned i, k;

	dsymtab->nr_alloc = dsymtab->nr_sym;
	dsymtab->sym = xrealloc(dsymtab->sym, dsymtab->nr_sym * sizeof(*dsymtab->sym));

	/*
	 * abuse ->sym_names[] to save original index
	 */
	dsymtab->sym_names = xmalloc(sizeof(*dsymtab->sym_names) * dsymtab->nr_sym);

	/* save current address for each symbol */
	for (i = 0; i < dsymtab->nr_sym; i++)
		dsymtab->sym_names[i] = (void *)(long)dsymtab->sym[i].addr;

	/* sort ->sym by address now */
	qsort(dsymtab->sym, dsymtab->nr_sym, sizeof(*dsymtab->sym), addrsort);

	/* find position of sorted symbol */
	for (i = 0; i < dsymtab->nr_sym; i++) {
		for (k = 0; k < dsymtab->nr_sym; k++) {
			if (dsymtab->sym_names[i] == (void *)(long)dsymtab->sym[k].addr) {
				dsymtab->sym_names[i] = &dsymtab->sym[k];
				break;
			}
		}
	}

	dsymtab->name_sorted = false;
}

__weak int arch_load_dynsymtab_noplt(struct symtab *dsymtab,
				     struct uftrace_elf_data *elf,
				     unsigned long offset, unsigned long flags)
{
	return 0;
}

int load_elf_dynsymtab(struct symtab *dsymtab, struct uftrace_elf_data *elf,
		       unsigned long offset, unsigned long flags)
{
	int ret = -1;
	char *shstr;
	unsigned long plt_addr = 0;
	unsigned long prev_addr;
	size_t plt_entsize = 1;
	int rel_type = SHT_NULL;
	bool found_dynamic = false;
	bool found_dynsym = false;
	struct uftrace_elf_iter sec_iter;
	struct uftrace_elf_iter dyn_iter;
	struct uftrace_elf_iter rel_iter;
	unsigned symidx;
	struct sym *sym;

	if (flags & SYMTAB_FL_ADJ_OFFSET) {
		elf_for_each_phdr(elf, &sec_iter) {
			if (sec_iter.phdr.p_type == PT_LOAD) {
				offset -= sec_iter.phdr.p_vaddr;
				break;
			}
		}
	}

	elf_for_each_shdr(elf, &sec_iter) {
		typeof(sec_iter.shdr) *shdr = &sec_iter.shdr;
		shstr = elf_get_name(elf, &sec_iter, shdr->sh_name);

		if (strcmp(shstr, ".dynsym") == 0) {
			memcpy(&dyn_iter, &sec_iter, sizeof(sec_iter));
			elf_get_strtab(elf, &dyn_iter, shdr->sh_link);
			elf_get_secdata(elf, &dyn_iter);
			found_dynsym = true;
		}
		else if (strcmp(shstr, ".rela.plt") == 0) {
			memcpy(&rel_iter, &sec_iter, sizeof(sec_iter));
			rel_type = SHT_RELA;
		}
		else if (strcmp(shstr, ".rel.plt") == 0) {
			memcpy(&rel_iter, &sec_iter, sizeof(sec_iter));
			rel_type = SHT_REL;
		}
		else if (strcmp(shstr, ".plt") == 0) {
			plt_addr = shdr->sh_addr + offset;
			plt_entsize = shdr->sh_entsize;
		}
		else if (strcmp(shstr, ".dynamic") == 0) {
			found_dynamic = true;
		}
	}

	if (!found_dynsym || !found_dynamic) {
		pr_dbg2("cannot find dynamic symbols.. skipping\n");
		ret = 0;
		goto out;
	}

	if (rel_type == SHT_NULL) {
		arch_load_dynsymtab_noplt(dsymtab, elf, offset, flags);
		goto out_sort;
	}

	if (elf->ehdr.e_machine == EM_ARM) {
		plt_addr += 8;     /* ARM PLT0 size is 20 */
		plt_entsize = 12;  /* size of R_ARM_JUMP_SLOT */
	}
	else if (elf->ehdr.e_machine == EM_AARCH64) {
		plt_addr += 16;    /* AARCH64 PLT0 size is 32 */
	}
	else if (elf->ehdr.e_machine == EM_386) {
		plt_entsize += 12;
	}
	else if (elf->ehdr.e_machine == EM_X86_64) {
		plt_entsize = 16;  /* lld (of LLVM) seems to miss setting it */
	}

	prev_addr = plt_addr;

	/* pre-allocate enough symbol table entries */
	dsymtab->nr_alloc = rel_iter.shdr.sh_size / rel_iter.shdr.sh_entsize;
	dsymtab->sym = malloc(dsymtab->nr_alloc * sizeof(*dsymtab->sym));

	if (rel_type == SHT_REL) {
		elf_for_each_rel(elf, &rel_iter) {
			symidx = elf_rel_symbol(&rel_iter.rel);
			elf_get_symbol(elf, &dyn_iter, symidx);

			if (load_dyn_symbol(dsymtab, symidx, offset, flags,
					    plt_entsize, prev_addr,
					    elf, &dyn_iter)) {
				sym = &dsymtab->sym[dsymtab->nr_sym - 1];
				prev_addr = sym->addr;
			}
		}
	}
	else {
		elf_for_each_rela(elf, &rel_iter) {
			symidx = elf_rel_symbol(&rel_iter.rela);
			elf_get_symbol(elf, &dyn_iter, symidx);

			if (load_dyn_symbol(dsymtab, symidx, offset, flags,
					    plt_entsize, prev_addr,
					    elf, &dyn_iter)) {
				sym = &dsymtab->sym[dsymtab->nr_sym - 1];
				prev_addr = sym->addr;
			}
		}
	}

out_sort:
	pr_dbg2("loaded %zd symbols\n", dsymtab->nr_sym);

	if (dsymtab->nr_sym == 0)
		goto out;

	/* also fixup the size of symbol table */
	sort_dynsymtab(dsymtab);
	ret = 0;

out:
	return ret;
}

static int load_dynsymtab(struct symtab *dsymtab, const char *filename,
			  unsigned long offset, unsigned long flags)
{
	int ret;
	struct uftrace_elf_data elf;

	if (elf_init(filename, &elf) < 0) {
		pr_dbg("error during open symbol file: %s: %m\n", filename);
		return -1;
	}

	pr_dbg2("loading dynamic symbols from %s (offset: %#lx)\n", filename, offset);
	ret = load_elf_dynsymtab(dsymtab, &elf, offset, flags);

	elf_finish(&elf);
	return ret;
}

static void merge_symtabs(struct symtab *left, struct symtab *right)
{
	size_t nr_sym = left->nr_sym + right->nr_sym;
	struct sym *syms;
	size_t i;

	if (right->nr_sym == 0)
		return;

	if (left->nr_sym == 0) {
		*left = *right;
		right->nr_sym = 0;
		right->sym = NULL;
		right->sym_names = NULL;
		return;
	}

	pr_dbg2("merge two symbol tables (left = %u, right = %u)\n",
		left->nr_sym, right->nr_sym);

	syms = xmalloc(nr_sym * sizeof(*syms));

	if (left->sym[0].addr < right->sym[0].addr) {
		memcpy(&syms[0], left->sym, left->nr_sym * sizeof(*syms));
		memcpy(&syms[left->nr_sym], right->sym, right->nr_sym * sizeof(*syms));
	}
	else {
		memcpy(&syms[0], right->sym, right->nr_sym * sizeof(*syms));
		memcpy(&syms[right->nr_sym], left->sym, left->nr_sym * sizeof(*syms));
	}

	free(left->sym);
	free(right->sym);
	left->sym = NULL;
	right->sym = NULL;

	free(left->sym_names);
	free(right->sym_names);
	left->sym_names = NULL;
	right->sym_names = NULL;

	left->nr_sym = left->nr_alloc = nr_sym;
	left->sym = syms;
	left->sym_names = xmalloc(nr_sym * sizeof(*left->sym_names));

	qsort(left->sym, left->nr_sym, sizeof(*left->sym), addrsort);

	for (i = 0; i < left->nr_sym; i++)
		left->sym_names[i] = &left->sym[i];
	qsort(left->sym_names, left->nr_sym, sizeof(*left->sym_names), namesort);

	left->name_sorted = true;
}

static int update_symtab_using_dynsym(struct symtab *symtab, const char *filename,
				      unsigned long offset, unsigned long flags)
{
	int ret = -1;
	int count = 0;
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;

	if (elf_init(filename, &elf) < 0)
		return -1;

	if (flags & SYMTAB_FL_ADJ_OFFSET) {
		elf_for_each_phdr(&elf, &iter) {
			if (iter.phdr.p_type == PT_LOAD) {
				offset -= iter.phdr.p_vaddr;
				break;
			}
		}
	}

	elf_for_each_shdr(&elf, &iter) {
		if (iter.shdr.sh_type == SHT_DYNSYM)
			break;
	}

	if (iter.shdr.sh_type != SHT_DYNSYM) {
		ret = 0;
		goto out;
	}

	pr_dbg2("updating symbol name using dynamic symbols\n");

	elf_for_each_dynamic_symbol(&elf, &iter) {
		struct sym *sym;
		char *name;
		uint64_t addr;

		if (iter.sym.st_shndx == SHN_UNDEF)
			continue;
		if (elf_symbol_type(&iter.sym) != STT_FUNC &&
		    elf_symbol_type(&iter.sym) != STT_GNU_IFUNC &&
		    elf_symbol_type(&iter.sym) != STT_OBJECT)
			continue;

		addr = iter.sym.st_value + offset;
		sym = bsearch(&addr, symtab->sym, symtab->nr_sym,
			      sizeof(*sym), addrfind);
		if (sym == NULL)
			continue;

		name = elf_get_name(&elf, &iter, iter.sym.st_name);
		if (sym->name[0] != '_' && name[0] == '_')
			continue;
		if (sym->name[1] == 'Z')
			continue;

		pr_dbg3("update symbol name to %s\n", name);
		free(sym->name);
		count++;

		if (flags & SYMTAB_FL_DEMANGLE)
			sym->name = demangle(name);
		else
			sym->name = xstrdup(name);
	}
	ret = 1;

	if (count)
		pr_dbg2("updated %d symbols\n", count);

	qsort(symtab->sym_names, symtab->nr_sym, sizeof(*symtab->sym_names), namesort);
	symtab->name_sorted = true;

out:
	elf_finish(&elf);
	return ret;
}

enum uftrace_trace_type check_trace_functions(const char *filename)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	enum uftrace_trace_type ret = TRACE_ERROR;
	const char *trace_funcs[] = {
		"__cyg_profile_func_enter",
		"mcount",
		"_mcount",
		"__fentry__",
		"__gnu_mcount_nc",
	};
	char *name;
	unsigned i;

	if (elf_init(filename, &elf) < 0) {
		pr_dbg("error during open symbol file: %s: %m\n", filename);
		return ret;
	}

	elf_for_each_shdr(&elf, &iter) {
		if (iter.shdr.sh_type == SHT_DYNSYM) {
			elf_get_secdata(&elf, &iter);
			break;
		}
	}

	if (iter.shdr.sh_type != SHT_DYNSYM) {
		pr_dbg("cannot find dynamic symbols.. skipping\n");
		ret = TRACE_NONE;
		goto out;
	}

	pr_dbg2("check trace functions in %s\n", filename);

	elf_for_each_dynamic_symbol(&elf, &iter) {
		elf_get_symbol(&elf, &iter, iter.i);
		name = elf_get_name(&elf, &iter, iter.sym.st_name);

		/* undefined function is ok here */
		if (elf_symbol_type(&iter.sym) != STT_FUNC &&
		    elf_symbol_type(&iter.sym) != STT_GNU_IFUNC)
			continue;

		for (i = 0; i < ARRAY_SIZE(trace_funcs); i++) {
			if (!strcmp(name, trace_funcs[i])) {
				ret = (i == 0) ? TRACE_CYGPROF : TRACE_MCOUNT;
				goto out;
			}
		}
	}

	ret = TRACE_NONE;

out:
	elf_finish(&elf);
	return ret;
}

struct uftrace_mmap *find_map_by_name(struct symtabs *symtabs,
				      const char *prefix)
{
	struct uftrace_mmap *map;
	char *mod_name;

	for_each_map(symtabs, map) {
		mod_name = strrchr(map->libname, '/');
		if (mod_name == NULL)
			mod_name = map->libname;
		else
			mod_name++;

		if (!strncmp(mod_name, prefix, strlen(prefix)))
			return map;
	}
	return NULL;
}

void load_symtabs(struct symtabs *symtabs, const char *dirname,
		  const char *filename)
{
	uint64_t offset = 0;

	if (symtabs->loaded)
		return;

	symtabs->dirname = dirname;
	symtabs->filename = filename;

	if (symtabs->flags & SYMTAB_FL_ADJ_OFFSET)
		offset = symtabs->exec_base;

	/* try .sym files first */
	if (dirname != NULL && (symtabs->flags & SYMTAB_FL_USE_SYMFILE)) {
		char *symfile = NULL;

		xasprintf(&symfile, "%s/%s.sym", dirname, basename(filename));
		if (access(symfile, F_OK) == 0)
			load_symbol_file(symtabs, symfile, offset);

		free(symfile);
	}

	/*
	 * skip loading unnecessary symbols (when no filter is used in
	 * the libmcount).  but it still needs to load dynamic symbols
	 * for plthook anyway.
	 */
	if (symtabs->symtab.nr_sym == 0 &&
	    !(symtabs->flags & SYMTAB_FL_SKIP_NORMAL)) {
		load_symtab(&symtabs->symtab, filename, offset, symtabs->flags);
		update_symtab_using_dynsym(&symtabs->symtab, filename, offset,
					   symtabs->flags);
	}
	if (symtabs->dsymtab.nr_sym == 0 &&
	    !(symtabs->flags & SYMTAB_FL_SKIP_DYNAMIC))
		load_dynsymtab(&symtabs->dsymtab, filename, offset, symtabs->flags);

	symtabs->loaded = true;
}

static int load_module_symbol_file(struct symtab *symtab, const char *symfile,
				   uint64_t offset)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	unsigned int i;
	unsigned int grow = SYMTAB_GROW;
	char allowed_types[] = "?TtwPKDdvu";
	uint64_t prev_addr = -1;
	char prev_type = 'X';

	fp = fopen(symfile, "r");
	if (fp == NULL) {
		pr_dbg("reading %s failed: %m\n", symfile);
		return -1;
	}

	pr_dbg2("loading symbols from %s: offset = %lx\n", symfile, offset);
	while (getline(&line, &len, fp) > 0) {
		struct sym *sym;
		uint64_t addr;
		char type;
		char *name;
		char *pos;

		if (*line == '#') {
			if (!strncmp(line, "# symbols: ", 11)) {
				addr = strtoull(line + 11, &pos, 10);
				symtab->nr_alloc = addr;

				addr *= sizeof(*sym);
				symtab->sym = xrealloc(symtab->sym, addr);
			}
			continue;
		}

		pos = strchr(line, '\n');
		if (pos)
			*pos = '\0';

		addr = strtoull(line, &pos, 16);

		if (*pos++ != ' ') {
			pr_dbg2("invalid symbol file format before type\n");
			continue;
		}
		type = *pos++;

		if (*pos++ != ' ') {
			pr_dbg2("invalid symbol file format after type\n");
			continue;
		}
		name = pos;

		/*
		 * remove kernel module if any.
		 *   ex)  btrfs_end_transaction_throttle     [btrfs]
		 */
		pos = strchr(name, '\t');
		if (pos)
			*pos = '\0';

		if (addr == prev_addr && type == prev_type) {
			sym = &symtab->sym[symtab->nr_sym - 1];

			/* for kernel symbols, replace SyS_xxx to sys_xxx */
			if (!strncmp(sym->name, "SyS_", 4) &&
			    !strncmp(name, "sys_", 4) &&
			    !strcmp(sym->name + 4, name + 4))
				strncpy(sym->name, name, 4);

			/* prefer x64 syscall names than 32 bit ones */
			if (!strncmp(sym->name, "__ia32", 6) &&
			    !strncmp(name, "__x64", 5) &&
			    !strcmp(sym->name + 6, name + 5))
				strcpy(sym->name, name);

			pr_dbg2("skip duplicated symbols: %s\n", name);
			continue;
		}

		if (strchr(allowed_types, type) == NULL)
			continue;

		/*
		 * it should be updated after the type check
		 * otherwise, it might access invalid sym
		 * in the above.
		 */
		prev_addr = addr;
		prev_type = type;

		if (symtab->nr_sym >= symtab->nr_alloc) {
			if (symtab->nr_alloc >= grow * 4)
				grow *= 2;
			symtab->nr_alloc += grow;
			symtab->sym = xrealloc(symtab->sym,
					       symtab->nr_alloc * sizeof(*sym));
		}

		sym = &symtab->sym[symtab->nr_sym++];

		sym->addr = addr + offset;
		sym->type = type;
		sym->name = demangle(name);
		sym->size = 0;

		pr_dbg3("[%zd] %c %lx + %-5u %s\n", symtab->nr_sym,
			sym->type, sym->addr, sym->size, sym->name);

		if (symtab->nr_sym > 1)
			sym[-1].size = sym->addr - sym[-1].addr;
	}
	free(line);

	qsort(symtab->sym, symtab->nr_sym, sizeof(*symtab->sym), addrsort);

	symtab->sym_names = xmalloc(sizeof(*symtab->sym_names) * symtab->nr_sym);

	for (i = 0; i < symtab->nr_sym; i++)
		symtab->sym_names[i] = &symtab->sym[i];
	qsort(symtab->sym_names, symtab->nr_sym, sizeof(*symtab->sym_names),
	      namesort);

	symtab->name_sorted = true;

	fclose(fp);
	return 0;
}

static void load_module_symbol(struct symtabs *symtabs, struct uftrace_module *m)
{
	unsigned flags = symtabs->flags;
	struct symtab dsymtab = {};

	if (flags & SYMTAB_FL_USE_SYMFILE) {
		char *symfile = NULL;

		xasprintf(&symfile, "%s/%s.sym",
			  symtabs->dirname, basename(m->name));
		if (access(symfile, F_OK) == 0) {
			load_module_symbol_file(&m->symtab, symfile, 0);
		}

		free(symfile);

		if (m->symtab.nr_sym)
			return;
	}

	/*
	 * Currently it uses a single symtab for both normal symbols
	 * and dynamic symbols.  Maybe it can be changed later to
	 * support more sophisticated symbol handling.
	 */
	load_symtab(&m->symtab, m->name, 0, flags);
	load_dynsymtab(&dsymtab, m->name, 0, flags);
	merge_symtabs(&m->symtab, &dsymtab);
	update_symtab_using_dynsym(&m->symtab, m->name, 0, flags);

}

struct uftrace_module * load_module_symtab(struct symtabs *symtabs,
					   const char *mod_name)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &modules.rb_node;
	struct uftrace_module *m;
	int pos;

	while (*p) {
		parent = *p;
		m = rb_entry(parent, struct uftrace_module, node);

		pos = strcmp(m->name, mod_name);
		if (pos == 0)
			return m;

		if (pos < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	m = xzalloc(sizeof(*m) + strlen(mod_name) + 1);
	strcpy(m->name, mod_name);
	load_module_symbol(symtabs, m);
	INIT_LIST_HEAD(&m->dinfo.files);

	rb_link_node(&m->node, parent, p);
	rb_insert_color(&m->node, &modules);

	return m;
}

void unload_module_symtabs(void)
{
	struct rb_node *n;
	struct uftrace_module *mod;

	while (!RB_EMPTY_ROOT(&modules)) {
		n = rb_first(&modules);
		rb_erase(n, &modules);

		mod = rb_entry(n, typeof (*mod), node);
		unload_symtab(&mod->symtab);
		free(mod);
	}
}

void load_module_symtabs(struct symtabs *symtabs)
{
	struct uftrace_mmap *map;
	static const char * const skip_libs[] = {
		/* uftrace internal libraries */
		"libmcount.so",
		"libmcount-fast.so",
		"libmcount-single.so",
		"libmcount-fast-single.so",
	};
	static const char libstdcpp6[] = "libstdc++.so.6";
	size_t k;
	unsigned long flags = symtabs->flags;
	const char *exec_path = symtabs->filename;
	bool check_cpp = false;
	bool needs_cpp = false;

	if (flags & SYMTAB_FL_USE_SYMFILE) {
		/* just use the symfile if it's already saved */
		check_cpp = true;
		needs_cpp = true;
	}

	for_each_map(symtabs, map) {
		struct symtab dsymtab = {};
		const char *libname = basename(map->libname);
		bool skip = false;

		for (k = 0; k < ARRAY_SIZE(skip_libs); k++) {
			if (!strcmp(libname, skip_libs[k])) {
				skip = true;
				break;
			}
		}

		if (skip)
			continue;

		if (exec_path == NULL)
			exec_path = map->libname;

		if (!check_cpp) {
			if (has_dependency(exec_path, libstdcpp6))
				needs_cpp = true;

			check_cpp = true;
		}

		/* load symbols from libstdc++.so only if it's written in C++ */
		if (!strncmp(libname, libstdcpp6, strlen(libstdcpp6))) {
			if (!needs_cpp)
				continue;
		}

		map->mod = load_module_symtab(symtabs, map->libname);
		if (map->mod && map->mod->symtab.nr_sym)
			continue;

		pr_dbg2("load module symbol table: %s\n", map->libname);

		if (flags & SYMTAB_FL_USE_SYMFILE) {
			char *symfile = NULL;

			xasprintf(&symfile, "%s/%s.sym",
				  symtabs->dirname, libname);
			if (access(symfile, F_OK) == 0) {
				load_module_symbol_file(&map->symtab, symfile,
							map->start);
			}

			free(symfile);

			if (map->symtab.nr_sym)
				continue;
		}

		/*
		 * Currently it uses a single symtab for both normal symbols
		 * and dynamic symbols.  Maybe it can be changed later to
		 * support more sophisticated symbol handling.
		 */
		load_symtab(&map->symtab, map->libname, map->start, flags);
		load_dynsymtab(&dsymtab, map->libname, map->start, flags);
		merge_symtabs(&map->symtab, &dsymtab);
		update_symtab_using_dynsym(&map->symtab, map->libname,
					   map->start, flags);
	}
}

int load_symbol_file(struct symtabs *symtabs, const char *symfile,
		     uint64_t offset)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	unsigned int i;
	unsigned int grow = SYMTAB_GROW;
	struct symtab *stab = &symtabs->symtab;
	char allowed_types[] = "?TtwPKDdvu";
	uint64_t prev_addr = -1;
	char prev_type = 'X';

	fp = fopen(symfile, "r");
	if (fp == NULL) {
		pr_dbg("reading %s failed: %m\n", symfile);
		return -1;
	}

	pr_dbg2("loading symbols from %s: offset = %lx\n", symfile, offset);
	while (getline(&line, &len, fp) > 0) {
		struct sym *sym;
		uint64_t addr;
		char type;
		char *name;
		char *pos;

		if (*line == '#') {
			if (!strncmp(line, "# symbols: ", 11)) {
				stab = &symtabs->symtab;

				addr = strtoull(line + 11, &pos, 10);
				stab->nr_alloc = addr;

				addr *= sizeof(*sym);
				stab->sym = xrealloc(stab->sym, addr);
			}
			if (!strncmp(line, "# plt symbols: ", 15)) {
				stab = &symtabs->dsymtab;

				addr = strtoull(line + 15, &pos, 10);
				stab->nr_alloc = addr;

				addr *= sizeof(*sym);
				stab->sym = xrealloc(stab->sym, addr);
			}
			continue;
		}

		pos = strchr(line, '\n');
		if (pos)
			*pos = '\0';

		addr = strtoull(line, &pos, 16);

		if (*pos++ != ' ') {
			pr_dbg2("invalid symbol file format before type\n");
			continue;
		}
		type = *pos++;

		if (*pos++ != ' ') {
			pr_dbg2("invalid symbol file format after type\n");
			continue;
		}
		name = pos;

		/*
		 * remove kernel module if any.
		 *   ex)  btrfs_end_transaction_throttle     [btrfs]
		 */
		pos = strchr(name, '\t');
		if (pos)
			*pos = '\0';

		if (addr == prev_addr && type == prev_type) {
			sym = &stab->sym[stab->nr_sym - 1];

			/* for kernel symbols, replace SyS_xxx to sys_xxx */
			if (!strncmp(sym->name, "SyS_", 4) &&
			    !strncmp(name, "sys_", 4) &&
			    !strcmp(sym->name + 4, name + 4))
				strncpy(sym->name, name, 4);

			/* prefer x64 syscall names than 32 bit ones */
			if (!strncmp(sym->name, "__ia32", 6) &&
			    !strncmp(name, "__x64", 5) &&
			    !strcmp(sym->name + 6, name + 5))
				strcpy(sym->name, name);

			pr_dbg2("skip duplicated symbols: %s\n", name);
			continue;
		}

		if (strchr(allowed_types, type) == NULL)
			continue;

		/*
		 * it should be updated after the type check
		 * otherwise, it might access invalid sym
		 * in the above.
		 */
		prev_addr = addr;
		prev_type = type;

		if (type == ST_PLT_FUNC)
			stab = &symtabs->dsymtab;
		else
			stab = &symtabs->symtab;

		if (stab->nr_sym >= stab->nr_alloc) {
			if (stab->nr_alloc >= grow * 4)
				grow *= 2;
			stab->nr_alloc += grow;
			stab->sym = xrealloc(stab->sym,
					     stab->nr_alloc * sizeof(*sym));
		}

		sym = &stab->sym[stab->nr_sym++];

		sym->addr = addr + offset;
		sym->type = type;
		sym->name = demangle(name);
		sym->size = 0;

		pr_dbg3("[%zd] %c %"PRIx64" + %-5u %s\n", stab->nr_sym,
			sym->type, sym->addr, sym->size, sym->name);

		if (stab->nr_sym > 1)
			sym[-1].size = sym->addr - sym[-1].addr;
	}
	free(line);
	pr_dbg2("loaded %zd normal + %zd dynamic symbols\n",
		symtabs->symtab.nr_sym, symtabs->dsymtab.nr_sym);

	stab = &symtabs->symtab;
	qsort(stab->sym, stab->nr_sym, sizeof(*stab->sym), addrsort);

	stab->sym_names = xmalloc(sizeof(*stab->sym_names) * stab->nr_sym);

	for (i = 0; i < stab->nr_sym; i++)
		stab->sym_names[i] = &stab->sym[i];
	qsort(stab->sym_names, stab->nr_sym, sizeof(*stab->sym_names), namesort);

	stab->name_sorted = true;

	/*
	 * sort dynamic symbol while reserving original index in ->sym_names[]
	 */
	stab = &symtabs->dsymtab;
	if (stab->nr_sym == 0)
		goto out;

	sort_dynsymtab(stab);

out:
	fclose(fp);
	return 0;
}

static bool symbol_is_func(struct sym *sym)
{
	switch (sym->type) {
	case ST_LOCAL_FUNC:
	case ST_GLOBAL_FUNC:
	case ST_WEAK_FUNC:
	case ST_PLT_FUNC:
	case ST_KERNEL_FUNC:
		return true;

	default:
		return false;
	}
}

void save_symbol_file(struct symtabs *symtabs, const char *dirname,
		      const char *exename)
{
	FILE *fp;
	unsigned i;
	char *symfile = NULL;
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	unsigned long offset = 0;
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	struct sym *sym, *prev;

	xasprintf(&symfile, "%s/%s.sym", dirname, basename(exename));

	fp = fopen(symfile, "wx");
	if (fp == NULL) {
		if (errno == EEXIST)
			return;
		pr_err("cannot open %s file", symfile);
	}

	pr_dbg2("saving symbols to %s\n", symfile);

	if (elf_init(exename, &elf) < 0) {
		pr_dbg("error during open elf file: %s: %m\n", exename);
		goto do_it;
	}

	elf_for_each_phdr(&elf, &iter) {
		if (iter.phdr.p_type == PT_LOAD) {
			offset = iter.phdr.p_vaddr;
			break;
		}
	}

	/* save relative offset of symbol address */
	symtabs->flags |= SYMTAB_FL_ADJ_OFFSET;

do_it:
	fprintf(fp, "# symbols: %lu\n", stab->nr_sym);
	fprintf(fp, "# plt symbols: %lu\n", dtab->nr_sym);

	/* dynamic symbols */
	for (i = 0; i < dtab->nr_sym; i++)
		fprintf(fp, "%016"PRIx64" %c %s\n", dtab->sym_names[i]->addr - offset,
		       (char) dtab->sym_names[i]->type, dtab->sym_names[i]->name);
	/* this last entry should come from ->sym[] to know the real end */
	if (i > 0) {
		fprintf(fp, "%016"PRIx64" %c %s\n", dtab->sym[i-1].addr + dtab->sym[i-1].size - offset,
			(char) dtab->sym[i-1].type, "__dynsym_end");
	}

	/* normal symbols */
	prev = NULL;
	for (i = 0; i < stab->nr_sym; i++) {
		sym = &stab->sym[i];

		if (prev) {
			if (symbol_is_func(prev) && !symbol_is_func(sym)) {
				fprintf(fp, "%016"PRIx64" %c %s\n",
					prev->addr + prev->size - offset,
					(char)prev->type, "__func_end");
			}
		}

		fprintf(fp, "%016"PRIx64" %c %s\n", sym->addr - offset,
			(char)sym->type, sym->name);

		prev = sym;
	}
	if (prev) {
		fprintf(fp, "%016"PRIx64" %c %s\n",
			prev->addr + prev->size - offset,
			(char)prev->type, "__sym_end");
	}

	elf_finish(&elf);
	free(symfile);
	fclose(fp);
}

static void save_module_symbol_file(struct symtab *stab, const char *symfile,
				    unsigned long offset)
{
	FILE *fp;
	unsigned i;
	bool prev_was_plt = false;
	struct sym *sym, *prev;

	if (stab->nr_sym == 0)
		return;

	fp = fopen(symfile, "wx");
	if (fp == NULL) {
		if (errno == EEXIST)
			return;
		pr_err("cannot open %s file", symfile);
	}

	pr_dbg2("saving symbols to %s\n", symfile);

	fprintf(fp, "# symbols: %lu\n", stab->nr_sym);

	prev = &stab->sym[0];
	prev_was_plt = (prev->type == ST_PLT_FUNC);

	fprintf(fp, "%016"PRIx64" %c %s\n", prev->addr - offset,
		(char)prev->type, prev->name);

	/* PLT + normal symbols (in any order)*/
	for (i = 1; i < stab->nr_sym; i++) {
		sym = &stab->sym[i];

		/* mark end of the this kind of symbols */
		if ((sym->type == ST_PLT_FUNC) != prev_was_plt) {
			fprintf(fp, "%016"PRIx64" %c __%ssym_end\n",
				prev->addr + prev->size - offset,
				(char)prev->type, prev_was_plt ? "dyn" : "");
		}
		else if (symbol_is_func(prev) && !symbol_is_func(sym)) {
			fprintf(fp, "%016"PRIx64" %c %s\n",
				prev->addr + prev->size - offset,
				(char)prev->type, "__func_end");
		}

		fprintf(fp, "%016"PRIx64" %c %s\n", sym->addr - offset,
			(char)sym->type, sym->name);

		prev = sym;
		prev_was_plt = (prev->type == ST_PLT_FUNC);
	}
	
	fprintf(fp, "%016"PRIx64" %c __%ssym_end\n",
		prev->addr + prev->size - offset,
		(char)prev->type, prev_was_plt ? "dyn" : "");

	fclose(fp);
}

void save_module_symtabs(const char *dirname)
{
	struct rb_node *n = rb_first(&modules);
	struct uftrace_module *mod;
	char *symfile = NULL;

	while (n != NULL) {
		mod = rb_entry(n, typeof (*mod), node);

		xasprintf(&symfile, "%s/%s.sym", dirname,
			  basename(mod->name));

		save_module_symbol_file(&mod->symtab, symfile, 0);

		free(symfile);
		symfile = NULL;

		n = rb_next(n);
	}
}

int save_kernel_symbol(char *dirname)
{
	char *symfile = NULL;
	char buf[PATH_MAX];
	FILE *ifp, *ofp;
	ssize_t len;
	int ret = 0;

	xasprintf(&symfile, "%s/kallsyms", dirname);
	ifp = fopen("/proc/kallsyms", "r");
	ofp = fopen(symfile, "w");

	if (ifp == NULL || ofp == NULL)
		pr_err("cannot open kernel symbol file");

	while ((len = fread(buf, 1, sizeof(buf), ifp)) > 0)
		fwrite(buf, 1, len, ofp);

	if (len < 0)
		ret = len;

	fclose(ifp);
	fclose(ofp);
	free(symfile);
	return ret;
}

int load_kernel_symbol(char *dirname)
{
	unsigned i;
	char *symfile = NULL;

	/* abuse it for checking symbol loading */
	if (kernel.node.rb_parent_color)
		return 0;

	xasprintf(&symfile, "%s/kallsyms", dirname);
	if (load_module_symbol_file(&kernel.symtab, symfile, 0) < 0) {
		free(symfile);
		return -1;
	}

	for (i = 0; i < kernel.symtab.nr_sym; i++)
		kernel.symtab.sym[i].type = ST_KERNEL_FUNC;

	kernel.node.rb_parent_color = 1;
	free(symfile);
	return 0;
}

struct symtab * get_kernel_symtab(void)
{
	return &kernel.symtab;
}

struct uftrace_module * get_kernel_module(void)
{
	return &kernel;
}

void build_dynsym_idxlist(struct symtab *dsymtab, struct dynsym_idxlist *idxlist,
			  const char *symlist[], unsigned symcount)
{
	unsigned i, k;
	unsigned *idx = NULL;
	unsigned count = 0;

	for (i = 0; i < dsymtab->nr_sym; i++) {
		for (k = 0; k < symcount; k++) {
			if (!strcmp(dsymtab->sym_names[i]->name, symlist[k])) {
				idx = xrealloc(idx, (count + 1) * sizeof(*idx));

				idx[count++] = i;
				break;
			}
		}
	}

	idxlist->idx   = idx;
	idxlist->count = count;
}

void destroy_dynsym_idxlist(struct dynsym_idxlist *idxlist)
{
	free(idxlist->idx);
	idxlist->idx = NULL;
	idxlist->count = 0;
}

bool check_dynsym_idxlist(struct dynsym_idxlist *idxlist, unsigned idx)
{
	unsigned i;

	for (i = 0; i < idxlist->count; i++) {
		if (idx == idxlist->idx[i])
			return true;
	}
	return false;
}

struct sym * find_dynsym(struct symtabs *symtabs, size_t idx)
{
	struct symtab *dsymtab = &symtabs->dsymtab;

	if (idx >= dsymtab->nr_sym)
		return NULL;

	/* ->sym_names are sorted by original index */
	return dsymtab->sym_names[idx];
}

size_t count_dynsym(struct symtabs *symtabs)
{
	struct symtab *dsymtab = &symtabs->dsymtab;

	return dsymtab->nr_sym;
}

static bool check_map_symtab(struct symtab *stab, uint64_t addr)
{
	uint64_t start, end;

	if (stab == NULL || stab->nr_sym == 0)
		return false;

	start = stab->sym[0].addr;
	end = stab->sym[stab->nr_sym - 1].addr + stab->sym[stab->nr_sym - 1].size;

	return (start <= addr && addr < end);
}

struct uftrace_mmap * find_map(struct symtabs *symtabs, uint64_t addr)
{
	struct uftrace_mmap *map;

	if (is_kernel_address(symtabs, addr))
		return MAP_KERNEL;

	if (check_map_symtab(&symtabs->symtab, addr) ||
	    check_map_symtab(&symtabs->dsymtab, addr))
		return MAP_MAIN;

	for_each_map(symtabs, map) {
		if (map->start <= addr && addr < map->end)
			return map;
	}
	return NULL;
}

struct uftrace_mmap * find_symbol_map(struct symtabs *symtabs, char *name)
{
	struct uftrace_mmap *map;

	if (find_symname(&symtabs->symtab, name))
		return MAP_MAIN;

	for_each_map(symtabs, map) {
		struct sym *sym;

		if (map->mod != NULL) {
			sym = find_symname(&map->mod->symtab, name);
			if (sym && sym->type != ST_PLT_FUNC)
				return map;
		}
	}
	return NULL;
}

struct sym * find_symtabs(struct symtabs *symtabs, uint64_t addr)
{
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	struct uftrace_mmap *map;
	struct sym *sym = NULL;

	map = find_map(symtabs, addr);
	if (map == MAP_KERNEL) {
		struct symtab *ktab = get_kernel_symtab();
		uint64_t kaddr = get_kernel_address(symtabs, addr);

		if (!ktab)
			return NULL;

		sym = bsearch(&kaddr, ktab->sym, ktab->nr_sym,
			      sizeof(*ktab->sym), addrfind);
		return sym;
	}

	if (map == MAP_MAIN) {
		/* try dynamic symbols first */
		sym = bsearch(&addr, dtab->sym, dtab->nr_sym,
			      sizeof(*sym), addrfind);
		if (sym)
			return sym;

		/*
		 * normal symbol table may overlap with dynamic symbols
		 * since it has data symbols too.
		 */
		sym = bsearch(&addr, stab->sym, stab->nr_sym,
			      sizeof(*sym), addrfind);
		goto out;
	}

	if (map != NULL) {
		if (map->mod == NULL) {
			map->mod = load_module_symtab(symtabs, map->libname);
			if (map->mod == NULL)
				return NULL;
		}

		/*
		 * use relative address for module symtab
		 * since mappings can be loaded at any address
		 * for multiple sessions
		 */
		addr -= map->start;

		stab = &map->mod->symtab;
		sym = bsearch(&addr, stab->sym, stab->nr_sym,
			      sizeof(*sym), addrfind);
	}

out:
	if (sym != NULL) {
		/* these dummy symbols are not part of real symbol table */
		if (!strcmp(sym->name, "__sym_end") ||
		    !strcmp(sym->name, "__dynsym_end") ||
		    !strcmp(sym->name, "__func_end"))
			sym = NULL;
	}

	return sym;
}

struct sym * find_sym(struct symtab *symtab, uint64_t addr)
{
	struct sym *sym;

	sym =  bsearch(&addr, symtab->sym, symtab->nr_sym,
		       sizeof(struct sym), addrfind);

	if (sym != NULL) {
		/* these dummy symbols are not part of real symbol table */
		if (!strcmp(sym->name, "__sym_end") ||
		    !strcmp(sym->name, "__dynsym_end") ||
		    !strcmp(sym->name, "__func_end"))
			sym = NULL;
	}

	return sym;
}

struct sym * find_symname(struct symtab *symtab, const char *name)
{
	size_t i;

	if (symtab->name_sorted) {
		struct sym **psym;

		psym = bsearch(name, symtab->sym_names, symtab->nr_sym,
			       sizeof(*psym), namefind);
		if (psym)
			return *psym;

		return NULL;
	}

	for (i = 0; i < symtab->nr_sym; i++) {
		struct sym *sym = &symtab->sym[i];

		if (!strcmp(name, sym->name))
			return sym;
	}

	return NULL;
}

char *symbol_getname(struct sym *sym, uint64_t addr)
{
	char *name;

	if (sym == NULL) {
		xasprintf(&name, "<%"PRIx64">", addr);
		return name;
	}

	return sym->name;
}

/* must be used in pair with symbol_getname() */
void symbol_putname(struct sym *sym, char *name)
{
	if (sym != NULL)
		return;
	free(name);
}

char *symbol_getname_offset(struct sym *sym, uint64_t addr)
{
	char *name;

	if (addr == sym->addr)
		name = xstrdup(sym->name);
	else if (sym->addr < addr && addr < sym->addr + sym->size)
		xasprintf(&name, "%s+%"PRIu64, sym->name, addr - sym->addr);
	else
		name = xstrdup("<unknown>");

	/* the return string has to be free-ed after use. */
	return name;
}

void print_symtabs(struct symtabs *symtabs)
{
	size_t i;
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	char *name;

	pr_out("Normal symbols\n");
	pr_out("==============\n");
	for (i = 0; i < stab->nr_sym; i++) {
		struct sym *sym = &stab->sym[i];

		name = symbol_getname(sym, sym->addr);
		pr_out("[%2zd] %#"PRIx64": %s (size: %u)\n",
		       i, sym->addr, name, sym->size);
		symbol_putname(sym, name);
	}

	pr_out("\n\n");
	pr_out("Dynamic symbols\n");
	pr_out("===============\n");
	for (i = 0; i < dtab->nr_sym; i++) {
		struct sym *sym = &dtab->sym[i];

		name = symbol_getname(sym, sym->addr);
		pr_out("[%2zd] %#"PRIx64": %s (size: %u)\n",
		       i, sym->addr, name, sym->size);
		symbol_putname(sym, name);
	}
}

uint64_t guess_kernel_base(char *str)
{
	uint64_t addr = strtoull(str, NULL, 16);

	/*
	 * AArch64 has different memory map depending on page size and
	 * level of page table.
	 */
	if (addr < 0x40000000UL)       /* 1G:3G split */
		return 0x40000000UL;
	else if (addr < 0x80000000UL)  /* 2G:2G split */
		return 0x80000000UL;
	else if (addr < 0xB0000000UL)  /* 3G:1G split (variant) */
		return 0xB0000000UL;
	else if (addr < 0xC0000000UL)  /* 3G:1G split */
		return 0xC0000000UL;
	/* below is for 64-bit systems */
	else if (addr < 0x8000000000ULL)    /* 512G:512G split */
		return 0xFFFFFF8000000000ULL;
	else if (addr < 0x40000000000ULL)   /* 4T:4T split */
		return 0xFFFFFC0000000000ULL;
	else if (addr < 0x800000000000ULL)  /* 128T:128T split (x86_64) */
		return 0xFFFF800000000000ULL;
	else
		return 0xFFFF000000000000ULL;
}

#ifdef UNIT_TEST

TEST_CASE(symbol_load_symfile) {
	struct symtabs tabs = {
		.loaded = true,
	};
	struct symtabs test = {
		.loaded = false,
	};
	struct sym dsym[3] = {
		{ 0x400100, 256, ST_PLT_FUNC, "plt1" },
		{ 0x400200, 256, ST_PLT_FUNC, "plt2" },
		{ 0x400300, 256, ST_PLT_FUNC, "plt3" },
	};
	struct sym nsym[3] = {
		{ 0x401100, 256, ST_GLOBAL_FUNC, "first" },
		{ 0x401200, 256, ST_LOCAL_FUNC, "second" },
		{ 0x401300, 256, ST_GLOBAL_FUNC, "third" },
	};
	struct sym *sym_names[3] = { &dsym[0], &dsym[1], &dsym[2] };
	char symfile[] = "SYM.sym";
	unsigned i;

	tabs.symtab.nr_sym = ARRAY_SIZE(nsym);
	tabs.symtab.sym = nsym;
	tabs.dsymtab.nr_sym = ARRAY_SIZE(dsym);
	tabs.dsymtab.sym = dsym;
	tabs.dsymtab.sym_names = sym_names;

	/* recover from earlier failures */
	unlink(symfile);

	symfile[3] = '\0';
	save_symbol_file(&tabs, ".", symfile);

	TEST_EQ(test.symtab.nr_sym, 0U);

	symfile[3] = '.';
	TEST_EQ(load_symbol_file(&test, symfile, 0), 0);

	/* +1 for the end marker of the symbols */
	TEST_EQ(test.dsymtab.nr_sym, ARRAY_SIZE(dsym) + 1);
	for (i = 0; i < ARRAY_SIZE(dsym); i++) {
		struct sym *sym = &test.dsymtab.sym[i];

		TEST_EQ(sym->addr, dsym[i].addr);
		TEST_EQ(sym->size, dsym[i].size);
		TEST_EQ(sym->type, dsym[i].type);
		TEST_STREQ(sym->name, dsym[i].name);
	}
	TEST_STREQ("__dynsym_end", test.dsymtab.sym[3].name);

	/* +1 for the end marker of the symbols */
	TEST_EQ(test.symtab.nr_sym, ARRAY_SIZE(nsym) + 1);
	for (i = 0; i < ARRAY_SIZE(nsym); i++) {
		struct sym *sym = &test.symtab.sym[i];

		TEST_EQ(sym->addr, nsym[i].addr);
		TEST_EQ(sym->size, nsym[i].size);
		TEST_EQ(sym->type, nsym[i].type);
		TEST_STREQ(sym->name, nsym[i].name);
	}
	TEST_STREQ("__sym_end", test.symtab.sym[3].name);

	TEST_EQ(test.symtab.name_sorted, true);
	TEST_STREQ("__sym_end", test.symtab.sym_names[0]->name);

	unlink(symfile);
	return TEST_OK;
}

TEST_CASE(symbol_load_module) {
	struct symtab stab = {
		.nr_alloc = 0,
	};
	struct sym mixed_sym[] = {
		{ 0x100, 256, ST_PLT_FUNC, "plt1" },
		{ 0x200, 256, ST_PLT_FUNC, "plt2" },
		{ 0x300, 256, ST_PLT_FUNC, "plt3" },
		{ 0x1100, 256, ST_GLOBAL_FUNC, "normal1" },
		{ 0x1200, 256, ST_LOCAL_FUNC,  "normal2" },
		{ 0x1300, 256, ST_GLOBAL_FUNC, "normal3" },
	};
	struct symtab test = {
		.nr_sym = 0,
	};
	char symfile[] = "SYM.sym";
	int i;

	/* recover from earlier failures */
	unlink(symfile);

	stab.sym = mixed_sym;
	stab.nr_sym = ARRAY_SIZE(mixed_sym);

	save_module_symbol_file(&stab, symfile, 0x400000);

	TEST_EQ(load_module_symbol_file(&test, symfile, 0x400000), 0);

	/* +2 for the end markers of the symbols */
	TEST_EQ(test.nr_sym, ARRAY_SIZE(mixed_sym) + 2);
	for (i = 0; i < 3; i++) {
		struct sym *sym = &test.sym[i];

		TEST_EQ(sym->addr, stab.sym[i].addr);
		TEST_EQ(sym->size, stab.sym[i].size);
		TEST_EQ(sym->type, stab.sym[i].type);
		TEST_STREQ(sym->name, stab.sym[i].name);
	}
	TEST_STREQ("__dynsym_end", test.sym[3].name);

	for (i = 4; i < 7; i++) {
		struct sym *sym = &test.sym[i];

		TEST_EQ(sym->addr, stab.sym[i-1].addr);
		TEST_EQ(sym->size, stab.sym[i-1].size);
		TEST_EQ(sym->type, stab.sym[i-1].type);
		TEST_STREQ(sym->name, stab.sym[i-1].name);
	}
	TEST_STREQ("__sym_end", test.sym[7].name);

	unlink(symfile);
	return TEST_OK;
}

#endif /* UNIT_TEST */
