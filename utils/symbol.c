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

#ifndef  EM_AARCH64
# define EM_AARCH64  183
#endif

static struct symtabs ksymtabs;

struct sym sched_sym = {
	.addr = EVENT_ID_PERF_SCHED_BOTH,
	.size = 1,
	.type = ST_LOCAL,
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
	unsigned grow = SYMTAB_GROW;

	if (elf_sym->st_shndx == STN_UNDEF)
		return 0;

	if (elf_sym->st_size == 0)
		return 0;

	if (elf_symbol_type(elf_sym) != STT_FUNC &&
	    elf_symbol_type(elf_sym) != STT_GNU_IFUNC)
		return 0;

	/* skip aliases */
	if (prev_sym_value == elf_sym->st_value)
		return 0;

	if (symtab->nr_sym >= symtab->nr_alloc) {
		if (symtab->nr_alloc >= grow * 4)
			grow *= 2;
		symtab->nr_alloc += grow;
		symtab->sym = xrealloc(symtab->sym,
				       symtab->nr_alloc * sizeof(*sym));
	}

	sym = &symtab->sym[symtab->nr_sym++];

	sym->addr = elf_sym->st_value + offset;
	sym->size = elf_sym->st_size;

	switch (elf_symbol_bind(elf_sym)) {
	case STB_LOCAL:
		sym->type = ST_LOCAL;
		break;
	case STB_GLOBAL:
		sym->type = ST_GLOBAL;
		break;
	case STB_WEAK:
		sym->type = ST_WEAK;
		break;
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
	unsigned grow = SYMTAB_GROW;

	elf_get_symbol(elf, iter, sym_idx);
	name = elf_get_name(elf, iter, iter->sym.st_name);

	if (*name == '\0')
		return 0;

	if (dsymtab->nr_sym >= dsymtab->nr_alloc) {
		if (dsymtab->nr_alloc >= grow * 4)
			grow *= 2;
		dsymtab->nr_alloc += grow;
		dsymtab->sym = xrealloc(dsymtab->sym,
					dsymtab->nr_alloc * sizeof(*sym));
	}

	sym = &dsymtab->sym[dsymtab->nr_sym++];

	if (elf->ehdr.e_machine == EM_ARM && iter->sym.st_value)
		sym->addr = iter->sym.st_value + offset;
	else
		sym->addr = prev_addr + plt_entsize;
	sym->size = plt_entsize;
	sym->type = ST_PLT;

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

__weak int arch_load_dynsymtab_bindnow(struct symtab *dsymtab,
				       struct uftrace_elf_data *elf,
				       unsigned long offset, unsigned long flags)
{
	return 0;
}

static int try_load_dynsymtab_bindnow(struct symtab *dsymtab,
				      struct uftrace_elf_data *elf,
				      unsigned long offset, unsigned long flags)
{
	bool bind_now = false;
	struct uftrace_elf_iter iter;

	elf_for_each_shdr(elf, &iter) {
		if (iter.shdr.sh_type == SHT_DYNAMIC)
			break;
	}

	if (iter.shdr.sh_type != SHT_DYNAMIC)
		return 0;

	elf_for_each_dynamic(elf, &iter) {
		if (iter.dyn.d_tag == DT_BIND_NOW)
			bind_now = true;
		else if ((iter.dyn.d_tag == DT_FLAGS_1) &&
			 (iter.dyn.d_un.d_val & DF_1_NOW))
			bind_now = true;
	}

	if (!bind_now)
		return 0;

	if (arch_load_dynsymtab_bindnow(dsymtab, elf, offset, flags) < 0) {
		pr_dbg("cannot load dynamic symbols for bind-now\n");
		unload_symtab(dsymtab);
		return -1;
	}

	if (!dsymtab->nr_sym)
		return 0;

	sort_dynsymtab(dsymtab);
	return 1;
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

	if (!found_dynsym || !found_dynamic || plt_addr == 0) {
		pr_dbg2("cannot find dynamic symbols.. skipping\n");
		ret = 0;
		goto out;
	}

	if (rel_type == SHT_NULL) {
		ret = try_load_dynsymtab_bindnow(dsymtab, elf, offset, flags);
		if (ret <= 0)
			pr_dbg("cannot find relocation info for PLT\n");
		goto out;
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
	pr_dbg2("loaded %zd symbols\n", dsymtab->nr_sym);

	if (dsymtab->nr_sym == 0)
		goto out;

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
		    elf_symbol_type(&iter.sym) != STT_GNU_IFUNC)
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
	struct uftrace_mmap *maps = symtabs->maps;
	char *mod_name;

	while (maps) {
		mod_name = strrchr(maps->libname, '/');
		if (mod_name == NULL)
			mod_name = maps->libname;
		else
			mod_name++;

		if (!strncmp(mod_name, prefix, strlen(prefix)))
			return maps;

		maps = maps->next;
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

void load_dlopen_symtabs(struct symtabs *symtabs, unsigned long offset,
			 const char *filename)
{
	const char *dirname = symtabs->dirname;

	if (symtabs->loaded)
		return;

	/* try .sym files first */
	if (dirname != NULL && (symtabs->flags & SYMTAB_FL_USE_SYMFILE)) {
		char *symfile = NULL;

		xasprintf(&symfile, "%s/%s.sym", dirname, basename(filename));
		if (access(symfile, F_OK) == 0)
			load_symbol_file(symtabs, symfile, offset);

		free(symfile);
	}
	if (symtabs->symtab.nr_sym == 0 &&
	    !(symtabs->flags & SYMTAB_FL_SKIP_NORMAL))
		load_symtab(&symtabs->symtab, filename, offset, symtabs->flags);
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
	char allowed_types[] = "TtwPK";
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

void load_module_symtabs(struct symtabs *symtabs)
{
	struct uftrace_mmap *maps;
	static const char * const skip_libs[] = {
		/* uftrace internal libraries */
		"libmcount.so",
		"libmcount-fast.so",
		"libmcount-single.so",
		"libmcount-fast-single.so",
	};
	size_t k;
	unsigned long flags = symtabs->flags;
	const char *exec_path = symtabs->filename;

	maps = symtabs->maps;
	while (maps) {
		struct symtab dsymtab = {};

		for (k = 0; k < ARRAY_SIZE(skip_libs); k++) {
			if (!strcmp(basename(maps->libname), skip_libs[k]))
				goto next;
		}

		if (exec_path && !strcmp(maps->libname, exec_path))
			goto next;

		pr_dbg2("load module symbol table: %s\n", maps->libname);

		if (flags & SYMTAB_FL_USE_SYMFILE) {
			char *symfile = NULL;

			xasprintf(&symfile, "%s/%s.sym",
				  symtabs->dirname, basename(maps->libname));
			if (access(symfile, F_OK) == 0) {
				load_module_symbol_file(&maps->symtab, symfile,
							maps->start);
			}

			free(symfile);

			if (maps->symtab.nr_sym)
				goto next;
		}

		/*
		 * Currently it uses a single symtab for both normal symbols
		 * and dynamic symbols.  Maybe it can be changed later to
		 * support more sophisticated symbol handling.
		 */
		load_symtab(&maps->symtab, maps->libname, maps->start, flags);
		load_dynsymtab(&dsymtab, maps->libname, maps->start, flags);
		merge_symtabs(&maps->symtab, &dsymtab);
		update_symtab_using_dynsym(&maps->symtab, maps->libname,
					   maps->start, flags);

next:
		maps = maps->next;
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
	char allowed_types[] = "TtwPK";
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

		if (type == ST_PLT)
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
	for (i = 0; i < stab->nr_sym; i++)
		fprintf(fp, "%016"PRIx64" %c %s\n", stab->sym[i].addr - offset,
		       (char) stab->sym[i].type, stab->sym[i].name);
	if (i > 0) {
		fprintf(fp, "%016"PRIx64" %c %s\n",
			stab->sym[i-1].addr + stab->sym[i-1].size - offset,
			(char) stab->sym[i-1].type, "__sym_end");
	}

	elf_finish(&elf);
	free(symfile);
	fclose(fp);
}

static void save_module_symbol(struct symtab *stab, const char *symfile,
			       unsigned long offset)
{
	FILE *fp;
	unsigned i;
	bool prev_was_plt = false;

	if (stab->nr_sym == 0)
		return;

	fp = fopen(symfile, "wx");
	if (fp == NULL) {
		if (errno == EEXIST)
			return;
		pr_err("cannot open %s file", symfile);
	}

	pr_dbg2("saving symbols to %s\n", symfile);

	prev_was_plt = (stab->sym[0].type == ST_PLT);

	/* PLT + normal symbols (in any order)*/
	for (i = 0; i < stab->nr_sym; i++) {
		struct sym *sym = &stab->sym[i];

		/* mark end of the this kind of symbols */
		if ((sym->type == ST_PLT) != prev_was_plt) {
			struct sym *prev = sym - 1;

			fprintf(fp, "%016"PRIx64" %c __%ssym_end\n",
				prev->addr + prev->size - offset,
				(char) prev->type, prev_was_plt ? "dyn" : "");
		}
		prev_was_plt = (sym->type == ST_PLT);

		fprintf(fp, "%016"PRIx64" %c %s\n", sym->addr - offset,
			(char) sym->type, sym->name);
	}
	
	struct sym *last = &stab->sym[stab->nr_sym - 1];

	fprintf(fp, "%016"PRIx64" %c __%ssym_end\n",
		last->addr + last->size - offset,
		(char) last->type, prev_was_plt ? "dyn" : "");

	fclose(fp);
}

void save_module_symtabs(struct symtabs *symtabs)
{
	char *symfile = NULL;
	struct uftrace_mmap *map;

	map = symtabs->maps;
	while (map) {
		xasprintf(&symfile, "%s/%s.sym", symtabs->dirname,
			  basename(map->libname));

		save_module_symbol(&map->symtab, symfile, map->start);

		free(symfile);
		symfile = NULL;

		map = map->next;
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

	if (ksymtabs.loaded)
		return 0;

	xasprintf(&symfile, "%s/kallsyms", dirname);
	if (load_symbol_file(&ksymtabs, symfile, 0) < 0) {
		free(symfile);
		return -1;
	}

	for (i = 0; i < ksymtabs.symtab.nr_sym; i++)
		ksymtabs.symtab.sym[i].type = ST_KERNEL;

	free(symfile);
	ksymtabs.loaded = true;
	return 0;
}

struct symtab * get_kernel_symtab(void)
{
	if (ksymtabs.loaded)
		return &ksymtabs.symtab;

	return NULL;
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
	struct uftrace_mmap *maps;

	if (is_kernel_address(symtabs, addr))
		return MAP_KERNEL;

        if (check_map_symtab(&symtabs->symtab, addr) ||
            check_map_symtab(&symtabs->dsymtab, addr))
                return MAP_MAIN;

	maps = symtabs->maps;
	while (maps) {
		if (maps->start <= addr && addr < maps->end)
			return maps;

		maps = maps->next;
	}
	return NULL;
}

struct uftrace_mmap * find_symbol_map(struct symtabs *symtabs, char *name)
{
	struct uftrace_mmap *maps;

	if (find_symname(&symtabs->symtab, name))
		return MAP_MAIN;

	maps = symtabs->maps;
	while (maps) {
		struct sym *sym;
		sym = find_symname(&maps->symtab, name);
		if (sym && sym->type != ST_PLT)
			return maps;

		maps = maps->next;
	}
	return NULL;
}

struct sym * find_symtabs(struct symtabs *symtabs, uint64_t addr)
{
	struct symtab *stab = &symtabs->symtab;
	struct symtab *dtab = &symtabs->dsymtab;
	struct uftrace_mmap *maps;
	struct sym *sym = NULL;

	maps = find_map(symtabs, addr);
	if (maps == MAP_KERNEL) {
		struct symtab *ktab = get_kernel_symtab();
		uint64_t kaddr = get_real_address(addr);

		if (!ktab)
			return NULL;

		sym = bsearch(&kaddr, ktab->sym, ktab->nr_sym,
			      sizeof(*ktab->sym), addrfind);
		return sym;
	}

	if (maps == MAP_MAIN) {
		sym = bsearch(&addr, stab->sym, stab->nr_sym,
			      sizeof(*sym), addrfind);
		if (sym)
			return sym;

		/* try dynamic symbols if failed */
		sym = bsearch(&addr, dtab->sym, dtab->nr_sym,
			      sizeof(*sym), addrfind);
		return sym;
	}

	if (maps) {
		if (maps->symtab.nr_sym == 0) {
			bool found = false;

			if (symtabs->flags & SYMTAB_FL_USE_SYMFILE) {
				char *symfile = NULL;
				unsigned long offset = 0;

				if (symtabs->flags & SYMTAB_FL_ADJ_OFFSET)
					offset = maps->start;

				xasprintf(&symfile, "%s/%s.sym", symtabs->dirname,
					  basename(maps->libname));
				if (!load_module_symbol_file(&maps->symtab,
							     symfile, offset)) {
					found = true;
				}
				free(symfile);
			}

			if (!found) {
				load_symtab(&maps->symtab, maps->libname,
					    maps->start, symtabs->flags);
			}
		}

		stab = &maps->symtab;
		sym = bsearch(&addr, stab->sym, stab->nr_sym,
			      sizeof(*sym), addrfind);
	}

	return sym;
}

struct sym * find_sym(struct symtab *symtab, uint64_t addr)
{
	return bsearch(&addr, symtab->sym, symtab->nr_sym,
		       sizeof(struct sym), addrfind);
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

uint64_t get_kernel_base(char *str)
{
	uint64_t addr = strtoull(str, NULL, 16);

	if (addr < 0x40000000UL) {
		return 0x40000000UL;
	} else if (addr < 0x80000000UL) {
		return 0x80000000UL;
	} else if (addr < 0xB0000000UL) {
		return 0xB0000000UL;
	} else if (addr < 0xC0000000UL) {
		return 0xC0000000UL;
	} else {
		return 0x800000000000ULL;
	}
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
		{ 0x400100, 256, ST_PLT, "plt1" },
		{ 0x400200, 256, ST_PLT, "plt2" },
		{ 0x400300, 256, ST_PLT, "plt3" },
	};
	struct sym nsym[3] = {
		{ 0x401100, 256, ST_GLOBAL, "first" },
		{ 0x401200, 256, ST_LOCAL, "second" },
		{ 0x401300, 256, ST_GLOBAL, "third" },
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
		{ 0x100, 256, ST_PLT, "plt1" },
		{ 0x200, 256, ST_PLT, "plt2" },
		{ 0x300, 256, ST_PLT, "plt3" },
		{ 0x1100, 256, ST_GLOBAL, "normal1" },
		{ 0x1200, 256, ST_LOCAL,  "normal2" },
		{ 0x1300, 256, ST_GLOBAL, "normal3" },
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

	save_module_symbol(&stab, symfile, 0x400000);

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
