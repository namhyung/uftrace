#include <string.h>
#include <stdint.h>
#include <link.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/rbtree.h"
#include "utils/list.h"

static struct mcount_dynamic_info *mdinfo;
static struct mcount_dynamic_stats {
	int total;
	int failed;
	int skipped;
	int nomatch;
	int unpatch;
} stats;

#define PAGE_SIZE   4096
#define CODE_CHUNK  (PAGE_SIZE * 8)

struct code_page {
	struct list_head	list;
	void			*page;
	int			pos;
};

static LIST_HEAD(code_pages);
static struct rb_root code_tree = RB_ROOT;

static struct mcount_orig_insn *lookup_code(struct rb_root *root,
					    unsigned long addr, bool create)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct mcount_orig_insn *iter;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct mcount_orig_insn, node);

		if (iter->addr == addr)
			return iter;

		if (iter->addr > addr)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	if (!create)
		return NULL;

	iter = xmalloc(sizeof(*iter));
	iter->addr = addr;

	rb_link_node(&iter->node, parent, p);
	rb_insert_color(&iter->node, root);
	return iter;
}

struct mcount_orig_insn *mcount_save_code(struct mcount_disasm_info *info,
					  void *jmp_insn, unsigned jmp_size)
{
	struct code_page *cp = NULL;
	struct mcount_orig_insn *orig;
	const int patch_size = ALIGN(info->copy_size + jmp_size, 32);

	if (!list_empty(&code_pages))
		cp = list_last_entry(&code_pages, struct code_page, list);

	if (cp == NULL || (cp->pos + patch_size > CODE_CHUNK)) {
		cp = xmalloc(sizeof(*cp));
		cp->page = mmap(NULL, CODE_CHUNK, PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (cp->page == MAP_FAILED)
			pr_err("mmap code page failed");
		cp->pos = 0;

		list_add_tail(&cp->list, &code_pages);
	}

	orig = lookup_code(&code_tree, info->addr, true);
	orig->insn = cp->page + cp->pos;

	memcpy(orig->insn, info->insns, info->copy_size);
	memcpy(orig->insn + info->copy_size, jmp_insn, jmp_size);

	cp->pos += patch_size;
	return orig;
}

void mcount_freeze_code(void)
{
	struct code_page *cp;

	list_for_each_entry(cp, &code_pages, list)
		mprotect(cp->page, CODE_CHUNK, PROT_READ|PROT_EXEC);
}

void *mcount_find_code(unsigned long addr)
{
	struct mcount_orig_insn *orig;

	orig = lookup_code(&code_tree, addr, false);
	if (orig == NULL)
		return NULL;

	return orig->insn;
}

/* dummy functions (will be overridden by arch-specific code) */
__weak int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	return -1;
}

__weak void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
}

__weak int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			     struct mcount_disasm_engine *disasm,
			     unsigned min_size)
{
	return -1;
}

__weak int mcount_unpatch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			       struct mcount_disasm_engine *disasm)
{
	return -1;
}

__weak void mcount_arch_find_module(struct mcount_dynamic_info *mdi,
				    struct symtab *symtab)
{
	mdi->arch = NULL;
}

__weak void mcount_arch_dynamic_recover(struct mcount_dynamic_info *mdi,
					struct mcount_disasm_engine *disasm)
{
}

__weak void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
}

__weak void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
}

struct find_module_data {
	struct symtabs *symtabs;
	bool needs_modules;
};

/* callback for dl_iterate_phdr() */
static int find_dynamic_module(struct dl_phdr_info *info, size_t sz, void *data)
{
	struct mcount_dynamic_info *mdi;
	struct find_module_data *fmd = data;
	struct symtabs *symtabs = fmd->symtabs;
	struct uftrace_mmap *map;
	bool base_addr_set = false;
	unsigned i;

	mdi = xzalloc(sizeof(*mdi));

	for (i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type != PT_LOAD)
			continue;

		if (!base_addr_set) {
			mdi->base_addr = info->dlpi_phdr[i].p_vaddr;
			base_addr_set = true;
		}

		if (!(info->dlpi_phdr[i].p_flags & PF_X))
			continue;

		/* find address and size of code segment */
		mdi->text_addr = info->dlpi_phdr[i].p_vaddr;
		mdi->text_size = info->dlpi_phdr[i].p_memsz;
		break;
	}
	mdi->base_addr += info->dlpi_addr;
	mdi->text_addr += info->dlpi_addr;

	map = find_map(symtabs, mdi->base_addr);
	if (map && map->mod) {
		mdi->map = map;
		mcount_arch_find_module(mdi, &map->mod->symtab);

		mdi->next = mdinfo;
		mdinfo = mdi;
	}
	else {
		free(mdi);
	}

	return !fmd->needs_modules;
}

static void prepare_dynamic_update(struct mcount_disasm_engine *disasm,
				   struct symtabs *symtabs,
				   bool needs_modules)
{
	struct find_module_data fmd = {
		.symtabs = symtabs,
		.needs_modules = needs_modules,
	};

	mcount_disasm_init(disasm);
	dl_iterate_phdr(find_dynamic_module, &fmd);
}

struct mcount_dynamic_info *setup_trampoline(struct uftrace_mmap *map)
{
	struct mcount_dynamic_info *mdi;

	for (mdi = mdinfo; mdi != NULL; mdi = mdi->next) {
		if (map == mdi->map)
			break;
	}

	if (mdi != NULL && mdi->trampoline == 0) {
		if (mcount_setup_trampoline(mdi) < 0)
			mdi = NULL;
	}

	return mdi;
}

struct patt_list {
	struct list_head list;
	struct uftrace_pattern patt;
	char *module;
	bool positive;
};

static bool match_pattern_list(struct list_head *patterns,
			       struct uftrace_mmap *map,
			       char *sym_name)
{
	struct patt_list *pl;
	bool ret = false;

	list_for_each_entry(pl, patterns, list) {
		char *libname = basename(map->libname);

		if (strncmp(libname, pl->module, strlen(pl->module)))
			continue;

		if (match_filter_pattern(&pl->patt, sym_name))
			ret = pl->positive;
	}

	return ret;
}

static int do_dynamic_update(struct symtabs *symtabs, char *patch_funcs,
			     enum uftrace_pattern_type ptype,
			     struct mcount_disasm_engine *disasm,
			     unsigned min_size)
{
	struct uftrace_mmap *map;
	struct symtab *symtab;
	struct strv funcs = STRV_INIT;
	char *def_mod;
	char *name;
	int j;
	/* skip special startup (csu) functions */
	const char *csu_skip_syms[] = {
		"_start",
		"__libc_csu_init",
		"__libc_csu_fini",
	};
	LIST_HEAD(patterns);
	struct patt_list *pl;
	bool all_negative = true;

	if (patch_funcs == NULL)
		return 0;

	def_mod = basename(symtabs->exec_map->libname);
	strv_split(&funcs, patch_funcs, ";");

	strv_for_each(&funcs, name, j) {
		char *delim;

		pl = xzalloc(sizeof(*pl));

		if (name[0] == '!')
			name++;
		else {
			pl->positive = true;
			all_negative = false;
		}

		delim = strchr(name, '@');
		if (delim == NULL) {
			pl->module = xstrdup(def_mod);
		}
		else {
			*delim = '\0';
			pl->module = xstrdup(++delim);
		}

		init_filter_pattern(ptype, &pl->patt, name);
		list_add_tail(&pl->list, &patterns);
	}

	/* prepend match-all pattern, if all patterns are negative */
	if (all_negative) {
		pl = xzalloc(sizeof(*pl));
		pl->positive = true;
		pl->module = xstrdup(def_mod);

		if (ptype == PATT_REGEX)
			init_filter_pattern(ptype, &pl->patt, ".");
		else
			init_filter_pattern(PATT_GLOB, &pl->patt, "*");

		list_add(&pl->list, &patterns);
	}

	for_each_map(symtabs, map) {
		bool found;
		bool csu_skip;
		unsigned i, k;
		struct sym *sym;
		struct mcount_dynamic_info *mdi;

		/* TODO: filter out unsuppported libs */
		mdi = setup_trampoline(map);
		if (mdi == NULL)
			continue;

		symtab = &map->mod->symtab;

		for (i = 0; i < symtab->nr_sym; i++) {
			sym = &symtab->sym[i];

			csu_skip = false;
			for (k = 0; k < ARRAY_SIZE(csu_skip_syms); k++) {
				if (!strcmp(sym->name, csu_skip_syms[k])) {
					csu_skip = true;
					break;
				}
			}
			if (csu_skip)
				continue;

			if (sym->type != ST_LOCAL_FUNC &&
			    sym->type != ST_GLOBAL_FUNC)
				continue;

			if (!match_pattern_list(&patterns, map, sym->name)) {
				if (mcount_unpatch_func(mdi, sym, disasm) == 0)
					stats.unpatch++;
				continue;
			}

			found = true;
			switch (mcount_patch_func(mdi, sym, disasm, min_size)) {
			case INSTRUMENT_FAILED:
				stats.failed++;
				break;
			case INSTRUMENT_SKIPPED:
				stats.skipped++;
				break;
			case INSTRUMENT_SUCCESS:
			default:
				break;
			}
			stats.total++;
		}

		if (!found)
			stats.nomatch++;
	}

	if (stats.failed + stats.skipped + stats.nomatch == 0) {
		pr_dbg("patched all (%d) functions in '%s'\n",
		       stats.total, basename(symtabs->filename));
	}

	while (!list_empty(&patterns)) {
		struct patt_list *pl;

		pl = list_first_entry(&patterns, struct patt_list, list);

		list_del(&pl->list);
		free(pl->module);
		free(pl);
	}

	strv_free(&funcs);
	return 0;
}

static void finish_dynamic_update(struct mcount_disasm_engine *disasm)
{
	struct mcount_dynamic_info *mdi, *tmp;

	mdi = mdinfo;
	while (mdi) {
		tmp = mdi->next;

		mcount_arch_dynamic_recover(mdi, disasm);
		mcount_cleanup_trampoline(mdi);
		free(mdi);

		mdi = tmp;
	}

	mcount_disasm_finish(disasm);
	mcount_freeze_code();
}

/* do not use floating-point in libmcount */
static int calc_percent(int n, int total, int *rem)
{
	int quot = 100 * n / total;

	*rem = (100 * n - quot * total) * 100 / total;
	return quot;
}

int mcount_dynamic_update(struct symtabs *symtabs, char *patch_funcs,
			  enum uftrace_pattern_type ptype,
			  struct mcount_disasm_engine *disasm)
{
	int ret = 0;
	char *size_filter;
	unsigned min_size = 0;
	bool needs_modules = !!strchr(patch_funcs, '@');

	prepare_dynamic_update(disasm, symtabs, needs_modules);

	size_filter = getenv("UFTRACE_PATCH_SIZE");
	if (size_filter != NULL)
		min_size = strtoul(size_filter, NULL, 0);

	ret = do_dynamic_update(symtabs, patch_funcs, ptype, disasm, min_size);

	if (stats.total && stats.failed) {
		int success = stats.total - stats.failed - stats.skipped;
		int r, q;

		pr_dbg("dynamic patch stats for '%s'\n",
		       basename(symtabs->filename));
		pr_dbg("   total: %8d\n", stats.total);
		q = calc_percent(success, stats.total, &r);
		pr_dbg(" patched: %8d (%2d.%02d%%)\n", success, q, r);
		q = calc_percent(stats.failed, stats.total, &r);
		pr_dbg("  failed: %8d (%2d.%02d%%)\n", stats.failed, q, r);
		q = calc_percent(stats.skipped, stats.total, &r);
		pr_dbg(" skipped: %8d (%2d.%02d%%)\n", stats.skipped, q, r);
		pr_dbg("no match: %8d\n", stats.nomatch);
	}

	finish_dynamic_update(disasm);
	return ret;
}
