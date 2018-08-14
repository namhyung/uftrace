#include <string.h>
#include <link.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"

static struct mcount_dynamic_info *mdinfo;
static struct mcount_dynamic_stats {
	int total;
	int failed;
	int skipped;
	int nomatch;
} stats;

/* dummy functions (will be overridden by arch-specific code) */
__weak int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	return -1;
}

__weak void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
}

__weak int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	return -1;
}

__weak void mcount_arch_find_module(struct mcount_dynamic_info *mdi)
{
	mdi->arch = NULL;
}

/* callback for dl_iterate_phdr() */
static int find_dynamic_module(struct dl_phdr_info *info, size_t sz, void *data)
{
	const char *name = info->dlpi_name;
	struct mcount_dynamic_info *mdi;
	bool base_addr_set = false;
	unsigned i;

	if ((data == NULL && name[0] == '\0') || strstr(name, data)) {
		mdi = xmalloc(sizeof(*mdi));
		mdi->mod_name = xstrdup(name);
		mdi->base_addr = 0;

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

		mdi->next = mdinfo;
		mdinfo = mdi;

		mcount_arch_find_module(mdi);

		return 1;
	}

	return 0;
}

static int prepare_dynamic_update(void)
{
	struct mcount_dynamic_info *mdi;
	int ret = 0;

	dl_iterate_phdr(find_dynamic_module, NULL);

	mdi = mdinfo;
	while (mdi) {
		ret = mcount_setup_trampoline(mdi);
		if (ret < 0)
			break;

		mdi = mdi->next;
	}
	return ret;
}

static int do_dynamic_update(struct symtabs *symtabs, char *patch_funcs,
			     enum uftrace_pattern_type ptype)
{
	char *name, *nopatched_name = NULL;
	struct symtab *symtab = &symtabs->symtab;
	struct strv funcs = STRV_INIT;
	int j;

	if (patch_funcs == NULL)
		return 0;

	strv_split(&funcs, patch_funcs, ";");

	strv_for_each(&funcs, name, j) {
		bool found = false;
		unsigned i;
		struct sym *sym;
		struct uftrace_pattern patt;

		init_filter_pattern(ptype, &patt, name);

		for (i = 0; i < symtab->nr_sym; i++) {
			sym = &symtab->sym[i];

			if (!match_filter_pattern(&patt, sym->name))
				continue;

			found = true;
			switch (mcount_patch_func(mdinfo, sym)) {
			case -1:
				stats.failed++;
				break;
			case -2:
				stats.skipped++;
				break;
			case 0:
			default:
				break;
			}
			stats.total++;
		}

		if (!found || stats.failed || stats.skipped)
			nopatched_name = name;
		if (!found)
			stats.nomatch++;

		free_filter_pattern(&patt);
	}

	if (stats.failed || stats.skipped || stats.nomatch) {
		pr_out("%s cannot be patched dynamically\n",
		       (stats.failed + stats.skipped + stats.nomatch) > 1 ?
		       "some functions" : nopatched_name);
	}

	strv_free(&funcs);
	return 0;
}

static void finish_dynamic_update(void)
{
	struct mcount_dynamic_info *mdi, *tmp;

	mdi = mdinfo;
	while (mdi) {
		tmp = mdi->next;

		mcount_cleanup_trampoline(mdi);
		free(mdi->mod_name);
		free(mdi);

		mdi = tmp;
	}
}

static float calc_percent(int n, int total)
{
	if (total == 0)
		return 0;

	return 100.0 * n / total;
}

int mcount_dynamic_update(struct symtabs *symtabs, char *patch_funcs,
			  enum uftrace_pattern_type ptype)
{
	int ret = 0;
	int success;

	if (prepare_dynamic_update() < 0) {
		pr_dbg("cannot setup dynamic tracing\n");
		return -1;
	}

	ret = do_dynamic_update(symtabs, patch_funcs, ptype);

	success = stats.total - stats.failed - stats.skipped;
	pr_dbg("dynamic update stats:\n");
	pr_dbg("   total: %8d\n", stats.total);
	pr_dbg(" patched: %8d (%.2f%%)\n", success,
	       calc_percent(success, stats.total));
	pr_dbg("  failed: %8d (%.2f%%)\n", stats.failed,
	       calc_percent(stats.failed, stats.total));
	pr_dbg(" skipped: %8d (%.2f%%)\n", stats.skipped,
	       calc_percent(stats.skipped, stats.total));
	pr_dbg("no match: %8d\n", stats.nomatch);
	finish_dynamic_update();
	return ret;
}
