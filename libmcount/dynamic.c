#include <string.h>
#include <link.h>
#include <regex.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/compiler.h"

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
	unsigned i;

	if ((data == NULL && name[0] == '\0') || strstr(name, data)) {
		mdi = xmalloc(sizeof(*mdi));
		mdi->mod_name = xstrdup(name);

		for (i = 0; i < info->dlpi_phnum; i++) {
			if (info->dlpi_phdr[i].p_type != PT_LOAD)
				continue;

			if (!(info->dlpi_phdr[i].p_flags & PF_X))
				continue;

			/* find address and size of code segment */
			mdi->addr = info->dlpi_phdr[i].p_vaddr + info->dlpi_addr;
			mdi->size = info->dlpi_phdr[i].p_memsz;
			break;
		}
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

static int do_dynamic_update(struct symtabs *symtabs, char *patch_funcs)
{
	char *str;
	char *pos, *name, *nopatched_name = NULL;
	struct symtab *symtab = &symtabs->symtab;

	if (patch_funcs == NULL)
		return 0;

	pos = str = strdup(patch_funcs);
	if (str == NULL)
		return 0;

	name = strtok(pos, ";");
	while (name) {
		bool is_regex;
		bool found = false;
		regex_t re;
		unsigned i;
		struct sym *sym;

		is_regex = strpbrk(name, REGEX_CHARS);
		if (is_regex) {
			if (regcomp(&re, name, REG_NOSUB | REG_EXTENDED)) {
				pr_dbg("regex pattern failed: %s\n", name);
				free(str);
				return -1;
			}
		}

		for (i = 0; i < symtab->nr_sym; i++) {
			sym = &symtab->sym[i];

			if ((is_regex && regexec(&re, sym->name, 0, NULL, 0)) ||
			    (!is_regex && strcmp(name, sym->name)))
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

		name = strtok(NULL, ";");
	}

	if (stats.failed || stats.skipped || stats.nomatch)
		pr_out("%s cannot be patched dynamically\n",
		       (stats.failed + stats.skipped + stats.nomatch) > 1 ?
		       "some functions" : nopatched_name);

	free(str);
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

int mcount_dynamic_update(struct symtabs *symtabs, char *patch_funcs)
{
	int ret = 0;
	int success;

	if (prepare_dynamic_update() < 0) {
		pr_dbg("cannot setup dynamic tracing\n");
		return -1;
	}

	ret = do_dynamic_update(symtabs, patch_funcs);

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
