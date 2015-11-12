#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT  "filter"

#include "../libmcount/mcount.h"
#include "filter.h"
#include "symbol.h"
#include "rbtree.h"
#include "utils.h"


static bool match_ip(struct ftrace_filter *filter, unsigned long ip)
{
	return filter->start <= ip && ip < filter->end;
}

/**
 * ftrace_match_filter - try to match @ip with filters in @root
 * @root - root of rbtree which has filters
 * @ip   - instruction address to match
 * @tr   - trigger data
 */
int ftrace_match_filter(struct rb_root *root, unsigned long ip,
			struct ftrace_trigger *tr)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct ftrace_filter *iter;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct ftrace_filter, node);

		if (match_ip(iter, ip)) {
			memcpy(tr, &iter->trigger, sizeof(*tr));
			return 1;
		}

		if (iter->start > ip)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	return 0;
}

static void add_trigger(struct ftrace_filter *filter, struct ftrace_trigger *tr)
{
	memcpy(&filter->trigger, tr, sizeof(*tr));
}

static void add_filter(struct rb_root *root, struct ftrace_filter *filter,
		       struct ftrace_trigger *tr)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct ftrace_filter *iter, *new;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct ftrace_filter, node);

		if (iter->start == filter->start) {
			add_trigger(iter, tr);
			return;
		}

		if (iter->start > filter->start)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	new = xmalloc(sizeof(*new));
	memcpy(new, filter, sizeof(*new));
	new->name = symbol_getname(new->sym, new->sym->addr);

	add_trigger(new, tr);

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);
}

static int add_exact_filter(struct rb_root *root, struct symtab *symtab,
			    char *module, char *filter_str,
			    struct ftrace_trigger *tr)
{
	struct ftrace_filter filter;
	struct sym *sym;

	sym = find_symname(symtab, filter_str);
	if (sym == NULL)
		return 0;

	filter.sym = sym;
	filter.start = sym->addr;
	filter.end = sym->addr + sym->size;

	pr_dbg("%s: %s (0x%lx-0x%lx)\n", module ?: "<exe>", filter.sym->name,
	       filter.start, filter.end);

	add_filter(root, &filter, tr);
	return 1;
}

static int add_regex_filter(struct rb_root *root, struct symtab *symtab,
			    char *module, char *filter_str,
			    struct ftrace_trigger *tr)
{
	struct ftrace_filter filter;
	struct sym *sym;
	regex_t re;
	char *symname;
	unsigned i;
	int ret = 0;

	if (regcomp(&re, filter_str, REG_NOSUB | REG_EXTENDED)) {
		pr_log("regex pattern failed: %s\n", filter_str);
		return 0;
	}

	for (i = 0; i < symtab->nr_sym; i++) {
		sym = &symtab->sym[i];
		symname = symbol_getname(sym, sym->addr);

		if (regexec(&re, symname, 0, NULL, 0))
			goto next;

		filter.sym = sym;
		filter.start = sym->addr;
		filter.end = sym->addr + sym->size;

		pr_dbg("%s: %s (0x%lx-0x%lx)\n", module ?: "<exe>", symname,
		       filter.start, filter.end);

		add_filter(root, &filter, tr);
		ret++;

next:
		symbol_putname(sym, symname);
	}
	return ret;
}

static int setup_module_and_trigger(char *str, char *module,
				    struct symtabs *symtabs,
				    struct symtab **psymtab,
				    struct ftrace_trigger *tr)
{
	char *pos = strchr(str, '@');

	*psymtab = &symtabs->symtab;

	if (pos) {
		char *tr_str;
		bool found_mod = false;

		*pos++ = '\0';
		tr_str = xstrdup(pos);

		while ((pos = strsep(&tr_str, ":")) != NULL) {
			if (!strncasecmp(pos, "depth=", 6)) {
				tr->flags |= TRIGGER_FL_DEPTH;
				tr->depth = strtoul(pos+6, NULL, 10);

				if (tr->depth < 0 ||
				    tr->depth > MCOUNT_RSTACK_MAX)
					pr_err_ns("invalid depth: %d\n",
						  tr->depth);
				continue;
			}
			if (!strcasecmp(pos, "backtrace")) {
				tr->flags |= TRIGGER_FL_BACKTRACE;
				continue;
			}

			if (module == NULL || strcasecmp(pos, module))
				return -1;

			found_mod = true;

			if (!strcasecmp(module, "plt"))
				*psymtab = &symtabs->dsymtab;
			else if (!strcasecmp(module, "kernel"))
				*psymtab = get_kernel_symtab();
		}

		if (module && !found_mod)
			return -1;
	}
	else {
		if (module)
			return -1;
	}

	return 0;
}

static void setup_trigger(char *filter_str, struct symtabs *symtabs,
			  char *module, struct rb_root *root,
			  unsigned long flags, enum filter_mode mode)
{
	char *str;
	char *pos, *name;

	if (filter_str == NULL)
		return;

	pos = str = strdup(filter_str);
	if (str == NULL)
		return;

	name = strtok(pos, ",");
	while (name) {
		struct symtab *symtab = &symtabs->symtab;
		struct ftrace_trigger tr = {
			.flags = flags,
			.fmode = mode,
		};
		int ret;
		char *mod = module;

		if (setup_module_and_trigger(name, mod, symtabs, &symtab,
					     &tr) < 0)
			goto next;

again:
		if (strpbrk(name, REGEX_CHARS))
			ret = add_regex_filter(root, symtab, mod, name, &tr);
		else
			ret = add_exact_filter(root, symtab, mod, name, &tr);

		if (ret == 0 && mod == NULL) {
			mod = "plt";
			symtab = &symtabs->dsymtab;
			goto again;
		}
next:
		name = strtok(NULL, ",");
	}

	free(str);
}

/**
 * ftrace_setup_filter - construct rbtree of filters
 * @filter_str - CSV of filter string
 * @symtabs    - symbol tables to find symbol address
 * @module     - optional module (binary/dso) name
 * @root       - root of resulting rbtree
 * @mode       - filter mode: opt-in (-F) or opt-out (-N)
 */
void ftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			 char *module, struct rb_root *root,
			 enum filter_mode mode)
{
	setup_trigger(filter_str, symtabs, module, root, TRIGGER_FL_FILTER, mode);
}

/**
 * ftrace_setup_trigger - construct rbtree of triggers
 * @trigger_str - CSV of trigger string (FUNC @ act)
 * @symtabs    - symbol tables to find symbol address
 * @module     - optional module (binary/dso) name
 * @root       - root of resulting rbtree
 */
void ftrace_setup_trigger(char *trigger_str, struct symtabs *symtabs,
			  char *module, struct rb_root *root)
{
	setup_trigger(trigger_str, symtabs, module, root, 0, FILTER_MODE_NONE);
}

/**
 * ftrace_cleanup_filter - delete filters in rbtree
 * @root - root of the filter rbtree
 */
void ftrace_cleanup_filter(struct rb_root *root)
{
	struct rb_node *node;
	struct ftrace_filter *filter;

	while (!RB_EMPTY_ROOT(root)) {
		node = rb_first(root);
		filter = rb_entry(node, struct ftrace_filter, node);

		rb_erase(node, root);

		symbol_putname(filter->sym, filter->name);
		free(filter);
	}
}

/**
 * ftrace_print_filter - print all filters in rbtree
 * @root - root of the filter rbtree
 */
void ftrace_print_filter(struct rb_root *root)
{
	struct rb_node *node;
	struct ftrace_filter *filter;

	node = rb_first(root);
	while (node) {
		filter = rb_entry(node, struct ftrace_filter, node);
		pr_log("%lx-%lx: %s\n", filter->start, filter->end, filter->name);
		node = rb_next(node);
	}
}
