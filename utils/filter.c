#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#include "../libmcount/mcount.h"
#include "symbol.h"
#include "rbtree.h"
#include "utils.h"


static void add_filter(struct rb_root *root, struct ftrace_filter *filter)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct ftrace_filter *iter;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct ftrace_filter, node);

		if (iter->start > filter->start)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&filter->node, parent, p);
	rb_insert_color(&filter->node, root);
}

static bool match_ip(struct ftrace_filter *filter, unsigned long ip)
{
	return filter->start <= ip && ip < filter->end;
}

int ftrace_match_filter(struct rb_root *root, unsigned long ip)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct ftrace_filter *iter;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct ftrace_filter, node);

		if (match_ip(iter, ip))
			return 1;

		if (iter->start > ip)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	return 0;
}

static int add_exact_filter(struct rb_root *root, struct symtab *symtab,
			    char *module, char *filter_str)
{
	struct ftrace_filter *filter;
	struct sym *sym;

	sym = find_symname(symtab, filter_str);
	if (sym == NULL)
		return 0;

	filter = xmalloc(sizeof(*filter));

	filter->sym = sym;
	filter->name = symbol_getname(sym, sym->addr);
	filter->start = sym->addr;
	filter->end = sym->addr + sym->size;

	pr_dbg("%s: %s (0x%lx-0x%lx)\n", module ?: "<exe>", filter->name,
	       filter->start, filter->end);

	add_filter(root, filter);
	return 1;
}

static int add_regex_filter(struct rb_root *root, struct symtab *symtab,
			    char *module, char *filter_str)
{
	struct ftrace_filter *filter;
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

		filter = xmalloc(sizeof(*filter));

		filter->sym = sym;
		filter->name = symname;
		filter->start = sym->addr;
		filter->end = sym->addr + sym->size;

		pr_dbg("%s: %s (0x%lx-0x%lx)\n", module ?: "<exe>", filter->name,
		       filter->start, filter->end);

		add_filter(root, filter);
		ret++;

next:
		symbol_putname(sym, symname);
	}
	return ret;
}

void ftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			 char *module, struct rb_root *root, bool *has_filter)
{
	int ret;
	char *str;
	char *pos, *name;
	struct symtab *symtab = &symtabs->symtab;

	if (filter_str == NULL)
		return;

	pos = str = strdup(filter_str);
	if (str == NULL)
		return;

	name = strtok(pos, ",");
	while (name) {
		pos = strchr(name, '@');
		if (pos) {
			if (module == NULL || strcasecmp(pos+1, module))
				goto next;
			*pos = '\0';

			if (!strcasecmp(module, "plt"))
				symtab = &symtabs->dsymtab;
			else if (!strcasecmp(module, "kernel"))
				symtab = get_kernel_symtab();
		} else {
			if (module)
				goto next;
		}

		if (strpbrk(name, REGEX_CHARS))
			ret = add_regex_filter(root, symtab, module, name);
		else
			ret = add_exact_filter(root, symtab, module, name);

		if (ret)
			*has_filter = true;

next:
		name = strtok(NULL, ",");
	}

	free(str);
}

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
