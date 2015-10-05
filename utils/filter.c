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

void ftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			 char *module, struct rb_root *root, bool *has_filter)
{
	char *str;
	char *pos, *name;
	struct sym *sym;
	struct ftrace_filter *filter;

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
		} else {
			if (module)
				goto next;
		}
		sym = find_symname(symtabs, name);
		if (sym == NULL)
			goto next;

		filter = xmalloc(sizeof(*filter));

		filter->sym = sym;
		filter->name = symbol_getname(sym, sym->addr);
		filter->start = sym->addr;
		filter->end = sym->addr + sym->size;

		add_filter(root, filter);
		*has_filter = true;

		pr_dbg("%s: %s (0x%lx-0x%lx)\n", __func__, filter->name,
		       filter->start, filter->end);
next:
		name = strtok(NULL, ",");
	}

	free(str);
}

void ftrace_setup_filter_regex(char *filter_str, struct symtabs *symtabs,
			       char *module, struct rb_root *root,
			       bool *has_filter)
{
	char *str;
	char *pos, *patt, *symname;
	struct symtab *symtab = &symtabs->symtab;
	struct sym *sym;
	struct ftrace_filter *filter;
	unsigned int i;
	regex_t re;

	if (filter_str == NULL)
		return;

	pos = str = strdup(filter_str);
	if (str == NULL)
		return;

	patt = strtok(pos, ",");
	while (patt) {
		pos = strchr(patt, '@');
		if (pos) {
			if (module == NULL || strcasecmp(pos+1, module))
				goto next;
			*pos = '\0';
		} else {
			if (module)
				goto next;
		}

		if (regcomp(&re, patt, REG_NOSUB)) {
			pr_log("regex pattern failed: %s\n", patt);
			goto next;
		}

		if (module && !strcasecmp(module, "plt"))
			symtab = &symtabs->dsymtab;

		for (i = 0; i < symtab->nr_sym; i++) {
			sym = &symtab->sym[i];
			symname = symbol_getname(sym, sym->addr);

			if (regexec(&re, symname, 0, NULL, 0))
				continue;

			filter = xmalloc(sizeof(*filter));

			filter->sym = sym;
			filter->name = symname;
			filter->start = sym->addr;
			filter->end = sym->addr + sym->size;

			add_filter(root, filter);
			*has_filter = true;

			pr_dbg("%s: %s (0x%lx-0x%lx)\n", __func__, filter->name,
			       filter->start, filter->end);
		}
next:
		patt = strtok(NULL, ",");
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
