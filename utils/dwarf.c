#ifdef HAVE_LIBDW

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <dwarf.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/dwarf.h"
#include "utils/symbol.h"

/* setup debug info from filename, return 0 for success */
static int setup_debug_info(const char *filename, struct debug_info *dinfo,
			    unsigned long offset)
{
	int fd;
	GElf_Ehdr ehdr;

	if (!check_trace_functions(filename))
		return 0;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg("cannot open debug info for %s: %m", filename);
		return -1;
	}

	dinfo->dw = dwarf_begin(fd, DWARF_C_READ);
	close(fd);

	if (dinfo->dw == NULL) {
		pr_dbg("failed to setup debug info: %s\n",
		       dwarf_errmsg(dwarf_errno()));
		return -1;
	}

	/*
	 * symbol address was adjusted to add offset already
	 * but it needs to use address in file (for shared libraries).
	 */
	if (gelf_getehdr(dwarf_getelf(dinfo->dw), &ehdr) && ehdr.e_type == ET_DYN)
		dinfo->offset = offset;
	else
		dinfo->offset = 0;

	return 0;
}

static void release_debug_info(struct debug_info *dinfo)
{
	if (dinfo->dw == NULL)
		return;

	dwarf_end(dinfo->dw);
	dinfo->dw = NULL;
}

struct arg_data {
	const char	*name;
	unsigned long	addr;
	char		*argspec;
	int		idx;
};

static int get_argspec(Dwarf_Die *die, void *data)
{
	struct arg_data *ad = data;
	Dwarf_Die arg;
	Dwarf_Addr offset = 0;
	int count = 0;

	dwarf_lowpc(die, &offset);
	pr_dbg2("found '%s' function for argspec (%#lx)\n", ad->name, offset);

	if (dwarf_child(die, &arg) != 0) {
		pr_dbg2("has no argument (children)\n");
		return 0;
	}

	do {
		char buf[256];

		if (dwarf_tag(&arg) != DW_TAG_formal_parameter)
			continue;

		snprintf(buf, sizeof(buf), "arg%d", ++ad->idx);

		if (ad->argspec == NULL)
			xasprintf(&ad->argspec, "@%s", buf);
		else
			ad->argspec = strjoin(ad->argspec, buf, ",");

		count++;
	}
	while (dwarf_siblingof(&arg, &arg) == 0);

	return count;
}

static int get_retspec(Dwarf_Die *die, void *data)
{
	struct arg_data *ad = data;
	char buf[256];
	Dwarf_Die spec;

	pr_dbg2("found '%s' function for retspec\n", ad->name);

	/* for C++ programs */
	if (!dwarf_hasattr(die, DW_AT_type)) {
		Dwarf_Attribute attr;

		if (!dwarf_hasattr(die, DW_AT_specification))
			return 0;

		dwarf_attr(die, DW_AT_specification, &attr);
		dwarf_formref_die(&attr, &spec);
		die = &spec;

		if (!dwarf_hasattr(die, DW_AT_type))
			return 0;
	}

	snprintf(buf, sizeof(buf), "@retval");
	ad->argspec = xstrdup(buf);

	return 1;
}

struct build_data {
	struct debug_info *dinfo;
};

static int get_dwarfspecs_cb(Dwarf_Die *die, void *data)
{
	struct arg_data ad = {
		.argspec = NULL,
	};
	Dwarf_Attribute attr;
	char *name = NULL;
	bool needs_free = false;
	Dwarf_Addr offset;

	if (uftrace_done)
		return DWARF_CB_ABORT;

	if (dwarf_tag(die) != DW_TAG_subprogram)
		return DWARF_CB_OK;

	/* XXX: old libdw might call with decl DIE */
	if (dwarf_hasattr(die, DW_AT_declaration))
		return DWARF_CB_OK;

	/* XXX: this assumes symbol->addr is same as the lowpc */
	if (!dwarf_hasattr(die, DW_AT_low_pc))
		return DWARF_CB_OK;

	dwarf_lowpc(die, &offset);

	if (dwarf_attr_integrate(die, DW_AT_linkage_name, &attr)) {
		name = demangle((char *)dwarf_formstring(&attr));
		needs_free = true;
	}
	if (name == NULL)
		name = (char *)dwarf_diename(die);
	if (unlikely(name == NULL))
		return DWARF_CB_OK;

	ad.name = name;
	ad.addr = offset;

	get_argspec(die, &ad);

	/* TODO: do something */

	free(ad.argspec);
	ad.argspec = NULL;

	ad.idx = 0;

	get_retspec(die, &ad);

	/* TODO: do something */

	free(ad.argspec);
	ad.argspec = NULL;

	if (needs_free)
		free(name);
	return DWARF_CB_OK;
}

static void build_debug_info(struct debug_info *dinfo)
{
	Dwarf_Off curr = 0;
	Dwarf_Off next = 0;
	size_t header_sz = 0;

	if (dinfo->dw == NULL)
		return;

	/* traverse every CU to find debug info */
	while (dwarf_nextcu(dinfo->dw, curr, &next,
			    &header_sz, NULL, NULL, NULL) == 0) {
		Dwarf_Die cudie;
		struct build_data bd = {
			.dinfo = dinfo,
		};

		if (dwarf_offdie(dinfo->dw, curr + header_sz, &cudie) == NULL)
			break;

		if (dwarf_tag(&cudie) != DW_TAG_compile_unit)
			break;

		if (uftrace_done)
			break;

		dwarf_getfuncs(&cudie, get_dwarfspecs_cb, &bd, 0);

		curr = next;
	}
}

void prepare_debug_info(struct symtabs *symtabs)
{
	struct uftrace_mmap *map;

	if (symtabs->loaded_debug)
		return;

	pr_dbg("prepare debug info\n");

	setup_debug_info(symtabs->filename, &symtabs->dinfo, symtabs->exec_base);
	build_debug_info(&symtabs->dinfo);

	map = symtabs->maps;
	while (map) {
		/* avoid loading of main executable or libmcount */
		if (strcmp(map->libname, symtabs->filename) &&
		    strncmp(basename(map->libname), "libmcount", 9)) {
			setup_debug_info(map->libname, &map->dinfo, map->start);
			build_debug_info(&map->dinfo);
		}
		map = map->next;
	}

	symtabs->loaded_debug = true;
}

void finish_debug_info(struct symtabs *symtabs)
{
	struct uftrace_mmap *map;

	if (!symtabs->loaded_debug)
		return;

	release_debug_info(&symtabs->dinfo);

	map = symtabs->maps;
	while (map) {
		release_debug_info(&map->dinfo);
		map = map->next;
	}

	symtabs->loaded_debug = false;
}

#endif /* HAVE_LIBDW */
