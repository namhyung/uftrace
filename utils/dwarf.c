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
	struct debug_info	*dinfo;
	int			nr_args;
	int			nr_rets;
	struct uftrace_pattern	*args;
	struct uftrace_pattern	*rets;
};

static int get_dwarfspecs_cb(Dwarf_Die *die, void *data)
{
	struct build_data *bd = data;
	struct arg_data ad = {
		.argspec = NULL,
	};
	Dwarf_Attribute attr;
	char *name = NULL;
	bool needs_free = false;
	Dwarf_Addr offset;
	int i;

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

	for (i = 0; i < bd->nr_args; i++) {
		if (!match_filter_pattern(&bd->args[i], name))
			continue;

		get_argspec(die, &ad);
		/* TODO: do something */

		free(ad.argspec);
		ad.argspec = NULL;
		break;
	}

	ad.idx = RETVAL_IDX;
	for (i = 0; i < bd->nr_rets; i++) {
		if (!match_filter_pattern(&bd->rets[i], name))
			continue;

		get_retspec(die, &ad);
		/* TODO: do something */

		free(ad.argspec);
		ad.argspec = NULL;
		break;
	}

	if (needs_free)
		free(name);
	return DWARF_CB_OK;
}

static void build_debug_info(struct debug_info *dinfo,
			     enum uftrace_pattern_type ptype,
			     struct strv *args, struct strv *rets)
{
	Dwarf_Off curr = 0;
	Dwarf_Off next = 0;
	size_t header_sz = 0;
	struct uftrace_pattern *arg_patt;
	struct uftrace_pattern *ret_patt;
	char *s;
	int i;

	if (dinfo->dw == NULL)
		return;

	arg_patt = xcalloc(args->nr, sizeof(*arg_patt));
	strv_for_each(args, s, i)
		init_filter_pattern(ptype, &arg_patt[i], s);

	ret_patt = xcalloc(rets->nr, sizeof(*ret_patt));
	strv_for_each(rets, s, i)
		init_filter_pattern(ptype, &ret_patt[i], s);

	/* traverse every CU to find debug info */
	while (dwarf_nextcu(dinfo->dw, curr, &next,
			    &header_sz, NULL, NULL, NULL) == 0) {
		Dwarf_Die cudie;
		struct build_data bd = {
			.dinfo   = dinfo,
			.args    = arg_patt,
			.rets    = ret_patt,
			.nr_args = args->nr,
			.nr_rets = rets->nr,
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

	for (i = 0; i < args->nr; i++)
		free_filter_pattern(&arg_patt[i]);
	free(arg_patt);
	for (i = 0; i < rets->nr; i++)
		free_filter_pattern(&ret_patt[i]);
	free(ret_patt);
}

/* find argspecs only have function name (pattern) */
static void extract_dwarf_args(char *argspec, char *retspec,
			       struct strv *pargs, struct strv *prets)
{
	if (argspec) {
		struct strv tmp = STRV_INIT;
		char *arg;
		int i;

		strv_split(&tmp, argspec, ";");
		strv_for_each(&tmp, arg, i) {
			if (strchr(arg, '@'))
				continue;

			strv_append(pargs, arg);
		}
		strv_free(&tmp);
	}

	if (retspec) {
		struct strv tmp = STRV_INIT;
		char *ret;
		int i;

		strv_split(&tmp, retspec, ";");
		strv_for_each(&tmp, ret, i) {
			if (strchr(ret, '@'))
				continue;

			strv_append(prets, ret);
		}
		strv_free(&tmp);
	}
}

void prepare_debug_info(struct symtabs *symtabs,
			enum uftrace_pattern_type ptype,
			char *argspec, char *retspec)
{
	struct uftrace_mmap *map;
	struct strv dwarf_args = STRV_INIT;
	struct strv dwarf_rets = STRV_INIT;

	if (symtabs->loaded_debug)
		return;

	extract_dwarf_args(argspec, retspec, &dwarf_args, &dwarf_rets);
	if (dwarf_args.nr == 0 && dwarf_rets.nr == 0) {
		/* nothing to do */
		return;
	}

	pr_dbg("prepare debug info\n");

	setup_debug_info(symtabs->filename, &symtabs->dinfo, symtabs->exec_base);
	build_debug_info(&symtabs->dinfo, ptype, &dwarf_args, &dwarf_rets);

	map = symtabs->maps;
	while (map) {
		/* avoid loading of main executable or libmcount */
		if (strcmp(map->libname, symtabs->filename) &&
		    strncmp(basename(map->libname), "libmcount", 9)) {
			setup_debug_info(map->libname, &map->dinfo, map->start);
			build_debug_info(&map->dinfo, ptype,
					 &dwarf_args, &dwarf_rets);
		}
		map = map->next;
	}

	strv_free(&dwarf_args);
	strv_free(&dwarf_rets);

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
