#ifdef HAVE_LIBDW

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <dwarf.h>

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

void prepare_debug_info(struct symtabs *symtabs)
{
	struct uftrace_mmap *map;

	if (symtabs->loaded_debug)
		return;

	pr_dbg("prepare debug info\n");

	setup_debug_info(symtabs->filename, &symtabs->dinfo, symtabs->exec_base);

	map = symtabs->maps;
	while (map) {
		/* avoid loading of main executable or libmcount */
		if (strcmp(map->libname, symtabs->filename) &&
		    strncmp(basename(map->libname), "libmcount", 9)) {
			setup_debug_info(map->libname, &map->dinfo, map->start);
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
