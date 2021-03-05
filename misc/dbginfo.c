#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>

#include "utils/symbol.h"
#include "utils/dwarf.h"
#include "utils/filter.h"

void print_debug_info(struct debug_info *dinfo, bool auto_args)
{
	int i;
	char *argspec = NULL;
	char *retspec = NULL;

	/* TODO: print enum definitions */

	for (i = 0; i < dinfo->nr_locs; i++) {
		struct debug_location *loc = &dinfo->locs[i];
		int idx = 0;

		if (loc->sym == NULL)
			continue;

		argspec = get_dwarf_argspec(dinfo, loc->sym->name, loc->sym->addr);
		retspec = get_dwarf_retspec(dinfo, loc->sym->name, loc->sym->addr);
		if (argspec == NULL && retspec == NULL && !auto_args)
			continue;

		printf("%s [addr: %"PRIx64"]\n", loc->sym->name, loc->sym->addr);

		/* skip common parts with compile directory  */
		if (dinfo->base_dir) {
			int len = strlen(dinfo->base_dir);
			if (!strncmp(loc->file->name, dinfo->base_dir, len))
				idx = len + 1;
		}
		printf("  srcline: %s:%d\n", loc->file->name + idx, loc->line);

		if (argspec)
			printf("  argspec: %s\n", argspec);
		if (retspec)
			printf("  retspec: %s\n", retspec);
	}
}

int main(int argc, char *argv[])
{
	struct uftrace_mmap *map;
	struct symtabs symtabs = {
		.dirname = ".",
		.flags = SYMTAB_FL_DEMANGLE,
	};
	char *argspec = NULL;
	char *retspec = NULL;
	char *filename = NULL;
	bool auto_args = false;
	enum uftrace_pattern_type ptype = PATT_REGEX;
	int opt;

	while ((opt = getopt(argc, argv, "aA:R:v")) != -1) {
		switch (opt) {
		case 'a':
			auto_args = true;
			break;
		case 'A':
			argspec = optarg;
			break;
		case 'R':
			retspec = optarg;
			break;
		case 'v':
			debug++;
			dbg_domain[DBG_DWARF]++;
			break;
		default:
			printf("dbginfo: unknown option: %c\n", opt);
			return 1;
		}
	}

	if (optind >= argc) {
		printf("Usage: dbginfo [-a | -A <arg> | -R <ret>] <filename>\n");
		return 1;
	}
	filename = argv[optind];

	logfp = stderr;
	outfp = stdout;

	map = xzalloc(sizeof(*map) + strlen(filename) + 1);
	strcpy(map->libname, filename);
	symtabs.maps = map;

	load_module_symtabs(&symtabs);
	prepare_debug_info(&symtabs, ptype, argspec, retspec, auto_args, false);

	print_debug_info(&map->mod->dinfo, auto_args);

	finish_debug_info(&symtabs);
	unload_module_symtabs();
	free(map);
	return 0;
}
