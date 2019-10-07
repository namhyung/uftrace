#ifndef UFTRACE_DWARF_H
#define UFTRACE_DWARF_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "utils/filter.h"
#include "utils/rbtree.h"
#include "utils/list.h"

struct symtabs;

#ifdef HAVE_LIBDW
# include <elfutils/libdw.h>
#else
# define Dwarf  void
#endif

struct debug_file {
	struct list_head	list;
	char			*name;
};

struct debug_location {
	struct sym		*sym;
	struct debug_file	*file;
	int			line;
};

struct debug_info {
	Dwarf			*dw;
	uint64_t		offset;
	struct rb_root		args;
	struct rb_root		rets;
	struct rb_root		enums;
	struct list_head	files;
	struct debug_location	*locs;
	int			nr_locs;
	int			nr_locs_used;
};

extern void prepare_debug_info(struct symtabs *symtabs,
			       enum uftrace_pattern_type ptype,
			       char *argspec, char *retspec,
			       bool auto_args, bool force);
extern void finish_debug_info(struct symtabs *symtabs);
extern bool debug_info_has_argspec(struct debug_info *dinfo);
extern bool debug_info_has_location(struct debug_info *dinfo);
extern char * get_dwarf_argspec(struct debug_info *dinfo, char *name,
				unsigned long addr);
extern char * get_dwarf_retspec(struct debug_info *dinfo, char *name,
				unsigned long addr);
struct debug_location *find_file_line(struct symtabs *symtabs, uint64_t addr);
extern void save_debug_info(struct symtabs *symtabs, char *dirname);
extern void load_debug_info(struct symtabs *symtabs);
extern void save_debug_file(FILE *fp, char code, char *str, unsigned long val);
/* only for dummy python module */
extern int setup_debug_info(const char *filename, struct debug_info *dinfo,
			    unsigned long offset, bool force);

#endif /* UFTRACE_DWARF_H */
