#ifndef UFTRACE_DWARF_H
#define UFTRACE_DWARF_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "utils/filter.h"
#include "utils/rbtree.h"

struct symtabs;

#ifdef HAVE_LIBDW
# include <elfutils/libdw.h>
#else
# define Dwarf  void
#endif

struct debug_info {
	Dwarf		*dw;
	uint64_t	offset;
	struct rb_root	args;
	struct rb_root	rets;
	struct rb_root	enums;
};

extern void prepare_debug_info(struct symtabs *symtabs,
			       enum uftrace_pattern_type ptype,
			       char *argspec, char *retspec);
extern void finish_debug_info(struct symtabs *symtabs);
extern bool debug_info_available(struct debug_info *dinfo);
extern char * get_dwarf_argspec(struct debug_info *dinfo, char *name,
				unsigned long addr);
extern char * get_dwarf_retspec(struct debug_info *dinfo, char *name,
				unsigned long addr);
extern void save_debug_info(struct symtabs *symtabs, char *dirname);
extern void load_debug_info(struct symtabs *symtabs);

#endif /* UFTRACE_DWARF_H */
