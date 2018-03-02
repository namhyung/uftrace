#ifndef UFTRACE_DWARF_H
#define UFTRACE_DWARF_H

#include <stdint.h>
#include <stdbool.h>

#include "utils/filter.h"
#include "utils/rbtree.h"

struct symtabs;

#ifdef HAVE_LIBDW

#include <elfutils/libdw.h>

struct debug_info {
	Dwarf		*dw;
	unsigned long	offset;
	struct rb_root	args;
	struct rb_root	rets;
};

extern void prepare_debug_info(struct symtabs *symtabs,
			       enum uftrace_pattern_type ptype,
			       char *argspec, char *retspec);
extern void finish_debug_info(struct symtabs *symtabs);

#else /* !HAVE_LIBDW */

struct debug_info {
	struct rb_root	args;
	struct rb_root	rets;
};

static inline void prepare_debug_info(struct symtabs *symtabs,
				      enum uftrace_pattern_type ptype,
				      char *argspec, char *retspec) {}
static inline void finish_debug_info(struct symtabs *symtabs) {}

#endif /* HAVE_LIBDW */

extern bool debug_info_available(struct debug_info *dinfo);
extern char * get_dwarf_argspec(struct debug_info *dinfo, char *name,
				unsigned long addr);
extern char * get_dwarf_retspec(struct debug_info *dinfo, char *name,
				unsigned long addr);
void save_debug_info(struct symtabs *symtabs, char *dirname);

#endif /* UFTRACE_DWARF_H */
