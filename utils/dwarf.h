#ifndef UFTRACE_DWARF_H
#define UFTRACE_DWARF_H

#include "utils/filter.h"

struct symtabs;

#ifdef HAVE_LIBDW

#include <elfutils/libdw.h>

struct debug_info {
	Dwarf		*dw;
	unsigned long	offset;
};

extern void prepare_debug_info(struct symtabs *symtabs,
			       enum uftrace_pattern_type ptype,
			       char *argspec, char *retspec);
extern void finish_debug_info(struct symtabs *symtabs);

#else /* !HAVE_LIBDW */

struct debug_info {
	/* nothing */
};

static inline void prepare_debug_info(struct symtabs *symtabs,
				      enum uftrace_pattern_type ptype,
				      char *argspec, char *retspec) {}
static inline void finish_debug_info(struct symtabs *symtabs) {}

#endif /* HAVE_LIBDW */

#endif /* UFTRACE_DWARF_H */
