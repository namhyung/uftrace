#ifndef UFTRACE_DWARF_H
#define UFTRACE_DWARF_H

#ifdef HAVE_LIBDW

#include <elfutils/libdw.h>

struct debug_info {
	Dwarf		*dw;
	unsigned long	offset;
};

extern int setup_debug_info(const char *filename, struct debug_info *dinfo,
			    unsigned long offset);
extern void release_debug_info(struct debug_info *info);

#else /* !HAVE_LIBDW */

struct debug_info {
	/* nothing */
};

static inline int setup_debug_info(const char *filename, struct debug_info *dinfo,
				   unsigned long offset)
{
	return -1;
}

static inline void release_debug_info(struct debug_info *dinfo) {}

#endif /* HAVE_LIBDW */

#endif /* UFTRACE_DWARF_H */
