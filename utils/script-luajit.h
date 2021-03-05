#ifndef UFTRACE_SCRIPT_LUAJIT_H
#define UFTRACE_SCRIPT_LUAJIT_H

#include "utils/filter.h"

struct script_info;

#ifdef HAVE_LIBLUAJIT

#define SCRIPT_LUAJIT_ENABLED 1
int script_init_for_luajit(struct script_info *info,
			   enum uftrace_pattern_type ptype);
void script_finish_for_luajit(void);

#else /* HAVE_LIBLUAJIT */

#define SCRIPT_LUAJIT_ENABLED 0
static inline int script_init_for_luajit(struct script_info *info,
					 enum uftrace_pattern_type ptype)
{
	return -1;
}

static inline void script_finish_for_luajit(void) {}

#endif /* HAVE_LIBLUAJIT */

#endif /* UFTRACE_SCRIPT_LUAJIT_H */
