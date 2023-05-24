#ifndef UFTRACE_SCRIPT_NATIVE_H
#define UFTRACE_SCRIPT_NATIVE_H

#include "utils/filter.h"

struct uftrace_script_info;

int script_init_for_native(struct uftrace_script_info *info, enum uftrace_pattern_type ptype);
void script_finish_for_native(void);

#endif /* UFTRACE_SCRIPT_NATIVE_H */
