#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>

#include "mcount.h"

extern bool debug;

static void __attribute__((constructor)) mcount_init(void)
{
	__monstartup(0, ~0);
}

static void __attribute__((destructor)) mcount_fini(void)
{
	_mcleanup();
}

void __cyg_profile_func_enter(void *child, void *parent)
{
	if (debug)
		printf("%s: p: %p, c: %p\n", __func__, parent, child);

	mcount_entry((unsigned long)parent, (unsigned long)child);
}

void __cyg_profile_func_exit(void *child, void *parent)
{
	int idx = mcount_rstack_idx;

	if (debug)
		printf("%s : p: %p, c: %p\n", __func__, parent, child);

	if (idx < 0)
		idx += MCOUNT_NOTRACE_IDX;

	if (idx <= 0 || idx >= MCOUNT_RSTACK_MAX) {
		if (debug)
			printf("%s: bad index [%d] for %p -> %p\n",
			       __func__, idx, parent, child);
		return;
	}

	if (mcount_rstack[idx-1].child_ip == (unsigned long)child &&
	    mcount_rstack[idx-1].parent_ip == (unsigned long)parent)
		mcount_exit();
}
