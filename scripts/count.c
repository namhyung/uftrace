#include <stdio.h>
#include <uftrace/script.h>

static int count = 0;

void uftrace_begin(struct uftrace_script_info *sc_info)
{
}

void uftrace_entry(struct uftrace_script_base_ctx *sc_ctx)
{
	++count;
}

void uftrace_exit(struct uftrace_script_base_ctx *sc_ctx)
{
}

void uftrace_end(void)
{
	printf("%d\n", count);
}
