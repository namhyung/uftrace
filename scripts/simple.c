#include <stdint.h>
#include <stdio.h>
#include <uftrace/script.h>

void uftrace_begin(struct uftrace_script_info *sc_info)
{
	printf("program begins...\n");
}

void uftrace_entry(struct uftrace_script_base_ctx *sc_ctx)
{
	printf("entry : %s()\n", sc_ctx->name);
}

void uftrace_exit(struct uftrace_script_base_ctx *sc_ctx)
{
	printf("exit  : %s()\n", sc_ctx->name);
}

void uftrace_end(void)
{
	printf("program is finished\n");
}
