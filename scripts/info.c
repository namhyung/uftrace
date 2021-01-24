#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <uftrace/script.h>

void uftrace_begin(struct uftrace_script_info *sc_info)
{
	printf("%d\n", sc_info->record);
	printf("%s\n", sc_info->version);
	printf("%s\n", sc_info->name);
	printf("%s\n", sc_info->cmds);

	/* disable actual data record by uftrace */
	sc_info->record = false;
}

void uftrace_entry(struct uftrace_script_base_ctx *sc_ctx)
{
}

void uftrace_exit(struct uftrace_script_base_ctx *sc_ctx)
{
}

void uftrace_end(void)
{
}
