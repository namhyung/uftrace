#include <cstdint>
#include <iostream>
#include <uftrace/script.h>

extern "C" {

void uftrace_begin(struct uftrace_script_info *sc_info)
{
	std::cout << "program begins...\n";
}

void uftrace_entry(struct uftrace_script_base_ctx *sc_ctx)
{
	std::cout << "entry : " << sc_ctx->name << "()\n";
}

void uftrace_exit(struct uftrace_script_base_ctx *sc_ctx)
{
	std::cout << "exit  : " << sc_ctx->name << "()\n";
}

void uftrace_end(void)
{
	std::cout << "program is finished\n";
}
}
