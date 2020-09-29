#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <uftrace/script.h>

/* uftrace_begin is optional, so can be omitted. */
void uftrace_begin(struct uftrace_script_info *sc_info)
{
	printf("uftrace_begin(ctx)\n");
	printf("  record  : %d\n", sc_info->record);
	printf("  version : %s\n", sc_info->version);
	if (sc_info->cmds)
		printf("  cmds    : %s\n", sc_info->cmds);
	printf("\n");
}

/* uftrace_entry is executed at the entry of each function. */
void uftrace_entry(struct uftrace_script_base_ctx *sc_ctx)
{
	int _tid = sc_ctx->tid;
	int _depth = sc_ctx->depth;
	uint64_t _time = sc_ctx->timestamp;
	unsigned long _address = sc_ctx->address;
	char *_name = sc_ctx->name;

	uint64_t unit = 1000000000;
	printf("%" PRIu64 ".%" PRIu64 "  %6d: [entry] %s(%lx) depth: %d\n",
	       (uint64_t)(_time / unit), _time % unit, _tid, _name, _address, _depth);
}

/* uftrace_exit is executed at the exit of each function. */
void uftrace_exit(struct uftrace_script_base_ctx *sc_ctx)
{
	int _tid = sc_ctx->tid;
	int _depth = sc_ctx->depth;
	uint64_t _time = sc_ctx->timestamp;
	uint64_t _duration = sc_ctx->duration; /* not used here */
	unsigned long _address = sc_ctx->address;
	char *_name = sc_ctx->name;

	uint64_t unit = 1000000000;
	printf("%" PRIu64 ".%" PRIu64 "  %6d: [exit ] %s(%lx) depth: %d\n",
	       (uint64_t)(_time / unit), _time % unit, _tid, _name, _address, _depth);
}

/* uftrace_end is optional, so can be omitted. */
void uftrace_end(void)
{
	printf("uftrace_end()\n");
}
