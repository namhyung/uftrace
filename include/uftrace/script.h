#ifndef UFTRACE_INCLUDE_SCRIPT_H
#define UFTRACE_INCLUDE_SCRIPT_H

#include <stdbool.h>
#include <stdint.h>

/* informantion passed during initialization */
struct uftrace_script_info {
	char *name;
	char *version;
	bool record;
	const char *cmds;
};

/* base context information passed to script */
struct uftrace_script_base_ctx {
	int tid;
	int depth;
	uint64_t timestamp;
	uint64_t duration; /* exit only */
	unsigned long address;
	char *name;
};

#endif /* UFTRACE_INCLUDE_SCRIPT_H */
