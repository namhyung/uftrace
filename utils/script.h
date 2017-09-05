/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef __UFTRACE_SCRIPT_H__
#define __UFTRACE_SCRIPT_H__

#include "libmcount/mcount.h"
#include "utils/script-python.h"

/* script type */
enum script_type_t {
	SCRIPT_UNKNOWN = 0,
	SCRIPT_PYTHON
};

/* context information passed to script */
struct script_context {
	int			tid;
	int			depth;
	uint64_t		timestamp;
	uint64_t		duration;	/* exit only */
	unsigned long		address;
	char			*symname;
	/* for arguments and return value */
	int			arglen;
	void			*argbuf;
	struct list_head	*argspec;
};

extern char *script_str;

typedef int (*script_uftrace_entry_t)(struct script_context *sc_ctx);
typedef int (*script_uftrace_exit_t)(struct script_context *sc_ctx);
typedef int (*script_uftrace_end_t)(void);

/* The below functions are used both in record time and script command. */
extern script_uftrace_entry_t script_uftrace_entry;
extern script_uftrace_exit_t script_uftrace_exit;
extern script_uftrace_end_t script_uftrace_end;

int script_init(char *script_pathname);

#endif /* __UFTRACE_SCRIPT_H__ */
