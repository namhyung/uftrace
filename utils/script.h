/*
 * Script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */
#ifndef UFTRACE_SCRIPT_H
#define UFTRACE_SCRIPT_H

#include "libmcount/mcount.h"
#include "utils/script-luajit.h"
#include "utils/script-python.h"
#include "utils/utils.h"

#define SCRIPT_ENABLED (SCRIPT_LUAJIT_ENABLED || SCRIPT_PYTHON_ENABLED)

/* script type */
enum script_type_t {
	SCRIPT_UNKNOWN = 0,
	SCRIPT_PYTHON,
	SCRIPT_LUAJIT,
	SCRIPT_TESTING,
	SCRIPT_TYPE_COUNT
};

/* informantion passed during initialization */
struct script_info {
	char *name;
	char *version;
	bool record;
	struct strv cmds;
};

/* context information passed to script */
struct script_context {
	int tid;
	int depth;
	uint64_t timestamp;
	uint64_t duration; /* exit only */
	unsigned long address;
	char *name;
	/* for arguments and return value */
	int arglen;
	void *argbuf;
	struct list_head *argspec;
};

union script_arg_val {
	char c;
	short s;
	int i;
	long l;
	long long L;
	float f;
	double d;
	long double D;
	unsigned char v[16];
};

extern char *script_str;

typedef int (*script_uftrace_entry_t)(struct script_context *sc_ctx);
typedef int (*script_uftrace_exit_t)(struct script_context *sc_ctx);
typedef int (*script_uftrace_event_t)(struct script_context *sc_ctx);
typedef int (*script_uftrace_end_t)(void);
typedef int (*script_atfork_prepare_t)(void);

/* The below functions are used both in record time and script command. */
extern script_uftrace_entry_t script_uftrace_entry;
extern script_uftrace_exit_t script_uftrace_exit;
extern script_uftrace_event_t script_uftrace_event;
extern script_uftrace_end_t script_uftrace_end;
extern script_atfork_prepare_t script_atfork_prepare;

int script_init(struct script_info *info, enum uftrace_pattern_type ptype);
void script_finish(void);

void script_add_filter(char *func, enum uftrace_pattern_type ptype);
int script_match_filter(char *func);
void script_finish_filter(void);

enum script_type_t get_script_type(const char *str);

#endif /* UFTRACE_SCRIPT_H */
