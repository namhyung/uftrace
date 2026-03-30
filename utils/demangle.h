#ifndef UFTRACE_DEMANGLE_H
#define UFTRACE_DEMANGLE_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "utils/utils.h"

#define MAX_DEBUG_DEPTH 128

enum symbol_demangler {
	DEMANGLE_ERROR = -2,
	DEMANGLE_NOT_SUPPORTED,
	DEMANGLE_NONE,
	DEMANGLE_SIMPLE,
	DEMANGLE_FULL,
};

extern enum symbol_demangler demangler;

struct demangle_debug {
	const char *func;
	int level;
	int pos;
};

struct demangle_data {
	char *old;
	char *new;
	const char *func;
	char *expected;
	int line;
	int pos;
	int len;
	int newpos;
	int alloc;
	int level;
	int type;
	int nr_dbg;
	int templates;
	bool type_info;
	bool first_name;
	bool ignore_disc;
	struct demangle_debug debug[MAX_DEBUG_DEPTH];
};

extern char dd_expbuf[2];

static inline int dd_eof(struct demangle_data *dd)
{
	return dd->pos >= dd->len;
}

static inline char dd_peek(struct demangle_data *dd, int lookahead)
{
	if (dd->pos + lookahead > dd->len)
		return 0;
	return dd->old[dd->pos + lookahead];
}

static inline char dd_curr(struct demangle_data *dd)
{
	return dd_peek(dd, 0);
}

static inline void __dd_add_debug(struct demangle_data *dd, const char *func)
{
	if (dd->nr_dbg < MAX_DEBUG_DEPTH && func) {
		struct demangle_debug *dbg = &dd->debug[dd->nr_dbg++];

		dbg->func = func;
		dbg->level = dd->level;
		dbg->pos = dd->pos;
	}
}

static inline char __dd_consume_n(struct demangle_data *dd, int n, const char *dbg)
{
	char c = dd_curr(dd);

	if (dbg)
		__dd_add_debug(dd, dbg);

	if (dd->pos + n > dd->len)
		return 0;

	dd->pos += n;
	return c;
}

static inline char __dd_consume(struct demangle_data *dd, const char *dbg)
{
	return __dd_consume_n(dd, 1, dbg);
}

#define dd_consume(dd) __dd_consume(dd, __func__)
#define dd_consume_n(dd, n) __dd_consume_n(dd, n, __func__)
#define dd_add_debug(dd) __dd_add_debug(dd, __func__)

#define DD_DEBUG(dd, exp, inc)                                                                     \
	({                                                                                         \
		dd->func = __func__;                                                               \
		dd->line = __LINE__ - 1;                                                           \
		dd->pos += inc;                                                                    \
		dd->expected = exp;                                                                \
		return -1;                                                                         \
	})

#define DD_DEBUG_CONSUME(dd, exp_c)                                                                \
	({                                                                                         \
		if (dd_consume(dd) != exp_c) {                                                     \
			if (!dd->expected) {                                                       \
				dd->func = __func__;                                               \
				dd->line = __LINE__;                                               \
				dd->pos--;                                                         \
				dd->expected = dd_expbuf;                                          \
				dd_expbuf[0] = exp_c;                                              \
			}                                                                          \
			return -1;                                                                 \
		}                                                                                  \
	})

#define __DD_DEBUG_CONSUME(dd, exp_c)                                                              \
	({                                                                                         \
		if (__dd_consume(dd, NULL) != exp_c) {                                             \
			if (!dd->expected) {                                                       \
				dd->func = __func__;                                               \
				dd->line = __LINE__;                                               \
				dd->pos--;                                                         \
				dd->expected = dd_expbuf;                                          \
				dd_expbuf[0] = exp_c;                                              \
			}                                                                          \
			return -1;                                                                 \
		}                                                                                  \
	})

void dd_debug_print(struct demangle_data *dd);

static inline int dd_append_len(struct demangle_data *dd, const char *str, int size)
{
	if (dd->newpos + size >= dd->alloc) {
		dd->alloc = ALIGN(dd->newpos + size + 1, 16);
		dd->new = xrealloc(dd->new, dd->alloc);
	}

	/* copy including the last NUL byte (but usually not) */
	strncpy(&dd->new[dd->newpos], str, size + 1);
	dd->newpos += size;
	dd->new[dd->newpos] = '\0';

	return 0;
}

static inline int dd_append(struct demangle_data *dd, const char *str)
{
	return dd_append_len(dd, str, strlen(str));
}

static inline int dd_append_separator(struct demangle_data *dd, const char *str)
{
	if (!dd->first_name)
		dd_append(dd, str);

	dd->first_name = false;
	return 0;
}

/* main API for symbol name demangling */
char *demangle(char *str);

#ifdef HAVE_CXA_DEMANGLE
/* copied from /usr/include/c++/4.7.2/cxxabi.h */
extern char *__cxa_demangle(const char *mangled_name, char *output_buffer, size_t *length,
			    int *status);

static inline bool support_full_demangle(void)
{
	return true;
}
#else
static inline bool support_full_demangle(void)
{
	return false;
}

static inline char *demangle_full(char *str)
{
	pr_warn("full demangle is not supported\n");
	return str;
}
#endif /* HAVE_CXA_DEMANGLE */

#endif /* UFTRACE_DEMANGLE_H */
