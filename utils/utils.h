/*
 * utiltily functions and macros for ftrace
 *
 * Copyright (C) 2014-2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef __FTRACE_UTILS_H__
#define __FTRACE_UTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <endian.h>

#include "rbtree.h"
#include "symbol.h"


#ifndef container_of
# define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#ifndef ALIGN
# define ALIGN(n, a)  (((n) + (a) - 1) & ~((a) - 1))
#endif

#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

extern int debug;
extern int logfd;

extern void __pr_log(const char *fmt, ...);
extern void __pr_err(const char *fmt, ...) __attribute__((noreturn));
extern void __pr_err_s(const char *fmt, ...) __attribute__((noreturn));

#ifndef PR_FMT
# define PR_FMT  "ftrace"
#endif

#define pr_dbg(fmt, ...) 					\
({								\
	if (debug)						\
		__pr_log(PR_FMT ": " fmt, ## __VA_ARGS__);	\
})

#define pr_dbg2(fmt, ...) 					\
({								\
	if (debug > 1)						\
		__pr_log(PR_FMT ": " fmt, ## __VA_ARGS__);	\
})

#define pr_log(fmt, ...)					\
	__pr_log(PR_FMT ": %s:%d:%s: " fmt,			\
		 __FILE__, __LINE__, __func__, ## __VA_ARGS__)

#define pr_err(fmt, ...)					\
	__pr_err_s(PR_FMT ": ERROR: %s:%d:%s: " fmt,		\
		 __FILE__, __LINE__, __func__, ## __VA_ARGS__)

#define pr_err_ns(fmt, ...)					\
	__pr_err(PR_FMT ": ERROR: %s:%d:%s: " fmt,		\
		 __FILE__, __LINE__, __func__, ## __VA_ARGS__)

#define pr_cont(fmt, ...)  __pr_log(fmt, ## __VA_ARGS__)


#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)  (sizeof(a) / sizeof(a[0]))
#endif

#define xmalloc(sz)							\
({ 	void *__ptr = malloc(sz);					\
	if (__ptr == NULL) {						\
		pr_err("xmalloc");					\
	}								\
	__ptr;								\
})

#define xzalloc(sz)							\
({ 	void *__ptr = calloc(sz, 1);					\
	if (__ptr == NULL) {						\
		pr_err("xzalloc");					\
	}								\
	__ptr;								\
})

#define xcalloc(sz, n)							\
({ 	void *__ptr = calloc(sz, n);					\
	if (__ptr == NULL) {						\
		pr_err("xcalloc");					\
	}								\
	__ptr;								\
})

#define xrealloc(p, n)							\
({ 	void *__ptr = realloc(p, n);					\
	if (__ptr == NULL) {						\
		pr_err("xrealloc");					\
	}								\
	__ptr;								\
})

#define xstrdup(s)							\
({ 	void *__ptr = strdup(s);					\
	if (__ptr == NULL) {						\
		pr_err("xstrdup");					\
	}								\
	__ptr;								\
})

#define xstrndup(s, sz)							\
({ 	void *__ptr = strndup(s, sz);					\
	if (__ptr == NULL) {						\
		pr_err("xstrndup");					\
	}								\
	__ptr;								\
})

#define xasprintf(s, fmt, ...)						\
({ 	int __ret = asprintf(s, fmt, ## __VA_ARGS__);			\
	if (__ret < 0) {						\
		pr_err("xasprintf");					\
	}								\
})

#define htonq(x)  htobe64(x)
#define ntohq(x)  be64toh(x)

struct iovec;

int read_all(int fd, void *buf, size_t size);
int fread_all(void *byf, size_t size, FILE *fp);
int write_all(int fd, void *buf, size_t size);
int writev_all(int fd, struct iovec *iov, int count);

int create_directory(char *dirname);
int remove_directory(char *dirname);

void print_time_unit(uint64_t delta_nsec);

#ifndef DISABLE_MCOUNT_FILTER
struct ftrace_filter {
	struct rb_node node;
	struct sym *sym;
	char *name;
	unsigned long start;
	unsigned long end;
};

#define REGEX_CHARS  ".?*+-^$|()[]{}"

void ftrace_setup_filter(char *filter_str, struct symtabs *symtabs,
			 char *module, struct rb_root *root);
int ftrace_match_filter(struct rb_root *root, unsigned long ip);
void ftrace_cleanup_filter(struct rb_root *root);
void ftrace_print_filter(struct rb_root *root);
#endif /* DISABLE_MCOUNT_FILTER */

void start_pager(void);
void wait_for_pager(void);

char *demangle(char *str);

#endif /* __FTRACE_UTILS_H__ */
