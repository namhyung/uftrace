/*
 * utiltily functions and macros for ftrace
 *
 * Copyright (C) 2014-2016, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef __FTRACE_UTILS_H__
#define __FTRACE_UTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <endian.h>
#include <string.h>
#include <ctype.h>


#ifndef container_of
# define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#ifndef ALIGN
# define ALIGN(n, a)  (((n) + (a) - 1) & ~((a) - 1))
#endif

#define DIV_ROUND_UP(v, r)  (((v) + (r) - 1) / (r))
#define ROUND_UP(v, r)      (DIV_ROUND_UP((v), (r)) * (r))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)  (sizeof(a) / sizeof(a[0]))
#endif

#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

#define NSEC_PER_SEC  1000000000
#define NSEC_PER_MSEC 1000000

extern int debug;
extern FILE *logfp;
extern FILE *outfp;

enum debug_domain {
	DBG_UFTRACE	= 0,
	DBG_SYMBOL,
	DBG_DEMANGLE,
	DBG_FILTER,
	DBG_FSTACK,
	DBG_SESSION,
	DBG_KERNEL,
	DBG_MCOUNT,
	DBG_DYNAMIC,
	DBG_DOMAIN_MAX,
};
extern int dbg_domain[DBG_DOMAIN_MAX];

enum color_setting {
	COLOR_UNKNOWN,
	COLOR_AUTO,
	COLOR_OFF,
	COLOR_ON,
};

#define COLOR_CODE_RED      'R'
#define COLOR_CODE_GREEN    'G'
#define COLOR_CODE_BLUE     'B'
#define COLOR_CODE_YELLOW   'Y'
#define COLOR_CODE_MAGENTA  'M'
#define COLOR_CODE_CYAN     'C'
#define COLOR_CODE_GRAY     'g'
#define COLOR_CODE_BOLD     'b'

extern void __pr_dbg(const char *fmt, ...);
extern void __pr_log(const char *fmt, ...);
extern void __pr_out(const char *fmt, ...);
extern void __pr_err(const char *fmt, ...) __attribute__((noreturn));
extern void __pr_err_s(const char *fmt, ...) __attribute__((noreturn));
extern void __pr_warn(const char *fmt, ...);
extern void __pr_color(char code, const char *fmt, ...);

extern enum color_setting log_color;
extern enum color_setting out_color;
extern void setup_color(enum color_setting color);
extern void setup_signal(void);

#ifndef PR_FMT
# define PR_FMT  "uftrace"
#endif

#ifndef PR_DOMAIN
# define PR_DOMAIN  DBG_UFTRACE
#endif

#define pr_dbg(fmt, ...) 					\
({								\
	if (dbg_domain[PR_DOMAIN])			\
		__pr_dbg(PR_FMT ": " fmt, ## __VA_ARGS__);	\
})

#define pr_dbg2(fmt, ...) 					\
({								\
	if (dbg_domain[PR_DOMAIN] > 1)		\
		__pr_dbg(PR_FMT ": " fmt, ## __VA_ARGS__);	\
})

#define pr_dbg3(fmt, ...) 					\
({								\
	if (dbg_domain[PR_DOMAIN] > 2)		\
		__pr_dbg(PR_FMT ": " fmt, ## __VA_ARGS__);	\
})

#define pr_log(fmt, ...)					\
	__pr_log(PR_FMT ": %s:%d:%s\n" fmt,			\
		 __FILE__, __LINE__, __func__, ## __VA_ARGS__)

#define pr_err(fmt, ...)					\
	__pr_err_s(PR_FMT ": %s:%d:%s\n ERROR: " fmt,		\
		 __FILE__, __LINE__, __func__, ## __VA_ARGS__)

#define pr_err_ns(fmt, ...)					\
	__pr_err(PR_FMT ": %s:%d:%s\n ERROR: " fmt,		\
		 __FILE__, __LINE__, __func__, ## __VA_ARGS__)

#define pr_warn(fmt, ...)	__pr_warn("WARN: " fmt, ## __VA_ARGS__)

#define pr_cont(fmt, ...)	__pr_log(fmt, ## __VA_ARGS__)
#define pr_out(fmt, ...)	__pr_out(fmt, ## __VA_ARGS__)
#define pr_use(fmt, ...)	__pr_out(fmt, ## __VA_ARGS__)

#define pr_red(fmt, ...)	__pr_color(COLOR_CODE_RED,     fmt, ## __VA_ARGS__)
#define pr_green(fmt, ...)	__pr_color(COLOR_CODE_GREEN,   fmt, ## __VA_ARGS__)
#define pr_blue(fmt, ...)	__pr_color(COLOR_CODE_BLUE,    fmt, ## __VA_ARGS__)
#define pr_yellow(fmt, ...)	__pr_color(COLOR_CODE_YELLOW,  fmt, ## __VA_ARGS__)
#define pr_magenta(fmt, ...)	__pr_color(COLOR_CODE_MAGENTA, fmt, ## __VA_ARGS__)
#define pr_cyan(fmt, ...)	__pr_color(COLOR_CODE_CYAN,    fmt, ## __VA_ARGS__)
#define pr_bold(fmt, ...)	__pr_color(COLOR_CODE_BOLD,    fmt, ## __VA_ARGS__)
#define pr_gray(fmt, ...)	__pr_color(COLOR_CODE_GRAY,    fmt, ## __VA_ARGS__)
#define pr_color(c, fmt, ...)	__pr_color(c,                  fmt, ## __VA_ARGS__)


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

/* this comes from /usr/include/elf.h */
#ifndef ELFDATA2LSB
# define ELFDATA2LSB	1		/* 2's complement, little endian */
# define ELFDATA2MSB	2		/* 2's complement, big endian */
#endif

static inline int get_elf_endian(void)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return ELFDATA2LSB;
#else
	return ELFDATA2MSB;
#endif
}

struct uftrace_time_range {
	uint64_t first;
	uint64_t start;
	uint64_t stop;
	bool start_elapsed;
	bool stop_elapsed;
};

struct iovec;

int read_all(int fd, void *buf, size_t size);
int pread_all(int fd, void *buf, size_t size, off_t off);
int fread_all(void *byf, size_t size, FILE *fp);
int write_all(int fd, void *buf, size_t size);
int writev_all(int fd, struct iovec *iov, int count);

int create_directory(char *dirname);
int remove_directory(char *dirname);
int chown_directory(char *dirname);
char *read_exename(void);

void print_time_unit(uint64_t delta_nsec);
void print_diff_percent(uint64_t base_nsec, uint64_t delta_nsec);

void start_pager(void);
void wait_for_pager(void);

bool check_time_range(struct uftrace_time_range *range, uint64_t timestamp);
uint64_t parse_time(char *arg, int limited_digits);

char * strjoin(char *left, char *right, char *delim);

#endif /* __FTRACE_UTILS_H__ */
