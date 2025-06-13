/*
 * utiltily functions and macros for uftrace
 *
 * Copyright (C) 2014-2017, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifndef UFTRACE_UTILS_H
#define UFTRACE_UTILS_H

#include <ctype.h>
#include <endian.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "compiler.h"

#ifndef container_of
#define container_of(ptr, type, member)                                                            \
	({                                                                                         \
		const typeof(((type *)0)->member) *__mptr = (ptr);                                 \
		(type *)((char *)__mptr - offsetof(type, member));                                 \
	})
#endif

#ifndef ALIGN
#define ALIGN(n, a) (((n) + (a)-1) & ~((a)-1))
#endif

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define DIV_ROUND_UP(v, r) (((v) + (r)-1) / (r))
#define ROUND_UP(v, r) (DIV_ROUND_UP((v), (r)) * (r))
#define ROUND_DOWN(v, r) (((v) / (r)) * (r))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define NSEC_PER_SEC 1000000000
#define NSEC_PER_MSEC 1000000

#define UFTRACE_SHMEM_PERMISSION_MODE 0700

#define BUG_REPORT_MSG "Please report this bug to https://github.com/namhyung/uftrace/issues.\n\n"

extern int debug;
extern FILE *logfp;
extern FILE *outfp;

/* colored output for argspec display */
extern const char *color_reset;
extern const char *color_bold;
extern const char *color_string;
extern const char *color_symbol;
extern const char *color_struct;
extern const char *color_enum;
extern const char *color_enum_or;

/* must change DBG_DOMAIN_STR (in mcount.h) as well */
enum debug_domain {
	DBG_UFTRACE = 0,
	DBG_SYMBOL,
	DBG_DEMANGLE,
	DBG_FILTER,
	DBG_FSTACK,
	DBG_SESSION,
	DBG_KERNEL,
	DBG_MCOUNT,
	DBG_PLTHOOK,
	DBG_DYNAMIC,
	DBG_EVENT,
	DBG_SCRIPT,
	DBG_DWARF,
	DBG_WRAP,
	DBG_DOMAIN_MAX,
};
extern int dbg_domain[DBG_DOMAIN_MAX];

enum color_setting {
	COLOR_UNKNOWN,
	COLOR_AUTO,
	COLOR_OFF,
	COLOR_ON,
};

enum format_mode {
	FORMAT_NORMAL,
	FORMAT_HTML,
};

#define COLOR_CODE_NORMAL '.'
#define COLOR_CODE_RESET '-'
#define COLOR_CODE_RED 'R'
#define COLOR_CODE_GREEN 'G'
#define COLOR_CODE_BLUE 'B'
#define COLOR_CODE_YELLOW 'Y'
#define COLOR_CODE_MAGENTA 'M'
#define COLOR_CODE_CYAN 'C'
#define COLOR_CODE_GRAY 'g'
#define COLOR_CODE_BOLD 'b'

#define DEFAULT_EVENT_COLOR COLOR_CODE_GREEN

extern void __pr_dbg(const char *fmt, ...);
extern void __pr_out(const char *fmt, ...);
extern void __pr_err(const char *fmt, ...) __attribute__((noreturn));
extern void __pr_err_s(const char *fmt, ...) __attribute__((noreturn));
extern void __pr_warn(const char *fmt, ...);
extern void __pr_color(char code, const char *fmt, ...);

extern enum color_setting log_color;
extern enum color_setting out_color;
extern enum format_mode format_mode;
extern void setup_color(enum color_setting color, char *pager);
extern void setup_signal(void);

#ifndef PR_FMT
#define PR_FMT "uftrace"
#endif

#ifndef PR_DOMAIN
#define PR_DOMAIN DBG_UFTRACE
#endif

#define pr_dbg(fmt, ...)                                                                           \
	({                                                                                         \
		if (dbg_domain[PR_DOMAIN])                                                         \
			__pr_dbg(PR_FMT ": " fmt, ##__VA_ARGS__);                                  \
	})

#define pr_dbg2(fmt, ...)                                                                          \
	({                                                                                         \
		if (dbg_domain[PR_DOMAIN] > 1)                                                     \
			__pr_dbg(PR_FMT ": " fmt, ##__VA_ARGS__);                                  \
	})

#define pr_dbg3(fmt, ...)                                                                          \
	({                                                                                         \
		if (dbg_domain[PR_DOMAIN] > 2)                                                     \
			__pr_dbg(PR_FMT ": " fmt, ##__VA_ARGS__);                                  \
	})

#define pr_dbg4(fmt, ...)                                                                          \
	({                                                                                         \
		if (dbg_domain[PR_DOMAIN] > 3)                                                     \
			__pr_dbg(PR_FMT ": " fmt, ##__VA_ARGS__);                                  \
	})

#define pr_err(fmt, ...)                                                                           \
	__pr_err_s(PR_FMT ": %s:%d:%s\n ERROR: " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define pr_err_ns(fmt, ...)                                                                        \
	__pr_err(PR_FMT ": %s:%d:%s\n ERROR: " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define pr_warn(fmt, ...) __pr_warn("WARN: " fmt, ##__VA_ARGS__)

#define pr_out(fmt, ...) __pr_out(fmt, ##__VA_ARGS__)
#define pr_cont(fmt, ...) __pr_out(fmt, ##__VA_ARGS__)
#define pr_use(fmt, ...) __pr_out("Usage: " fmt, ##__VA_ARGS__)

#define pr_red(fmt, ...) __pr_color(COLOR_CODE_RED, fmt, ##__VA_ARGS__)
#define pr_green(fmt, ...) __pr_color(COLOR_CODE_GREEN, fmt, ##__VA_ARGS__)
#define pr_blue(fmt, ...) __pr_color(COLOR_CODE_BLUE, fmt, ##__VA_ARGS__)
#define pr_yellow(fmt, ...) __pr_color(COLOR_CODE_YELLOW, fmt, ##__VA_ARGS__)
#define pr_magenta(fmt, ...) __pr_color(COLOR_CODE_MAGENTA, fmt, ##__VA_ARGS__)
#define pr_cyan(fmt, ...) __pr_color(COLOR_CODE_CYAN, fmt, ##__VA_ARGS__)
#define pr_bold(fmt, ...) __pr_color(COLOR_CODE_BOLD, fmt, ##__VA_ARGS__)
#define pr_gray(fmt, ...) __pr_color(COLOR_CODE_GRAY, fmt, ##__VA_ARGS__)
#define pr_color(c, fmt, ...) __pr_color(c, fmt, ##__VA_ARGS__)
#define pr_flush() fflush(outfp)

#define xmalloc(sz)                                                                                \
	({                                                                                         \
		void *__ptr = malloc(sz);                                                          \
		if (__ptr == NULL) {                                                               \
			pr_err("xmalloc");                                                         \
		}                                                                                  \
		__ptr;                                                                             \
	})

#define xzalloc(sz)                                                                                \
	({                                                                                         \
		void *__ptr = calloc(1, sz);                                                       \
		if (__ptr == NULL) {                                                               \
			pr_err("xzalloc");                                                         \
		}                                                                                  \
		__ptr;                                                                             \
	})

#define xcalloc(n, sz)                                                                             \
	({                                                                                         \
		void *__ptr = calloc(n, sz);                                                       \
		if (__ptr == NULL) {                                                               \
			pr_err("xcalloc");                                                         \
		}                                                                                  \
		__ptr;                                                                             \
	})

#define xrealloc(p, n)                                                                             \
	({                                                                                         \
		void *__ptr = realloc(p, n);                                                       \
		if (__ptr == NULL) {                                                               \
			pr_err("xrealloc");                                                        \
		}                                                                                  \
		__ptr;                                                                             \
	})

#define xstrdup(s)                                                                                 \
	({                                                                                         \
		void *__ptr = strdup(s);                                                           \
		if (__ptr == NULL) {                                                               \
			pr_err("xstrdup");                                                         \
		}                                                                                  \
		__ptr;                                                                             \
	})

#define xstrndup(s, sz)                                                                            \
	({                                                                                         \
		void *__ptr = strndup(s, sz);                                                      \
		if (__ptr == NULL) {                                                               \
			pr_err("xstrndup");                                                        \
		}                                                                                  \
		__ptr;                                                                             \
	})

#define xasprintf(s, fmt, ...)                                                                     \
	({                                                                                         \
		int __ret = asprintf(s, fmt, ##__VA_ARGS__);                                       \
		if (__ret < 0) {                                                                   \
			pr_err("xasprintf");                                                       \
		}                                                                                  \
		__ret;                                                                             \
	})

#define xvasprintf(s, fmt, ap)                                                                     \
	({                                                                                         \
		int __ret = vasprintf(s, fmt, ap);                                                 \
		if (__ret < 0) {                                                                   \
			pr_err("xvasprintf");                                                      \
		}                                                                                  \
		__ret;                                                                             \
	})

#define call_if_nonull(fptr, ...)                                                                  \
	({                                                                                         \
		if (fptr != NULL)                                                                  \
			fptr(__VA_ARGS__);                                                         \
	})

#define stringify(s) __stringify(s)
#define __stringify(s) #s

#ifndef htonq
#define htonq(x) htobe64(x)
#endif
#ifndef ntohq
#define ntohq(x) be64toh(x)
#endif
/* this comes from /usr/include/elf.h */
#ifndef ELFDATA2LSB
#define ELFDATA2LSB 1 /* 2's complement, little endian */
#define ELFDATA2MSB 2 /* 2's complement, big endian */
#endif

#ifndef ELFCLASS32
#define ELFCLASSNONE 0
#define ELFCLASS32 1
#define ELFCLASS64 2
#endif

static inline int get_elf_endian(void)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return ELFDATA2LSB;
#else
	return ELFDATA2MSB;
#endif
}

static inline int get_elf_class(void)
{
	if (sizeof(long) == 4)
		return ELFCLASS32;
	else if (sizeof(long) == 8)
		return ELFCLASS64;
	else
		return ELFCLASSNONE;
}

static inline bool host_is_lp64(void)
{
	return get_elf_class() == ELFCLASS64;
}

static inline const char *get_endian_str(void)
{
	if (get_elf_endian() == ELFDATA2LSB)
		return "LE";
	else
		return "BE";
}

static inline char *has_kernel_opt(char *buf)
{
	int idx = 0;

	if (!strncasecmp(buf, "kernel", 6))
		idx = 6;
	else if (!strncasecmp(buf, "k", 1))
		idx = 1;

	if (idx && (buf[idx] == '\0' || buf[idx] == ','))
		return buf;

	return NULL;
}

static inline char *has_kernel_filter(char *buf)
{
	char *opt = strchr(buf, '@');

	if (opt && has_kernel_opt(opt + 1))
		return opt;

	return NULL;
}

struct uftrace_time_range {
	uint64_t first;
	uint64_t start;
	uint64_t stop;
	bool start_elapsed;
	bool stop_elapsed;
	bool kernel_skip_out;
	bool event_skip_out;
};

struct iovec;

int read_all(int fd, void *buf, size_t size);
int pread_all(int fd, void *buf, size_t size, off_t off);
int fread_all(void *byf, size_t size, FILE *fp);
int write_all(int fd, const void *buf, size_t size);
int writev_all(int fd, struct iovec *iov, int count);
int fwrite_all(const void *buf, size_t size, FILE *fp);

int create_directory(const char *dirname);
int remove_directory(const char *dirname);
int chown_directory(const char *dirname);
char *read_exename(void);

extern clockid_t clock_source;
void setup_clock_id(const char *clock_str);

void print_time_unit(uint64_t delta_nsec);
void print_diff_percent(uint64_t base_nsec, uint64_t delta_nsec);
void print_diff_time_unit(uint64_t base_nsec, uint64_t pair_nsec);
void print_diff_count(uint64_t base, uint64_t pair);
void print_diff_percent_point(double base, double pair);

char *setup_pager(void);
void start_pager(char *pager);
void wait_for_pager(void);

bool check_time_range(struct uftrace_time_range *range, uint64_t timestamp);
uint64_t parse_time(char *arg, int limited_digits);
uint64_t parse_timestamp(char *arg);

char *strjoin(char *left, char *right, const char *delim);
char *json_quote(char *str, int *len);

/* strv - string vector */
struct strv {
	int nr; /* actual allocation is (nr + 1) */
	char **p; /* terminated by NULL (like argv[]) */
};

#define STRV_INIT                                                                                  \
	(struct strv)                                                                              \
	{                                                                                          \
		.nr = 0, .p = NULL,                                                                \
	}
#define strv_for_each(strv, s, i) for (i = 0; i < (strv)->nr && ((s) = (strv)->p[i]); i++)

void strv_split(struct strv *strv, const char *str, const char *delim);
void strv_copy(struct strv *strv, int argc, char *argv[]);
void strv_append(struct strv *strv, const char *str);
void strv_replace(struct strv *strv, int idx, const char *str);
char *strv_join(struct strv *strv, const char *delim);
void strv_free(struct strv *strv);
char *str_ltrim(char *str);
char *str_rtrim(char *str);

char **parse_cmdline(char *cmd, int *argc);
void free_parsed_cmdline(char **argv);

char *absolute_dirname(const char *path, char *resolved_path);

/* Do not modify the input path (unlike in POSIX version) */
static inline const char *uftrace_basename(const char *pathname)
{
	const char *p = strrchr(pathname, '/');

	return p ? p + 1 : pathname;
}

char *uftrace_strerror(int errnum, char *buf, size_t buflen);

void stacktrace(void);

#if defined(__x86_64__) || defined(__i386__)
#define TRAP() asm volatile("int $3")
#else
#define TRAP() raise(SIGTRAP)
#endif

#define DTRAP()                                                                                    \
	if (DEBUG_MODE) {                                                                          \
		TRAP();                                                                            \
	}

#define ASSERT(cond)                                                                               \
	if (unlikely(!(cond))) {                                                                   \
		pr_red("%s:%d: %s: ASSERT `%s' failed.\n", __FILE__, __LINE__, __func__, #cond);   \
		stacktrace();                                                                      \
		pr_red(BUG_REPORT_MSG);                                                            \
		pr_flush();                                                                        \
		TRAP();                                                                            \
	}

#define DASSERT(cond)                                                                              \
	if (DEBUG_MODE && unlikely(!(cond))) {                                                     \
		pr_red("%s:%d: %s: DEBUG ASSERT `%s' failed.\n", __FILE__, __LINE__, __func__,     \
		       #cond);                                                                     \
		stacktrace();                                                                      \
		pr_red(BUG_REPORT_MSG);                                                            \
		pr_flush();                                                                        \
		TRAP();                                                                            \
	}

int copy_file(const char *path_in, const char *path_out);

#endif /* UFTRACE_UTILS_H */
