#ifndef __FTRACE_UTILS_H__
#define __FTRACE_UTILS_H__

#include <stdlib.h>
#include <stdbool.h>

#ifndef container_of
# define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#ifndef ALIGN
# define ALIGN(n, a)  (((n) + (a) - 1) & ~((a) - 1))
#endif

extern int debug;
extern int logfd;

extern void pr_dbg(const char *fmt, ...);
extern void pr_dbg2(const char *fmt, ...);
extern void pr_log(const char *fmt, ...);
extern void pr_err(const char *fmt, ...) __attribute__((noreturn));

#ifdef HAVE_LIBIBERTY
# include <libiberty.h>
#else

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)  (sizeof(a) / sizeof(a[0]))
#endif

#define xmalloc(sz)							\
({ 	void *__ptr = malloc(sz);					\
	if (__ptr == NULL) {						\
		pr_err("%s:%d:%s: memory allocation failed.\n",		\
			__FILE__, __LINE__, __func__);			\
	}								\
	__ptr;								\
})

#define xzalloc(sz)							\
({ 	void *__ptr = calloc(sz, 1);					\
	if (__ptr == NULL) {						\
		pr_err("%s:%d:%s: memory allocation failed.\n",		\
			__FILE__, __LINE__, __func__);			\
	}								\
	__ptr;								\
})

#define xcalloc(sz, n)							\
({ 	void *__ptr = calloc(sz, n);					\
	if (__ptr == NULL) {						\
		pr_err("%s:%d:%s: memory allocation failed.\n",		\
			__FILE__, __LINE__, __func__);			\
	}								\
	__ptr;								\
})

#define xrealloc(p, n)							\
({ 	void *__ptr = realloc(p, n);					\
	if (__ptr == NULL) {						\
		pr_err("%s:%d:%s: memory allocation failed.\n",		\
			__FILE__, __LINE__, __func__);			\
	}								\
	__ptr;								\
})

#define xstrdup(s)							\
({ 	void *__ptr = strdup(s);					\
	if (__ptr == NULL) {						\
		pr_err("%s:%d:%s: memory allocation failed.\n",		\
			__FILE__, __LINE__, __func__);			\
	}								\
	__ptr;								\
})

#define xstrndup(s, sz)							\
({ 	void *__ptr = strndup(s, sz);					\
	if (__ptr == NULL) {						\
		pr_err("%s:%d:%s: memory allocation failed.\n",		\
			__FILE__, __LINE__, __func__);			\
	}								\
	__ptr;								\
})
#endif /* HAVE_LIBIBERTY */

#endif /* __FTRACE_UTILS_H__ */
