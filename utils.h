#ifndef __FTRACE_UTILS_H__
#define __FTRACE_UTILS_H__

#include <stdlib.h>

#ifndef container_of
# define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define ARRAY_SIZE(a)  (sizeof(a) / sizeof(a[0]))

#define xmalloc(sz)							\
({ 	void *__ptr = malloc(sz);					\
	if (__ptr == NULL) {						\
		fprintf(stderr, "%s:%d:%s: memory allocation failed.\n",\
			__FILE__, __LINE__, __func__);			\
		exit(1);						\
	}								\
	__ptr;								\
})

#define xzalloc(sz)							\
({ 	void *__ptr = calloc(sz, 1);					\
	if (__ptr == NULL) {						\
		fprintf(stderr, "%s:%d:%s: memory allocation failed.\n",\
			__FILE__, __LINE__, __func__);			\
		exit(1);						\
	}								\
	__ptr;								\
})

#define xcalloc(sz, n)							\
({ 	void *__ptr = calloc(sz, n);					\
	if (__ptr == NULL) {						\
		fprintf(stderr, "%s:%d:%s: memory allocation failed.\n",\
			__FILE__, __LINE__, __func__);			\
		exit(1);						\
	}								\
	__ptr;								\
})

#define xstrdup(s)							\
({ 	void *__ptr = strdup(s);					\
	if (__ptr == NULL) {						\
		fprintf(stderr, "%s:%d:%s: memory allocation failed.\n",\
			__FILE__, __LINE__, __func__);			\
		exit(1);						\
	}								\
	__ptr;								\
})

#endif /* __FTRACE_UTILS_H__ */
