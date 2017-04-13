#ifndef __UFTRACE_UNIT_TEST_H__
#define __UFTRACE_UNIT_TEST_H__

#include <stdio.h>
#include <string.h>

enum {
	TEST_OK		= 0,	/* success */
	TEST_NG,		/* failed */
	TEST_SKIP,		/* skipped */
	TEST_SIG,		/* signal caught */
	TEST_BAD,		/* unknown result */
	TEST_MAX,
};

#define stringify(s)    __stringify(s)
#define __stringify(s)  #s

extern int debug;

#define __TEST_OP(a, op, b, file, line)  ({			\
	__typeof__(a) __a = (a);				\
	__typeof__(b) __b = (b);				\
								\
	if (!(__a op __b)) {					\
		if (debug)					\
			printf("test failed at %s:%d: %s\n",	\
			       file, line, stringify(a op b));	\
		/* return only if result is different */	\
		return TEST_NG;					\
	}							\
	TEST_OK;						\
})

#define TEST_EQ(a, b)  __TEST_OP(a, ==, b, __FILE__, __LINE__)
#define TEST_NE(a, b)  __TEST_OP(a, !=, b, __FILE__, __LINE__)
#define TEST_GT(a, b)  __TEST_OP(a, >,  b, __FILE__, __LINE__)
#define TEST_GE(a, b)  __TEST_OP(a, >=, b, __FILE__, __LINE__)
#define TEST_LT(a, b)  __TEST_OP(a, <,  b, __FILE__, __LINE__)
#define TEST_LE(a, b)  __TEST_OP(a, <=, b, __FILE__, __LINE__)

#define __TEST_STREQ(a, b, file, line)      ({			\
	if (strcmp((a), (b))) {					\
		if (debug)					\
			printf("test failed: %s\n",		\
			       stringify(a == b));		\
		return TEST_NG;					\
	}							\
	TEST_OK;						\
})
#define TEST_STREQ(a, b)  __TEST_STREQ((a), (b), __FILE, __LINE__)

#define __TEST_MEMEQ(a, b, sz, file, line)      ({		\
	if (memcmp((a), (b), (sz))) {				\
		if (debug)					\
			printf("test failed: %s\n",		\
			       stringify(a == b));		\
		return TEST_NG;					\
	}							\
	TEST_OK;						\
})
#define TEST_MEMEQ(a, b, sz)  __TEST_MEMEQ((a), (b), (sz), __FILE__, __LINE__)


#define TEST_SECTION  "uftrace.unit_test"

struct uftrace_unit_test {
	const char *name;
	int (*func)(void);
};

#define TEST_CASE(t)				\
extern int func_ ## t(void);			\
						\
__attribute__((section(TEST_SECTION),used))	\
const struct uftrace_unit_test test_ ## t = {	\
	.name = stringify(t),			\
	.func = func_ ## t,			\
};						\
						\
int func_ ## t(void)


#define TERM_COLOR_NORMAL	""
#define TERM_COLOR_RESET	"\033[0m"
#define TERM_COLOR_BOLD		"\033[1m"
#define TERM_COLOR_RED		"\033[31m"
#define TERM_COLOR_GREEN	"\033[32m"
#define TERM_COLOR_YELLOW	"\033[33m"

#endif /* __UFTRACE_UNIT_TEST_H__ */
