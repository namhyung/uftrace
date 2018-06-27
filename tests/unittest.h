#ifndef UFTRACE_UNIT_TEST_H
#define UFTRACE_UNIT_TEST_H

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

#define __TEST_NG(file, line, test)	({			\
	if (debug)						\
		printf("test failed at %s:%d: %s\n",		\
			file, line, test);			\
	return TEST_NG;						\
})

#define __TEST_OP(a, op, b, file, line)  ({			\
	__typeof__(a) __a = (a);				\
	__typeof__(b) __b = (b);				\
								\
	if (!(__a op __b))					\
		__TEST_NG(file, line, stringify(a op b));	\
	TEST_OK;						\
})

#define TEST_EQ(a, b)  __TEST_OP(a, ==, b, __FILE__, __LINE__)
#define TEST_NE(a, b)  __TEST_OP(a, !=, b, __FILE__, __LINE__)
#define TEST_GT(a, b)  __TEST_OP(a, >,  b, __FILE__, __LINE__)
#define TEST_GE(a, b)  __TEST_OP(a, >=, b, __FILE__, __LINE__)
#define TEST_LT(a, b)  __TEST_OP(a, <,  b, __FILE__, __LINE__)
#define TEST_LE(a, b)  __TEST_OP(a, <=, b, __FILE__, __LINE__)

#define __TEST_STREQ(a, b, file, line)      ({			\
	if (strcmp((a), (b)))					\
		__TEST_NG(file, line, stringify(a == b));	\
	TEST_OK;						\
})
#define TEST_STREQ(a, b)  __TEST_STREQ((a), (b), __FILE__, __LINE__)

#define __TEST_MEMEQ(a, b, sz, file, line)      ({		\
	if (memcmp((a), (b), (sz)))				\
		__TEST_NG(file, line, stringify(a == b));	\
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
#define TERM_COLOR_RED		"\033[91m"
#define TERM_COLOR_GREEN	"\033[32m"
#define TERM_COLOR_YELLOW	"\033[33m"

#endif /* UFTRACE_UNIT_TEST_H */
