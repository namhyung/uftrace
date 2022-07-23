#include <float.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct large {
	char buf[4096];
};

struct small {
	unsigned char bit : 1;
};

struct large return_large(char patt)
{
	struct large l;

	memset(l.buf, patt, sizeof(l.buf));

	return l;
}

#if __clang__
__attribute__((optnone))
#endif
struct small
return_small(void)
{
	struct small s = { .bit = 1 };
	return s;
}

#if __clang__
__attribute__((optnone))
#endif
long double
return_long_double(void)
{
	return LDBL_MAX;
}

int main(void)
{
	struct large l;
	struct small s;
	long double ld;

	l = return_large(1);
	if (l.buf[10] != 1)
		return 1;

	s = return_small();
	if (s.bit != 1)
		return 1;

	ld = return_long_double();
	if (ld != LDBL_MAX)
		return 1;

	return 0;
}
