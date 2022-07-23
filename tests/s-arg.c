/*
 * This is to test uftrace can work well with passing various arguments
 * to the functions.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *strs[] = { "a", "b", "c" };
const unsigned nr_strs = sizeof(strs) / sizeof(strs[0]);

const int ints[] = { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144 };
const unsigned nr_ints = sizeof(ints) / sizeof(ints[0]);

/* adds some holes/pads in purpose */
struct big {
	char c;
	double d;
	short s;
	long double ld;
	int i;
	unsigned long long ull;
	long l;
};

int bar(unsigned n, const char *str)
{
	if (n >= nr_strs)
		return strcmp("foo", str);
	return strcmp(strs[n], str);
}

int foo(unsigned n)
{
	unsigned int i;

	while (n-- > 0) {
		const char *str = n >= nr_strs ? "foo" : strs[n];

		if (bar(n, str) != 0)
			return -1;
	}
	return 0;
}

int many(unsigned argc, ...)
{
	unsigned i;
	va_list ap;

	va_start(ap, argc);
	for (i = 0; i < argc; i++) {
		if (ints[i] != va_arg(ap, int))
			return -1;
	}
	va_end(ap);

	return 0;
}

int check(struct big val, struct big *ref)
{
	if (val.c != ref->c)
		return -1;
	if (val.d != ref->d)
		return -1;
	if (val.s != ref->s)
		return -1;
	if (val.ld != ref->ld)
		return -1;
	if (val.i != ref->i)
		return -1;
	if (val.ull != ref->ull)
		return -1;
	if (val.l != ref->l)
		return -1;
	return 0;
}

int pass(int n)
{
	struct big b = { 'b', 3.14, -1, 2.71828, n, 987654321ULL, 12345L };
	return check(b, &b);
}

int main(int argc, char *argv[])
{
	unsigned n = 3;

	if (argc > 1)
		n = atoi(argv[1]);

	if (foo(n) < 0)
		return 1;
	if (many(nr_ints, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144) < 0)
		return 1;
	if (pass(n) < 0)
		return 1;
	return 0;
}
