/*
 * This is to test "uftrace_print()" to record interval variables in the middle
 * of functions.
 */
#include <stdio.h>
#include <uftrace.h>

/* adds some holes/pads in purpose */
struct big {
	char c;
	double d;
	short s;
	long double ld;
	char *str;
	int i;
	unsigned long long ull;
	long l;
};

int check(struct big val, struct big *ref)
{
	uftrace_print(val.c);
	uftrace_print(ref->d);
	uftrace_print(val.s);
	uftrace_print(ref->ld);
	uftrace_print(val.i);
	uftrace_print(ref->ull);
	uftrace_print(val.l);
	uftrace_print("string test!");
	uftrace_print(val.str);
	uftrace_print(ref->str);
	return 0;
}

int pass(int n)
{
	struct big b = { 'b', 3.14, -1, 2.71828, "hello", n, 987654321ULL, 12345L };
	uftrace_print(&b);
	return check(b, &b);
}

int main()
{
	unsigned n = 3;
	pass(n);

	return 0;
}
