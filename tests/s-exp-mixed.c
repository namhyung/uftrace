#include <stdio.h>

char *p;

double mixed_add(int a, float b)
{
	return a + b;
}

#if __clang__
__attribute__((optnone))
#endif
long mixed_sub(void *a, unsigned long b)
{
	return (long)a - b;
}

long long mixed_mul(double a, long long b)
{
	return a * b;
}

long double mixed_div(long long a, long double b, int c)
{
	return a / b;
}

char *mixed_str(char *a, double b)
{
	static char buf[32];

	p = a;
	if (b)
		snprintf(buf, sizeof(buf), "%.2f", b);

	return b ? buf : "return";
}

int main(int argc, char *argv[])
{
	int a, b, c, d;

	a = mixed_add(-1, 0.2);
	b = mixed_sub((void *)0x400000, 2048);
	c = mixed_mul(-3, 80000000000LL);
	d = mixed_div(4, -0.000002, 3);
	mixed_str("argument", 0);

	return (a + b + c + d) ? 0 : 1;
}
