#include <stdio.h>

char *gs;
char gc;
double gd;

enum xx {
	ONE = 1,
	TWO,
};

void null(char *s)
{
}

int foo(volatile int a, long b)
{
	return a + b;
}

float bar(char *s, char c, double d, void (*fp)(char *s))
{
	gs = s;
	gc = c;
	gd = d;
	fp(NULL);
	return -1.0;
}

void baz(enum xx x)
{
	foo(x, -1);
}

int main(void)
{
	foo(-1, 32768);
	bar("string argument", 'c', 0.00001, null);
	baz(ONE);

	return 0;
}
