#include <stdint.h>

char ga;
char gb;
char gc;
char gd;

char foo(char a, char b, char c)
{
	ga = a;
	gb = b;
	gc = c;
	return 'd';
}

char bar(char a, char b, char c, char d)
{
	ga = a;
	gb = b;
	gc = c;
	gd = d;
	return 0;
}

int main(void)
{
	char d;

	d = foo('f', 'o', 'o');
	d += bar(0, 'B', 'a', 'r');

	return d == 'd' ? 0 : 1;
}
