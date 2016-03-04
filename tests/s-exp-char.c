#include <stdint.h>

char foo(char a, unsigned char b, int8_t c)
{
	return 'd';
}

char bar(char a, char b, char c, char d)
{
	return 0;
}

int main(void)
{
	char d;

	d = foo('f', 'o', 'o');
	d += bar(0, 'B', 'a', 'r');

	return d == 'd' ? 0 : 1;
}
