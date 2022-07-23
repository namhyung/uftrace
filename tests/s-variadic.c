#include <stdarg.h>
#include <stdio.h>

int variadic(const char *fmt, ...)
{
	va_list ap;
	int ret;
	char buf[256];

	va_start(ap, fmt);
	ret = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	return ret;
}

int main(void)
{
	variadic("print %c %s %d %ld %lu %lld %f", 'a', "hello", 100, 1234L, 5678UL, 9876543210ULL,
		 3.141592);
	return 0;
}
