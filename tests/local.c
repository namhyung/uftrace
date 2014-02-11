static void __attribute__((noinline)) bar(volatile unsigned char *c)
{
	struct {
		long l;
		long long ll;
		unsigned long ul;
		unsigned long long ull;
		char ac[1024];
	} t = { .l = 1, };

	if (sizeof(t) > (*c) * 256)
		*c = sizeof(t) / 256;
	else
		*c = 128 * t.l;
}

static int __attribute__((noinline)) foo(int a)
{
	volatile unsigned char buf[128] = { 0, 1, 2, };

	if (a > 1)
		buf[0] = 1;
	else
		buf[0] = 0;
	buf[1]++;

	bar(&buf[2]);
	return buf[0] * buf[1] + buf[2];
}

int main(void)
{
	return foo(1) + foo(2);
}
