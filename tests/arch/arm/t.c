volatile int tcount;

extern void a2();

void __attribute__((noinline)) t1(void)
{
	a2();
	tcount++;
}

void __attribute__((noinline)) t2(void)
{
	tcount++;
}

