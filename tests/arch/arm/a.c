static volatile int acount;

extern volatile int tcount;
extern void t1(void);
extern void t2(void);

static void __attribute__((noinline)) a1(void)
{
	t1();
	acount++;
}

void __attribute__((noinline)) a2(void)
{
	t2();
	acount++;
}

int main(void)
{
	a1();
	return acount + tcount;
}

