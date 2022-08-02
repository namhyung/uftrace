static volatile int account;

extern volatile int tcount;
extern void t1(void);
extern void t2(void);

static void __attribute__((noinline)) a1(void)
{
	t1();
	account++;
}

void __attribute__((noinline)) a2(void)
{
	t2();
	account++;
}

int main(void)
{
	a1();
	return account + tcount;
}
