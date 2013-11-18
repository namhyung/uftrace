static int a(void);
static int b(void);
static int c(void);

static int a(void)
{
	return b();
}

static int b(void)
{
	return c();
}

static int c(void)
{
	return 0;
}

int main(void)
{
	return a();
}
