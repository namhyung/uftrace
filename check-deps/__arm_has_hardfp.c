int main(void)
{
	float f;

	asm volatile ("vstr %%s0, %0\n" : "=m" (f));
	return 0;
}
