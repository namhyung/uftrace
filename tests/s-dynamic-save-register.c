/* Testing -fipa-ra optimization option.  */
#include <assert.h>

int __attribute__((noinline)) bar(int a, int b, int c, int d, int e, int f)
{
	asm("nopl   (%ebx,%ebx,1)");
	asm("nopl   (%ebx,%ebx,1)");
	return a + b + c + d + e + f + 3;
}

int __attribute__((noinline)) foo(int a, int b, int c, int d, int e, int f)
{
	asm("nopl   (%ebx,%ebx,1)");
	asm("nopl   (%ebx,%ebx,1)");

	int a_dup = a;
	int b_dup = b;
	int c_dup = c;
	int d_dup = d;
	int e_dup = e;
	int f_dup = f;
	a_dup += bar(a,b,c,d,e,f);
	b_dup += bar(a,b,c,d,e,f);
	c_dup += bar(a,b,c,d,e,f);
	d_dup += bar(a,b,c,d,e,f);
	e_dup += bar(a,b,c,d,e,f);
	f_dup += bar(a,b,c,d,e,f);

	return bar(a_dup,b_dup,c_dup,d_dup,e_dup,f_dup);
}

int main (void)
{
	asm("nopl   (%ebx,%ebx,1)");
	asm("nopl   (%ebx,%ebx,1)");

	assert(foo(1,1,1,1,1,1) == 63);
	return 0;
}
