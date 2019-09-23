#include <stdio.h>
#include <stdlib.h>

extern void test_jmp_prolog();
asm(
".type test_jmp_prolog, @function\n"
"test_jmp_prolog:\n"
#if defined(__x86_64__)
"   xor %rcx, %rcx\n"
"   inc %rcx\n"
"   cmp $2, %rcx\n"
"   jne test_jmp_prolog + 3\n" /* 3 size of xor reg, reg */
#elif defined(__i386__)
"   xor %ecx, %ecx\n"
"   inc %ecx\n"
"   cmp $2, %ecx\n"
"   jne test_jmp_prolog + 2\n" /* 2 size of xor reg, reg */
#endif
"   ret\n"
".size test_jmp_prolog, . -test_jmp_prolog\n"
);

int foo(int n)
{
	volatile int i = 0;
	int sum = 0;

	for (i = 0; i < n; i++)
		sum += i;

	return sum;
}

int bar(int n)
{
	int i = 0;
	volatile int sum = 0;

	for (i = 0; i < n; i++)
		sum += i;

	return sum;
}

int main(int argc, char *argv[])
{
	int n = 5;

	if (argc > 1)
		n = atoi(argv[1]);

	test_jmp_prolog();
	foo(n);
	bar(n);

	return 0;
}
