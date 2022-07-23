#include <stdlib.h>
#include <ucontext.h>
#include <unistd.h>

int foo(ucontext_t *old, ucontext_t *new)
{
	swapcontext(old, new);
}

int bar(int c)
{
	return c + getpid();
}

int baz(int c)
{
	return c % 2;
}

#define STACKSIZE 8192

int main(int argc, char *argv[])
{
	int n = 10;
	char stack[STACKSIZE];
	ucontext_t curr, new;

	if (argc > 1)
		n = atoi(argv[1]);

	getcontext(&new);
	new.uc_link = &curr;
	new.uc_stack.ss_sp = stack;
	new.uc_stack.ss_size = STACKSIZE;

	makecontext(&new, (void (*)(void))bar, 1, n);

	foo(&curr, &new);
	n = baz(n);

	return !(n < 2);
}
