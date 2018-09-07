#include <signal.h>

enum foo_enum {
	XXX = 1,
	YYY,
};

void foo(enum foo_enum a)
{
	static volatile int i;

	i += a;
}

int main(int argc, char *argv[])
{
	kill(0, 0);
	foo(0);
	foo(XXX);
	return 0;
}
