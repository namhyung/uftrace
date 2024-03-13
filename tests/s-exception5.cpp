#include <stdlib.h>

int exception = 1;

struct A {
	A()
	{
		if (exception)
			throw 42;
	}
};

void f()
{
	static A a;
}

int main(int argc, char *argv[])
{
	if (argc > 1)
		exception = atoi(argv[1]);

	try {
		f();
	} catch (int d) {
	}
	return 0;
}
