#include <iostream>

static void print_int(int n)
{
	std::cout << n << std::endl;
}

extern "C" {
	void foo(int n)
	{
		print_int(n);
	}
}
