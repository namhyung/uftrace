#include <stdio.h>

extern int lib_a(int i);
extern int lib_d(int i);

int main(void)
{
	int res = lib_a(1111);
	res += lib_d(4444);

	return 0;
}
