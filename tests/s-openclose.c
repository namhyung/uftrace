#include <stdio.h>

int main(void)
{
	fclose(fopen("/dev/null", "r"));
	return 0;
}
