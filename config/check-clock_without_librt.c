#include <time.h>

int main(void)
{
	return clock_gettime(CLOCK_MONOTONIC, 0);
}
