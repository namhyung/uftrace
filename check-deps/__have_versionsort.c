#define _GNU_SOURCE
#include <dirent.h>

int main(void)
{
	const struct dirent d1 = {.d_ino = 1, .d_name = "B1"};
	const struct dirent d2 = {.d_ino = 2, .d_name = "A2"};
	const struct dirent *dp1 = &d1;
	const struct dirent *dp2 = &d1;
	versionsort(&dp1, &dp2);
	return 0;
}
