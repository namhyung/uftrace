#include <stdio.h>
#include <stdlib.h>

#define LOOP_CNT 4

int big(int n) {
	char string[] = "a local string variable saved in the stack memory";
	volatile unsigned x = n;
	int i;

	for (i = 0; i < LOOP_CNT; i++) {
		x *= 3 + i;
		x ^= 0xf0f0f0f0;
		x &= (1 << i) - 1;

		if (x == 0)
			x = (unsigned)string[i] << i;
	}
	return n;
}

int small(int n) {
	return big(n) ? n : 1;
}

int main(int argc, char *argv[]) {
	char string[] = "a very long string variable saved in the stack memory";
	int n = 123456;
	int i;

	if (argc > 1)
		n = atoi(argv[1]);
	else if (argc > 2)
		n = strtol(argv[1], NULL, atoi(argv[2]));

	small(n ? n : 123456);

	for (i = 0; i < LOOP_CNT; i++) {
		static volatile unsigned x = 42; 

		x *= 1 << i;
		x ^= 0xdeadbeef;
		x >>= i;

		if (x == 0)
			x = (unsigned)string[i] << i;
	}

	return n ? (n ^ n) : 0;
}
