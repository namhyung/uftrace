/* This target program is intended for use with the agent. It executes a loop
 * and awaits for external input at each iteration.
 *
 * It accepts options so it can adapt its execution to test various agent
 * features.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int func(int depth);
static int a(int depth);
static int b(int depth);
static int c(int depth);

static int func(int depth)
{
	if (depth)
		return a(--depth) + 1;

	return 0;
}

static int a(int depth)
{
	if (depth)
		return b(--depth) + 1;

	return 0;
}

static int b(int depth)
{
	if (depth)
		return c(--depth) + 1;

	return 0;
}

static int c(int depth)
{
	if (getpid()) /* true */
		return depth;

	return -1; /* unreached */
}

int main(int argc, char *argv[])
{
	int i;
	int depth = 3;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--depth"))
			depth = atoi(argv[++i]);
	}

	do {
		func(depth);
	} while (getchar() != EOF);

	return 0;
}
