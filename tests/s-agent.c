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

static int func(int depth, char *s);
static int trigger(int depth, char *s);
static int a(int depth);
static int b(int depth);
static int c(int depth);

#define CAFE 0xCAFE
#define DELAY 1000
static int use_delay;

/* accessed by func and trigger in different ways so they don't get merged by
   the compiler */
static int dummy;

static int func(int depth, char *s)
{
	dummy++;
	(*(__volatile__ __typeof__(s) *)&(s)); /* prevent compiler optimization for s */
	if (depth)
		return a(--depth) + 1;

	return CAFE;
}

static int trigger(int depth, char *s)
{
	dummy--;
	(*(__volatile__ __typeof__(s) *)&(s)); /* prevent compiler optimization for s */
	if (depth)
		return a(--depth) + 1;

	return CAFE;
}

static int a(int depth)
{
	if (use_delay)
		usleep(DELAY);
	if (depth)
		return b(--depth) + 1;

	return CAFE;
}

static int b(int depth)
{
	if (use_delay)
		usleep(DELAY);
	if (depth)
		return c(--depth) + 1;

	return CAFE;
}

static int c(int depth)
{
	if (use_delay)
		usleep(DELAY);
	if (getpid()) /* true */
		return CAFE - depth;

	return -1; /* unreached */
}

int main(int argc, char *argv[])
{
	int i;
	int depth = 3;
	int use_trigger = 0;
	char *s = NULL;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--depth"))
			depth = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--trigger"))
			use_trigger = 1;
		else if (!strcmp(argv[i], "--delay"))
			use_delay = 1;
		else
			s = argv[i];
	}

	if (depth <= 0)
		depth = 1;

	do {
		func(depth, s);
		if (use_trigger)
			trigger(depth, s);
	} while (getchar() != EOF);

	return 0;
}
