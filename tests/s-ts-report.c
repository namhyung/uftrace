/*
* This is a test binary for verifying min/max timestamp fields in report.
 *
 * foo() is called twice with different self/child time distributions:
 * call 1: small self, large child (5M) -> total=large, self=small
 * call 2: large self (2M), small child -> total=small, self=large
 *
 * So:
 * total-min-ts = timestamp of call 2 (later)
 * self-min-ts  = timestamp of call 1 (earlier)
 * total-min-ts > self-min-ts
 */

void child(int iters)
{
	volatile int x = 0;
	int i;

	for (i = 0; i < iters; i++)
		x++;
}

void foo(int self_iters, int child_iters)
{
	volatile int x = 0;
	int i;

	for (i = 0; i < self_iters; i++)
		x++;

	child(child_iters);
}

int main(void)
{
	foo(100, 5000000); /* call 1: small self, large child */
	foo(2000000, 100); /* call 2: large self, small child */
	return 0;
}
