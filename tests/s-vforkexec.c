#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void __attribute__((noinline)) child(void)
{
	char buf[4096] = {};
	char *pos;
	int len;

	len = readlink("/proc/self/exe", buf, sizeof(buf));

	pos = strrchr(buf, '/');
	strcpy(pos, "/t-abc");
	execl(buf, "t-abc", NULL);
}

int main(int argc, char *argv[])
{
	int i;
	int n = 10;
	int pid;

	if (argc > 1)
		n = atoi(argv[1]);

	pid = vfork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		child();
		return -1;
	}

	wait(NULL);
	return n;
}
