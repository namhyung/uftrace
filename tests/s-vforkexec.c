#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
	int i;
	char *n = "10";
	int pid;

	if (argc > 1)
		n = argv[1];

	pid = vfork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		char buf[4096] = {};
		char *pos;
		int len;

		len = readlink("/proc/self/exe", buf, sizeof(buf));

		pos = strrchr(buf, '/');
		strcpy(pos, "/t-abc");
		execl(buf, "t-abc", n, NULL);
		return -1;
	}

	wait(NULL);
	return 0;
}
