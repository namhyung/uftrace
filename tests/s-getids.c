#include <unistd.h>

int main(int argc, char *argv[])
{
	getpid();
	getppid();
	getpgid(0);
	getsid(0);
	getuid();
	geteuid();
	getgid();
	getegid();
	return 0;
}
