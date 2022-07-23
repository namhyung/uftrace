#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
	switch (fork()) {
	case -1:
		return 1;
	default:
		wait(NULL);
		/* fall through */
	case 0:
		close(open("/dev/null", O_RDONLY));
		break;
	}

	return 0;
}
