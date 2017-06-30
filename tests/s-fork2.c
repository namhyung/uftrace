#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

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
