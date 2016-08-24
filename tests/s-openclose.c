#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main(void)
{
	close(open("/dev/null", O_RDONLY));
	return 0;
}
