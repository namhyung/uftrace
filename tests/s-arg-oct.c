#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
	const char *pathname = "bar.foo";

	creat(pathname, 0755);
	chmod(pathname, 0777);
	unlink(pathname);

	return 0;
}
