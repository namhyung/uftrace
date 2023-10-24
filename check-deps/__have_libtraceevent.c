#include <event-parse.h>

int main(void)
{
	struct tep_handle *tep;

	tep = tep_alloc();
	tep_free(tep);

	return 0;
}
