#define UNW_LOCAL_ONLY
#include <libunwind.h>

int main(void)
{
	unw_cursor_t cursor;
	unw_context_t context;

	unw_getcontext(&context);
	unw_init_local(&cursor, &context);

	return 0;
}
