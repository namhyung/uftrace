#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
#define LTTNG_UST_TRACEPOINT_DEFINE

#include "__have_liblttng.h"

int main(int argc, char *argv[])
{
	lttng_ust_tracepoint(uftrace_check_deps, have_lttng);
	return 0;
}
