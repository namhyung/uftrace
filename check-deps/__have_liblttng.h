#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER uftrace_check_deps

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "./__have_liblttng.h"

#if !defined(__HAVE_LIBLTTNG_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define __HAVE_LIBLTTNG_H

#include "lttng/tracepoint.h"

LTTNG_UST_TRACEPOINT_EVENT(uftrace_check_deps, have_lttng, LTTNG_UST_TP_ARGS(),
			   LTTNG_UST_TP_FIELDS())

#endif // __HAVE_LIBLTTNG_H

#include <lttng/tracepoint-event.h>
