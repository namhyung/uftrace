#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER lttng_ust_cyg_profile

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "libmcount/lttng-tp.h"

#if !defined(UFTRACE_LTTNG_TP_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define UFTRACE_LTTNG_TP_H

#include <lttng/tracepoint.h>

/* clang-format off */
LTTNG_UST_TRACEPOINT_EVENT(
	lttng_ust_cyg_profile,
	func_entry,
	LTTNG_UST_TP_ARGS(
		void *, func_addr,
		void *, call_site,
		long *, args,
		unsigned int, arg_count
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(unsigned long, addr,
			(unsigned long) func_addr)
		lttng_ust_field_integer_hex(unsigned long, call_site,
			(unsigned long) call_site)
		lttng_ust_field_sequence_hex(long, args, args, unsigned int, arg_count)
	)
)

LTTNG_UST_TRACEPOINT_LOGLEVEL(lttng_ust_cyg_profile, func_entry,
			LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_FUNCTION)

LTTNG_UST_TRACEPOINT_EVENT(
	lttng_ust_cyg_profile,
	func_exit,
	LTTNG_UST_TP_ARGS(
		void *, func_addr,
		void *, call_site,
		long , retval
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(unsigned long, addr,
			(unsigned long) func_addr)
		lttng_ust_field_integer_hex(unsigned long, call_site,
			(unsigned long) call_site)
		lttng_ust_field_integer_hex(long, retval, retval)
	)
)

LTTNG_UST_TRACEPOINT_LOGLEVEL(lttng_ust_cyg_profile, func_exit,
			LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_FUNCTION)
/* clang-format on */

#endif // UFTRACE_LTTNG_TP_H

#include <lttng/tracepoint-event.h>
