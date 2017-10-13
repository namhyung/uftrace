#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/uio.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"

struct dlopen_base_data {
	const char *libname;
	unsigned long base_addr;
};

static const char *simple_basename(const char *pathname)
{
	const char *p = strrchr(pathname, '/');

	return p ? p + 1 : pathname;
}

static int dlopen_base_callback(struct dl_phdr_info *info,
				size_t size, void *arg)
{
	struct dlopen_base_data *data = arg;

	if (!strstr(simple_basename(info->dlpi_name), data->libname))
		return 0;

	data->base_addr = info->dlpi_addr;
	data->libname = info->dlpi_name; /* update to use full path */
	return 0;
}

static void send_dlopen_msg(struct mcount_thread_data *mtdp, const char *sess_id,
			    uint64_t timestamp,  uint64_t base_addr,
			    const char *libname)
{
	struct uftrace_msg_dlopen dlop = {
		.task = {
			.time = timestamp,
			.pid = getpid(),
			.tid = gettid(mtdp),
		},
		.base_addr = base_addr,
		.namelen = strlen(libname),
	};
	struct uftrace_msg msg = {
		.magic = UFTRACE_MSG_MAGIC,
		.type = UFTRACE_MSG_DLOPEN,
		.len = sizeof(dlop) + dlop.namelen,
	};
	struct iovec iov[3] = {
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = &dlop, .iov_len = sizeof(dlop), },
		{ .iov_base = (void *)libname, .iov_len = dlop.namelen, },
	};
	int len = sizeof(msg) + msg.len;

	if (pfd < 0)
		return;

	memcpy(dlop.sid, sess_id, sizeof(dlop.sid));

	if (writev(pfd, iov, 3) != len) {
		if (!mcount_should_stop())
			pr_err("write tid info failed");
	}
}

/*
 * hooking functions
 */
static int (*real_backtrace)(void **buffer, int sz);
static void (*real_cxa_throw)(void *exc, void *type, void *dest);
static void (*real_cxa_end_catch)(void);
static void * (*real_dlopen)(const char *filename, int flags);

void mcount_hook_functions(void)
{
	real_backtrace		= dlsym(RTLD_NEXT, "backtrace");
	real_cxa_throw		= dlsym(RTLD_NEXT, "__cxa_throw");
	real_cxa_end_catch	= dlsym(RTLD_NEXT, "__cxa_end_catch");
	real_dlopen		= dlsym(RTLD_NEXT, "dlopen");
}

__visible_default int backtrace(void **buffer, int sz)
{
	int ret;

	if (real_backtrace == NULL)
		return 0;

	mcount_rstack_restore();
	ret = real_backtrace(buffer, sz);
	mcount_rstack_reset();

	return ret;
}

__visible_default void __cxa_throw(void *exception, void *type, void *dest)
{
	struct mcount_thread_data *mtdp;

	/*
	 * restore return addresses so that it can unwind stack frames
	 * safely during the exception handling.
	 * It pairs to __cxa_end_catch().
	 */
	mcount_rstack_restore();

	mtdp = get_thread_data();
	if (!check_thread_data(mtdp))
		pr_dbg("exception thrown from [%d]\n", mtdp->idx);

	real_cxa_throw(exception, type, dest);
}

__visible_default void __cxa_end_catch(void)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;
	unsigned long retaddr;

	/* get frame address where exception handler returns */
	retaddr = (unsigned long)__builtin_frame_address(0);

	real_cxa_end_catch();

	pr_dbg("exception returned at frame: %#lx\n", retaddr);

	mtdp = get_thread_data();
	if (!check_thread_data(mtdp)) {
		int idx;

		/* it needs to find how much stack frame was unwinded */
		for (idx = mtdp->idx - 1; idx >= 0; idx--) {
			rstack = &mtdp->rstack[idx];

			pr_dbg2("[%d] parent at %p\n", idx, rstack->parent_loc);
			if (rstack->parent_loc == &mtdp->cygprof_dummy)
				break;

			if ((unsigned long)rstack->parent_loc > retaddr) {
				/* do not overwrite current return address */
				rstack->parent_ip = *rstack->parent_loc;
				break;
			}

			/* record unwinded functions */
			if (!(rstack->flags & MCOUNT_FL_NORECORD))
				rstack->end_time = mcount_gettime();

			mcount_exit_filter_record(mtdp, rstack, NULL);
		}

		/* we're in ENTER state, so add 1 to the index */
		mtdp->idx = idx + 1;
		pr_dbg("[%d] exception returned\n", mtdp->idx);

		mcount_rstack_reset();
	}
}

__visible_default void * dlopen(const char *filename, int flags)
{
	struct mcount_thread_data *mtdp;
	uint64_t timestamp = mcount_gettime();
	struct dlopen_base_data data;
	void *ret;

	if (unlikely(real_dlopen == NULL))
		mcount_hook_functions();

	ret = real_dlopen(filename, flags);

	if (unlikely(mcount_should_stop() || filename == NULL))
		return ret;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return ret;
	}
	else {
		if (unlikely(mtdp->recursion_guard))
			return ret;

		mtdp->recursion_guard = true;
	}

	data.libname = simple_basename(filename);
	dl_iterate_phdr(dlopen_base_callback, &data);

	/*
	 * get timestamp before calling dlopen() so that
	 * it can have symbols in static initializers which
	 * called during the dlopen.
	 */
	send_dlopen_msg(mtdp, session_name(), timestamp,
			data.base_addr, data.libname);

	mtdp->recursion_guard = false;
	return ret;
}

#ifdef UNIT_TEST

TEST_CASE(mcount_wrap_dlopen)
{
	void *handle;

	TEST_EQ(real_dlopen, NULL);

	handle= dlopen(NULL, RTLD_LAZY);

	TEST_NE(handle, NULL);
	TEST_NE(real_dlopen, NULL);

	return TEST_OK;
}

#endif /* UNIT_TEST */
