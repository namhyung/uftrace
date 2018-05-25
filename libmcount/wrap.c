#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/uio.h>
#include <spawn.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/compiler.h"

extern struct symtabs symtabs;

struct dlopen_base_data {
	struct mcount_thread_data *mtdp;
	uint64_t timestamp;
};


static const char *simple_basename(const char *pathname)
{
	const char *p = strrchr(pathname, '/');

	return p ? p + 1 : pathname;
}

static void send_dlopen_msg(struct mcount_thread_data *mtdp, const char *sess_id,
			    uint64_t timestamp,  uint64_t base_addr,
			    const char *libname)
{
	struct uftrace_msg_dlopen dlop = {
		.task = {
			.time = timestamp,
			.pid = getpid(),
			.tid = mcount_gettid(mtdp),
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

	mcount_memcpy4(dlop.sid, sess_id, sizeof(dlop.sid));

	if (writev(pfd, iov, 3) != len) {
		if (!mcount_should_stop())
			pr_err("write tid info failed");
	}
}

static int dlopen_base_callback(struct dl_phdr_info *info,
				size_t size, void *arg)
{
	struct dlopen_base_data *data = arg;
	char buf[PATH_MAX];
	char *p;

	if (info->dlpi_name[0] == '\0')
		return 0;
	if (!strcmp("linux-vdso.so.1", info->dlpi_name))
		return 0;

	p = realpath(info->dlpi_name, buf);
	if (p == NULL)
		p = buf;

	if (find_map_by_name(&symtabs, simple_basename(p)))
		return 0;

	/* report a library not found in the session maps */
	send_dlopen_msg(data->mtdp, mcount_session_name(), data->timestamp,
			info->dlpi_addr, info->dlpi_name);
	return 0;
}

void mcount_rstack_reset_exception(struct mcount_thread_data *mtdp,
				   unsigned long frame_addr)
{
	int idx;
	struct mcount_ret_stack *rstack;

	/* it needs to find how much stack frame was unwinded */
	for (idx = mtdp->idx - 1; idx >= 0; idx--) {
		rstack = &mtdp->rstack[idx];

		pr_dbg2("[%d] parent at %p\n", idx, rstack->parent_loc);
		if (rstack->parent_loc == &mtdp->cygprof_dummy)
			break;

		if ((unsigned long)rstack->parent_loc > frame_addr) {
			/*
			 * there might be tail call optimizations in the
			 * middle of the exception handling path.
			 * in that case, we need to keep the original
			 * mtdp->idx but update parent address of the
			 * first rstack of the tail call chain.
			 */
			int orig_idx = idx;

			while (idx > 0) {
				struct mcount_ret_stack *tail_call;
				tail_call = &mtdp->rstack[idx - 1];

				if (rstack->parent_loc != tail_call->parent_loc)
					break;

				idx--;
				rstack = tail_call;
				pr_dbg2("exception in tail call at [%d]\n", idx + 1);
			}
			idx = orig_idx;

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
	pr_dbg2("exception returned to [%d]\n", mtdp->idx);

	mcount_rstack_reset(mtdp);
}

static char ** collect_uftrace_envp(void)
{
	size_t n = 0;
	size_t i, k;
	char **envp;

#define ENV(_name)  "UFTRACE_" #_name

	const char *const uftrace_env[] = {
		ENV(FILTER), ENV(TRIGGER), ENV(ARGUMENT), ENV(RETVAL),
		ENV(AUTO_ARGS), ENV(DEPTH), ENV(DISABLED), ENV(PIPE),
		ENV(LOGFD), ENV(DEBUG), ENV(BUFFER), ENV(MAX_STACK),
		ENV(COLOR), ENV(THRESHOLD), ENV(DEMANGLE), ENV(PLTHOOK),
		ENV(PATCH), ENV(EVENT), ENV(SCRIPT), ENV(NEST_LIBCALL),
		ENV(DEBUG_DOMAIN), ENV(LIST_EVENT), ENV(DIR),
		ENV(KERNEL_PID_UPDATE), ENV(PATTERN),
		/* not uftrace-specific, but necessary to run */
		"LD_PRELOAD", "LD_LIBRARY_PATH",
	};

#undef ENV

	for (i = 0; i < ARRAY_SIZE(uftrace_env); i++) {
		if (getenv(uftrace_env[i]))
			n++;
	}

	envp = xcalloc(sizeof(*envp), n + 2);

	for (i = k = 0; i < ARRAY_SIZE(uftrace_env); i++) {
		char *env_str;
		char *env_val;

		env_val = getenv(uftrace_env[i]);
		if (env_val == NULL)
			continue;

		xasprintf(&env_str, "%s=%s", uftrace_env[i], env_val);
		envp[k++] = env_str;
	}

	return envp;
}

static char ** merge_envp(char *const *env1, char **env2)
{
	int i, n = 0;
	char **envp;

	for (i = 0; env1 && env1[i]; i++)
		n++;
	for (i = 0; env2 && env2[i]; i++)
		n++;


	envp = xcalloc(sizeof(*envp), n + 1);

	n = 0;
	for (i = 0; env1 && env1[i]; i++)
		envp[n++] = env1[i];
	for (i = 0; env2 && env2[i]; i++)
		envp[n++] = env2[i];

	return envp;
}

/*
 * hooking functions
 */
static int (*real_backtrace)(void **buffer, int sz);
static void (*real_cxa_throw)(void *exc, void *type, void *dest);
static void (*real_cxa_rethrow)(void);
static void * (*real_cxa_begin_catch)(void *exc);
static void (*real_cxa_end_catch)(void);
static void * (*real_dlopen)(const char *filename, int flags);
static __noreturn void (*real_pthread_exit)(void *retval);
static void (*real_unwind_resume)(void *exc);
static int (*real_posix_spawn)(pid_t *pid, const char *path,
			       const posix_spawn_file_actions_t *actions,
			       const posix_spawnattr_t *attr,
			       char *const argv[], char *const envp[]);
static int (*real_posix_spawnp)(pid_t *pid, const char *file,
				const posix_spawn_file_actions_t *actions,
				const posix_spawnattr_t *attr,
				char *const argv[], char *const envp[]);
/* TODO: support execle() */
static int (*real_execve)(const char *path, char *const argv[],
			  char *const envp[]);
static int (*real_execvpe)(const char *file, char *const argv[],
			   char *const envp[]);
static int (*real_fexecve)(int fd, char *const argv[], char *const envp[]);

void mcount_hook_functions(void)
{
	real_backtrace		= dlsym(RTLD_NEXT, "backtrace");
	real_cxa_throw		= dlsym(RTLD_NEXT, "__cxa_throw");
	real_cxa_rethrow	= dlsym(RTLD_NEXT, "__cxa_rethrow");
	real_cxa_begin_catch	= dlsym(RTLD_NEXT, "__cxa_begin_catch");
	real_cxa_end_catch	= dlsym(RTLD_NEXT, "__cxa_end_catch");
	real_dlopen		= dlsym(RTLD_NEXT, "dlopen");
	real_pthread_exit	= dlsym(RTLD_NEXT, "pthread_exit");
	real_unwind_resume	= dlsym(RTLD_NEXT, "_Unwind_Resume");
	real_posix_spawn	= dlsym(RTLD_NEXT, "posix_spawn");
	real_posix_spawnp	= dlsym(RTLD_NEXT, "posix_spawnp");
	real_execve		= dlsym(RTLD_NEXT, "execve");
	real_execvpe		= dlsym(RTLD_NEXT, "execvpe");
	real_fexecve		= dlsym(RTLD_NEXT, "fexecve");
}

__visible_default int backtrace(void **buffer, int sz)
{
	int ret;
	struct mcount_thread_data *mtdp;

	if (unlikely(real_backtrace == NULL))
		mcount_hook_functions();

	mtdp = get_thread_data();
	if (!check_thread_data(mtdp))
		mcount_rstack_restore(mtdp);

	ret = real_backtrace(buffer, sz);

	if (!check_thread_data(mtdp))
		mcount_rstack_reset(mtdp);

	return ret;
}

__visible_default void __cxa_throw(void *exception, void *type, void *dest)
{
	struct mcount_thread_data *mtdp;

	if (unlikely(real_cxa_throw == NULL))
		mcount_hook_functions();

	mtdp = get_thread_data();
	if (!check_thread_data(mtdp)) {
		pr_dbg("exception thrown from [%d]\n", mtdp->idx);

		mtdp->in_exception = true;

		/*
		 * restore return addresses so that it can unwind stack
		 * frames safely during the exception handling.
		 * It pairs to mcount_rstack_reset_exception().
		 */
		mcount_rstack_restore(mtdp);
	}

	real_cxa_throw(exception, type, dest);
}

__visible_default void __cxa_rethrow(void)
{
	struct mcount_thread_data *mtdp;

	if (unlikely(real_cxa_rethrow == NULL))
		mcount_hook_functions();

	mtdp = get_thread_data();
	if (!check_thread_data(mtdp)) {
		pr_dbg("exception rethrown from [%d]\n", mtdp->idx);

		mtdp->in_exception = true;

		/*
		 * restore return addresses so that it can unwind stack
		 * frames safely during the exception handling.
		 * It pairs to mcount_rstack_reset_exception()
		 */
		mcount_rstack_restore(mtdp);
	}

	real_cxa_rethrow();
}

__visible_default void _Unwind_Resume(void *exception)
{
	struct mcount_thread_data *mtdp;

	if (unlikely(real_unwind_resume == NULL))
		mcount_hook_functions();

	mtdp = get_thread_data();
	if (!check_thread_data(mtdp)) {
		pr_dbg2("exception resumed on [%d]\n", mtdp->idx);

		mtdp->in_exception = true;

		/*
		 * restore return addresses so that it can unwind stack
		 * frames safely during the exception handling.
		 * It pairs to mcount_rstack_reset_exception().
		 */
		mcount_rstack_restore(mtdp);
	}

	real_unwind_resume(exception);
}

__visible_default void * __cxa_begin_catch(void *exception)
{
	struct mcount_thread_data *mtdp;
	void *obj;

	if (unlikely(real_cxa_begin_catch == NULL))
		mcount_hook_functions();

	obj = real_cxa_begin_catch(exception);

	mtdp = get_thread_data();
	if (!check_thread_data(mtdp) && unlikely(mtdp->in_exception)) {
		unsigned long *frame_ptr;
		unsigned long frame_addr;

		frame_ptr = __builtin_frame_address(0);
		frame_addr = *frame_ptr;  /* XXX: probably dangerous */

		/* basic sanity check */
		if (frame_addr < (unsigned long)frame_ptr)
			frame_addr = (unsigned long)frame_ptr;

		mcount_rstack_reset_exception(mtdp, frame_addr);
		mtdp->in_exception = false;
	}

	return obj;
}

__visible_default void __cxa_end_catch(void)
{
	if (unlikely(real_cxa_end_catch == NULL))
		mcount_hook_functions();

	real_cxa_end_catch();
}

__visible_default void * dlopen(const char *filename, int flags)
{
	struct mcount_thread_data *mtdp;
	struct dlopen_base_data data = {
		.timestamp = mcount_gettime(),
	};
	void *ret;

	/*
	 * get timestamp before calling dlopen() so that
	 * it can have symbols in static initializers which
	 * called during the dlopen.
	 */

	if (unlikely(real_dlopen == NULL))
		mcount_hook_functions();

	ret = real_dlopen(filename, flags);

	if (filename == NULL)
		return ret;

	mtdp = get_thread_data();
	if (unlikely(check_thread_data(mtdp))) {
		mtdp = mcount_prepare();
		if (mtdp == NULL)
			return ret;
	}
	else {
		if (!mcount_guard_recursion(mtdp, false))
			return ret;
	}

	data.mtdp = mtdp;
	dl_iterate_phdr(dlopen_base_callback, &data);

	mcount_unguard_recursion(mtdp);
	return ret;
}

__visible_default __noreturn void pthread_exit(void *retval)
{
	struct mcount_thread_data *mtdp;
	struct mcount_ret_stack *rstack;

	if (unlikely(real_pthread_exit == NULL))
		mcount_hook_functions();

	mtdp = get_thread_data();
	if (!check_thread_data(mtdp)) {
		rstack = &mtdp->rstack[mtdp->idx - 1];
		mcount_exit_filter_record(mtdp, rstack, NULL);
		mcount_rstack_restore(mtdp);
	}

	real_pthread_exit(retval);
}

__visible_default int posix_spawn(pid_t *pid, const char *path,
				  const posix_spawn_file_actions_t *actions,
				  const posix_spawnattr_t *attr,
				  char *const argv[], char *const envp[])
{
	char **uftrace_envp;
	char **new_envp;

	if (unlikely(real_posix_spawn == NULL))
		mcount_hook_functions();

	uftrace_envp = collect_uftrace_envp();
	new_envp = merge_envp(envp, uftrace_envp);

	return real_posix_spawn(pid, path, actions, attr, argv, new_envp);
}

__visible_default int posix_spawnp(pid_t *pid, const char *file,
				   const posix_spawn_file_actions_t *actions,
				   const posix_spawnattr_t *attr,
				   char *const argv[], char *const envp[])
{
	char **uftrace_envp;
	char **new_envp;

	if (unlikely(real_posix_spawnp == NULL))
		mcount_hook_functions();

	uftrace_envp = collect_uftrace_envp();
	new_envp = merge_envp(envp, uftrace_envp);

	return real_posix_spawnp(pid, file, actions, attr, argv, new_envp);
}

__visible_default int execve(const char *path, char *const argv[],
			     char *const envp[])
{
	char **uftrace_envp;
	char **new_envp;

	if (unlikely(real_execve == NULL))
		mcount_hook_functions();

	uftrace_envp = collect_uftrace_envp();
	new_envp = merge_envp(envp, uftrace_envp);

	return real_execve(path, argv, new_envp);
}

__visible_default int execvpe(const char *file, char *const argv[],
			      char *const envp[])
{
	char **uftrace_envp;
	char **new_envp;

	if (unlikely(real_execvpe == NULL))
		mcount_hook_functions();

	uftrace_envp = collect_uftrace_envp();
	new_envp = merge_envp(envp, uftrace_envp);

	return real_execvpe(file, argv, new_envp);
}

__visible_default int fexecve(int fd, char *const argv[], char *const envp[])
{
	char **uftrace_envp;
	char **new_envp;

	if (unlikely(real_fexecve == NULL))
		mcount_hook_functions();

	uftrace_envp = collect_uftrace_envp();
	new_envp = merge_envp(envp, uftrace_envp);

	return real_fexecve(fd, argv, new_envp);
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
