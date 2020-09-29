#define PR_FMT "script"
#define PR_DOMAIN DBG_SCRIPT

#include "utils/script-native.h"
#include "utils/filter.h"
#include "utils/fstack.h"
#include "utils/script.h"
#include "utils/symbol.h"
#include "utils/utils.h"
#include <dlfcn.h>

static void *native_handle;

static void (*__uftrace_begin)(struct uftrace_script_info *info);
static void (*__uftrace_entry)(struct uftrace_script_context *sc_ctx);
static void (*__uftrace_exit)(struct uftrace_script_context *sc_ctx);
static void (*__uftrace_end)(void);

static int native_uftrace_begin(struct uftrace_script_info *info)
{
	__uftrace_begin(info);
	return 0;
}

static int native_uftrace_entry(struct uftrace_script_context *sc_ctx)
{
	__uftrace_entry(sc_ctx);
	return 0;
}

static int native_uftrace_exit(struct uftrace_script_context *sc_ctx)
{
	__uftrace_exit(sc_ctx);
	return 0;
}

static int native_uftrace_end(void)
{
	__uftrace_end();
	return 0;
}

static int native_atfork_prepare(void)
{
	return 0;
}

#define INIT_NATIVE_API_FUNC(func)                                                                 \
	do {                                                                                       \
		__##func = dlsym(native_handle, #func);                                            \
		if (!__##func) {                                                                   \
			pr_err("dlsym for \"" #func "\" is failed!\n");                            \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

static int load_native_api_funcs(const char *so_pathname)
{
	native_handle = dlopen(so_pathname, RTLD_LAZY | RTLD_GLOBAL);
	if (!native_handle) {
		pr_warn("%s cannot be loaded!\n", so_pathname);
		return -1;
	}
	pr_dbg("%s is loaded\n", so_pathname);

	INIT_NATIVE_API_FUNC(uftrace_begin);
	INIT_NATIVE_API_FUNC(uftrace_entry);
	INIT_NATIVE_API_FUNC(uftrace_exit);
	INIT_NATIVE_API_FUNC(uftrace_end);

	return 0;
}

int script_init_for_native(struct uftrace_script_info *info, enum uftrace_pattern_type ptype)
{
	pr_dbg("%s(\"%s\")\n", __func__, info->name);

	script_uftrace_entry = native_uftrace_entry;
	script_uftrace_exit = native_uftrace_exit;
	script_uftrace_end = native_uftrace_end;
	script_atfork_prepare = native_atfork_prepare;

	if (load_native_api_funcs(info->name) < 0)
		return -1;

	if (info->cmds == NULL)
		info->cmds = "";

	native_uftrace_begin(info);

	return 0;
}

void script_finish_for_native(void)
{
	pr_dbg("%s()\n", __func__);

	dlclose(native_handle);
	native_handle = NULL;
}
