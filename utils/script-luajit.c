#ifdef HAVE_LIBLUAJIT

#define PR_FMT "script"
#define PR_DOMAIN DBG_SCRIPT

#include "utils/script-luajit.h"
#include "utils/filter.h"
#include "utils/fstack.h"
#include "utils/script.h"
#include "utils/symbol.h"
#include "utils/utils.h"
#include <dlfcn.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

static const char *libluajit = "libluajit-5.1.so";
static void *luajit_handle;
static lua_State *L;

static lua_State *(*dlluaL_newstate)(void);
static void (*dlluaL_openlibs)(lua_State *L);
static int (*dlluaL_loadfile)(lua_State *L, const char *filename);
static void (*dllua_close)(lua_State *L);
static int (*dllua_pcall)(lua_State *L, int nargs, int nresults, int errfunc);
static int (*dllua_next)(lua_State *L, int index);
static void (*dllua_createtable)(lua_State *L, int narr, int nrec);
static void (*dllua_gettable)(lua_State *L, int index);
static void (*dllua_settable)(lua_State *L, int index);
static const char *(*dllua_tolstring)(lua_State *L, int index, size_t *len);
static void (*dllua_pushstring)(lua_State *L, const char *s);
static void (*dllua_pushinteger)(lua_State *L, lua_Integer n);
static void (*dllua_pushnumber)(lua_State *L, lua_Number n);
static void (*dllua_pushboolean)(lua_State *L, int b);
static void (*dllua_pushnil)(lua_State *L);
static void (*dllua_remove)(lua_State *L, int index);

static void (*dllua_getfield)(lua_State *L, int index, const char *k);
static int (*dllua_type)(lua_State *L, int index);
static void (*dllua_settop)(lua_State *L, int index);

#define dllua_newtable(L) dllua_createtable(L, 0, 0)
#define dllua_pop(L, n) dllua_settop(L, -(n)-1)
#define dllua_tostring(L, i) dllua_tolstring(L, (i), NULL)
#define dllua_isnil(L, n) (dllua_type(L, (n)) == LUA_TNIL)
#define dllua_getglobal(L, s) dllua_getfield(L, LUA_GLOBALSINDEX, (s))

static void setup_common_context(struct script_context *sc_ctx)
{
	dllua_newtable(L);
	dllua_pushstring(L, "tid");
	dllua_pushinteger(L, sc_ctx->tid);
	dllua_settable(L, -3);
	dllua_pushstring(L, "depth");
	dllua_pushinteger(L, sc_ctx->depth);
	dllua_settable(L, -3);
	dllua_pushstring(L, "timestamp");
	dllua_pushinteger(L, sc_ctx->timestamp);
	dllua_settable(L, -3);
	dllua_pushstring(L, "duration");
	dllua_pushinteger(L, sc_ctx->duration);
	dllua_settable(L, -3);
	dllua_pushstring(L, "address");
	dllua_pushinteger(L, sc_ctx->address);
	dllua_settable(L, -3);
	dllua_pushstring(L, "name");
	dllua_pushstring(L, sc_ctx->name);
	dllua_settable(L, -3);
}

static void setup_argument_context(bool is_retval, struct script_context *sc_ctx)
{
	struct uftrace_arg_spec *spec;
	void *data = sc_ctx->argbuf;
	union script_arg_val val;
	int count = 0;

	list_for_each_entry(spec, sc_ctx->argspec, list) {
		/* skip unwanted arguments or retval */
		if (is_retval != (spec->idx == RETVAL_IDX))
			continue;

		count++;
	}
	if (count == 0)
		return;

	if (is_retval)
		dllua_pushstring(L, "retval");
	else
		dllua_pushstring(L, "args");
	dllua_newtable(L);

	count = 0;
	list_for_each_entry(spec, sc_ctx->argspec, list) {
		const int null_str = -1;
		unsigned short slen;
		char ch_str[2];
		char *str;
		double dval __maybe_unused;

		/* skip unwanted arguments or retval */
		if (is_retval != (spec->idx == RETVAL_IDX))
			continue;

		/* reset the value */
		memset(val.v, 0, sizeof(val));

		switch (spec->fmt) {
		case ARG_FMT_AUTO:
		case ARG_FMT_SINT:
		case ARG_FMT_UINT:
		case ARG_FMT_HEX:
		case ARG_FMT_PTR:
		case ARG_FMT_ENUM:
			memcpy(val.v, data, spec->size);
			switch (spec->size) {
			case 1:
				dllua_pushinteger(L, ++count);
				dllua_pushinteger(L, val.c);
				dllua_settable(L, -3);
				break;
			case 2:
				dllua_pushinteger(L, ++count);
				dllua_pushinteger(L, val.s);
				dllua_settable(L, -3);
				break;
			case 4:
				dllua_pushinteger(L, ++count);
				dllua_pushinteger(L, val.i);
				dllua_settable(L, -3);
				break;
			case 8:
				dllua_pushinteger(L, ++count);
				dllua_pushinteger(L, val.L);
				dllua_settable(L, -3);
				break;
			default:
				pr_warn("invalid argument format: %d\n", spec->fmt);
				break;
			}
			data += ALIGN(spec->size, 4);
			break;
		case ARG_FMT_FLOAT:
			memcpy(val.v, data, spec->size);
#ifndef LIBMCOUNT
			switch (spec->size) {
			case 4:
				dval = val.f;
				break;
			case 8:
				dval = val.d;
				break;
			case 10:
				dval = (double)val.D;
				break;
			default:
				pr_dbg("invalid floating-point type size %d\n", spec->size);
				dval = 0;
				break;
			}
			dllua_pushinteger(L, ++count);
			dllua_pushnumber(L, dval);
			dllua_settable(L, -3);
#endif
			data += ALIGN(spec->size, 4);
			break;

		case ARG_FMT_STR:
		case ARG_FMT_STD_STRING:
			/* get string length (2 bytes in the beginning) */
			memcpy(&slen, data, 2);

			str = xmalloc(slen + 1);

			/* copy real string contents */
			memcpy(str, data + 2, slen);
			str[slen] = '\0';

			/* NULL string is encoded as '0xffffffff' */
			if (slen == 4 && !memcmp(str, &null_str, sizeof(null_str)))
				strcpy(str, "NULL");

			dllua_pushinteger(L, ++count);
			dllua_pushstring(L, str);
			dllua_settable(L, -3);
			free(str);
			data += ALIGN(slen + 2, 4);
			break;

		case ARG_FMT_CHAR:
			/* make it a string */
			memcpy(ch_str, data, 1);
			ch_str[1] = '\0';
			dllua_pushinteger(L, ++count);
			dllua_pushstring(L, ch_str);
			dllua_settable(L, -3);
			data += 4;
			break;

		case ARG_FMT_STRUCT:
			str = NULL;
			xasprintf(&str, "struct: %s{}", spec->type_name ? spec->type_name : "");
			dllua_pushinteger(L, ++count);
			dllua_pushstring(L, str);
			dllua_settable(L, -3);
			free(str);
			data += ALIGN(spec->size, 4);
			break;

		default:
			pr_warn("invalid argument format: %d\n", spec->fmt);
			break;
		}
	}
	if (is_retval) {
		dllua_pushinteger(L, 1);
		dllua_gettable(L, -2);
		dllua_remove(L, -2);
	}
	dllua_settable(L, -3);
}

static int luajit_uftrace_begin(struct script_info *info)
{
	int i;
	char *s;

	dllua_getglobal(L, "uftrace_begin");
	if (dllua_isnil(L, -1)) {
		dllua_pop(L, 1);
		return -1;
	}
	dllua_newtable(L);
	dllua_pushstring(L, "record");
	dllua_pushboolean(L, info->record);
	dllua_settable(L, -3);
	dllua_pushstring(L, "version");
	dllua_pushstring(L, info->version);
	dllua_settable(L, -3);
	dllua_pushstring(L, "cmds");
	dllua_newtable(L);
	strv_for_each(&info->cmds, s, i) {
		dllua_pushinteger(L, i + 1);
		dllua_pushstring(L, s);
		dllua_settable(L, -3);
	}
	dllua_settable(L, -3);
	if (dllua_pcall(L, 1, 0, 0) != 0) {
		pr_dbg("uftrace_begin failed: %s\n", dllua_tostring(L, -1));
		dllua_pop(L, 1);
		return -1;
	}
	return 0;
}

static int luajit_uftrace_entry(struct script_context *sc_ctx)
{
	dllua_getglobal(L, "uftrace_entry");
	if (dllua_isnil(L, -1)) {
		dllua_pop(L, 1);
		return -1;
	}

	setup_common_context(sc_ctx);
	if (sc_ctx->arglen)
		setup_argument_context(false, sc_ctx);

	if (dllua_pcall(L, 1, 0, 0) != 0) {
		pr_dbg("uftrace_entry failed: %s\n", dllua_tostring(L, -1));
		dllua_pop(L, 1);
		return -1;
	}

	return 0;
}

static int luajit_uftrace_exit(struct script_context *sc_ctx)
{
	dllua_getglobal(L, "uftrace_exit");
	if (dllua_isnil(L, -1)) {
		dllua_pop(L, 1);
		return -1;
	}

	setup_common_context(sc_ctx);

	if (sc_ctx->arglen)
		setup_argument_context(true, sc_ctx);

	if (dllua_pcall(L, 1, 0, 0) != 0) {
		pr_dbg("uftrace_exit failed: %s\n", dllua_tostring(L, -1));
		dllua_pop(L, 1);
		return -1;
	}

	return 0;
}

static int luajit_uftrace_event(struct script_context *sc_ctx)
{
	
	dllua_getglobal(L, "uftrace_event");
	if (dllua_isnil(L, -1)) {
		dllua_pop(L, 1);
		return -1;
	}

	setup_common_context(sc_ctx);

	if (sc_ctx->argbuf) {
		dllua_pushstring(L, "args");
		dllua_pushstring(L, sc_ctx->argbuf);
		dllua_settable(L, -3);
	}

	if (dllua_pcall(L, 1, 0, 0) != 0) {
		pr_dbg("uftrace_event failed: %s\n", dllua_tostring(L, -1));
		dllua_pop(L, 1);
		return -1;
	}

	return 0;
}

static int luajit_uftrace_end(void)
{
	dllua_getglobal(L, "uftrace_end");
	if (dllua_isnil(L, -1)) {
		dllua_pop(L, 1);
		return -1;
	}
	if (dllua_pcall(L, 0, 0, 0) != 0) {
		pr_dbg("uftrace_end failed: %s\n", dllua_tostring(L, -1));
		dllua_pop(L, 1);
		return -1;
	}
	return 0;
}

static int luajit_atfork_prepare(void)
{
	return 0;
}

#define INIT_LUAJIT_API_FUNC(func)                                                                 \
	do {                                                                                       \
		dl##func = dlsym(luajit_handle, #func);                                            \
		if (!dl##func) {                                                                   \
			pr_err("dlsym for \"" #func "\" is failed!\n");                            \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

static int load_luajit_api_funcs(void)
{
	luajit_handle = dlopen(libluajit, RTLD_LAZY | RTLD_GLOBAL);
	if (!luajit_handle) {
		pr_warn("%s cannot be loaded!\n", libluajit);
		return -1;
	}
	pr_dbg("%s is loaded\n", libluajit);

	INIT_LUAJIT_API_FUNC(luaL_newstate);
	INIT_LUAJIT_API_FUNC(luaL_openlibs);
	INIT_LUAJIT_API_FUNC(luaL_loadfile);
	INIT_LUAJIT_API_FUNC(lua_close);

	INIT_LUAJIT_API_FUNC(lua_pcall);
	INIT_LUAJIT_API_FUNC(lua_next);

	INIT_LUAJIT_API_FUNC(lua_gettable);
	INIT_LUAJIT_API_FUNC(lua_settable);

	INIT_LUAJIT_API_FUNC(lua_pushstring);
	INIT_LUAJIT_API_FUNC(lua_pushinteger);
	INIT_LUAJIT_API_FUNC(lua_pushnumber);

	INIT_LUAJIT_API_FUNC(lua_pushboolean);
	INIT_LUAJIT_API_FUNC(lua_pushnil);

	INIT_LUAJIT_API_FUNC(lua_remove);

	INIT_LUAJIT_API_FUNC(lua_getfield);
	INIT_LUAJIT_API_FUNC(lua_type);
	INIT_LUAJIT_API_FUNC(lua_createtable);
	INIT_LUAJIT_API_FUNC(lua_settop);
	INIT_LUAJIT_API_FUNC(lua_tolstring);

	return 0;
}

int script_init_for_luajit(struct script_info *info, enum uftrace_pattern_type ptype)
{
	pr_dbg("%s()\n", __func__);
	script_uftrace_entry = luajit_uftrace_entry;
	script_uftrace_exit = luajit_uftrace_exit;
	script_uftrace_event = luajit_uftrace_event;
	script_uftrace_end = luajit_uftrace_end;
	script_atfork_prepare = luajit_atfork_prepare;

	if (load_luajit_api_funcs() < 0)
		return -1;

	L = dlluaL_newstate();
	dlluaL_openlibs(L);
	if (dlluaL_loadfile(L, info->name) != 0)
		return -1;
	if (dllua_pcall(L, 0, 0, 0) != 0) {
		pr_warn("luajit script failed: %s\n", dllua_tostring(L, -1));
		dllua_pop(L, 1);
		return -1;
	}

	dllua_getglobal(L, "UFTRACE_FUNCS");
	if (!dllua_isnil(L, -1)) {
		dllua_pushnil(L);
		while (dllua_next(L, -2) != 0) {
			char *filter_str = xstrdup(dllua_tostring(L, -1));
			script_add_filter(filter_str, ptype);
			free(filter_str);
			dllua_pop(L, 1);
		}
	}
	dllua_pop(L, 1);

	luajit_uftrace_begin(info);
	return 0;
}

void script_finish_for_luajit(void)
{
	pr_dbg("%s()\n", __func__);
	dllua_close(L);

	dlclose(luajit_handle);
	luajit_handle = NULL;
}

#endif
