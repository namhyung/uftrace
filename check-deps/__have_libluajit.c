#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

int main(void)
{
	lua_State *L = luaL_newstate();
	luaL_openlibs(L);
	return 0;
}
