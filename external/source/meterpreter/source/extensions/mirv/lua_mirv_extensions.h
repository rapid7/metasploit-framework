#define WIN32_LEAN_AND_MEAN

#include "mirv.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"


int l_sendudp (lua_State *L);
// function sendudp(message,dest,port) str,str,int
int l_openlog (lua_State *L);
int l_getevent(lua_State *L);
int l_closelog(lua_State *L);
	