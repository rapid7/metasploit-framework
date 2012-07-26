#define WIN32_LEAN_AND_MEAN

#include "mirv.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include <Wtsapi32.h>
#include <UserEnv.h> 
#pragma comment(lib,"Wtsapi32.lib")
#pragma comment(lib,"Userenv.lib")

int l_sendudp (lua_State *L);
// function sendudp(message,dest,port) str,str,int
int l_openlog (lua_State *L);
int l_getevent(lua_State *L);
int l_closelog(lua_State *L);
int l_rdp_hijack(lua_State *L);
int l_get_rdp_sessions(lua_State *L);
void l_pushtablestring(lua_State* L , char* key , char* value);