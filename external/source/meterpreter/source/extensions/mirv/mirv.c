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
#include "lua_mirv_extensions.h"
// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();
#define MAX_THREADS 256
#define MAX_DESC 140 //twitter style!
mirv_thread threads[MAX_THREADS];

int add_thread_record(DWORD thread_id,char *description){
	int i;
	char *tmpdest;
	for(i=0;i<MAX_THREADS;i++) // find a free slot
		if (threads[i].thread_id==0){
			threads[i].thread_id=thread_id;
			if (strlen(description)>MAX_DESC){
				tmpdest=(char *)malloc(140*sizeof(char)+1);	
				strncpy(tmpdest,description,MAX_DESC);
				tmpdest[MAX_DESC]='\0';
				threads[i].description=tmpdest;
			}else{
				threads[i].description=description;
			}
			break;
		}
	return i;
}
int find_thread_pos(DWORD thread_id){
	int i;
	for(i=0;i<MAX_THREADS;i++){
		if(threads[i].thread_id==thread_id){
			dprintf("Found thread %i, at slot %i with desc %s",thread_id,i,threads[i].description);
			return i;
		}
	}
	
	return -1;
}
int send_thread_signal(DWORD thread_id,enum thread_signal sig){
	int i;
	i=find_thread_pos(thread_id);
	if (i>=0){
		threads[i].signal=sig;
		dprintf("Sending %d at slot %i the stop signal",thread_id,i);
		return 1;
	}else{
		return -1;
	}
}

//enum thread_signal get_thread_signal(DWORD thread_id){
//	int i;
//	for(i=0;threads[i].thread_id==0;i++); // find thread 
//	return threads[i].signal;
//	
//}

/*
LPCSTR do_lua(LPCSTR lua_code){
	lua_State *l,*t;
	const char *msg,*ret;
	
	int res;
	l = luaL_newstate();
	luaL_openlibs(l);
	luaL_dostring(l,lua_code); // Parse code
	//lua_pcall(l, 0, 0, 0); 
	t=lua_newthread(l);
	lua_getglobal(t, "loop"); // get loop to the top
	while(TRUE){
		res = lua_resume(t,0);
		switch(res){
			case LUA_YIELD:
				// do nothing at the moment
				break;
			case 0: // finished execution
				msg=lua_tostring(t, -1);
				goto endlua;
			default:
				// ERROR
				msg=lua_tostring(t, -1);
				goto endlua;
				break;
		}
	}
endlua:
	ret=strdup(msg);
	lua_close(l);
	return ret;
	//return msg;
}
*/
LPCSTR do_lua(LPCSTR lua_code,DWORD thread_id){
	lua_State *l,*t;
	const char *msg=NULL,*ret=NULL;
//	int tpos;
	int res;
	enum thread_signal sig;
	l = luaL_newstate();
	luaL_openlibs(l);
	lua_pushcfunction(l, l_sendudp);
    lua_setglobal(l, "sendudp");

	lua_pushcfunction(l, l_openlog);
    lua_setglobal(l, "openlog");

	lua_pushcfunction(l, l_getevent);
    lua_setglobal(l, "getevent");

	lua_pushcfunction(l, l_closelog);
    lua_setglobal(l, "closelog");
	
	lua_pushcfunction(l, l_get_rdp_sessions);
    lua_setglobal(l, "rdp_sessions");


	lua_pushcfunction(l, l_rdp_hijack);
    lua_setglobal(l, "rdp_hijack");

	if(luaL_dostring(l,lua_code)!=0){	// Error parsing code
		dprintf("Error parsing code :( ");
		msg=lua_tostring(l, -1);
		goto endlua;
	}// Parse code
	//lua_pcall(l, 0, 0, 0); 
	t=lua_newthread(l);
	lua_getglobal(t, "loop"); // get loop to the top

	while(TRUE){
		res = lua_resume(t,0);
		switch(res){
		case LUA_YIELD:
			dprintf("Checking if we need to stop... ");
			
			if(thread_id>0){
			sig=threads[find_thread_pos(thread_id)].signal;
			dprintf("sig is %d, so " , sig);
			if(sig==stop){
				msg="Stopping thread as per instruction from user";
				dprintf("yes!.");
				goto endlua;
			}
			}
			dprintf("no, carry on.");
			break;
		case 0: // finished execution
			dprintf("Execution finished for this thread");
			//msg=lua_tostring(t, -1);
			goto endlua;
		default:
			// ERROR
			//msg=lua_tostring(t, -1);
			goto endlua;
			break;
		}
	}
endlua:
	if(msg==NULL){
		if(lua_isnil(t,-1)){
			msg="No value returned";			
		}else{
			msg=lua_tostring(t, -1);
		}
	}
	dprintf("The return value is '%s'",msg);
	ret=_strdup(msg);
	lua_close(l);
	return ret;

}
DWORD WINAPI LuaThreadProc(
	__in  LPVOID lpParameter
	){
		LPCSTR lua_ret;
		int i;
		
		
		lua_ret=do_lua((LPCSTR)lpParameter,GetCurrentThreadId());		
		threads[i].description=(char *)lua_ret;
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
	int slot;
	lua_code= packet_get_tlv_value_string(packet,TLV_TYPE_MIRV_LUA_CODE);
	newThread=packet_get_tlv_value_bool(packet,TLV_TYPE_MIRV_NEWTHREAD);
	response = packet_create_response( packet );
	if (newThread){ // Do you want to run as a new thread?
		if(NULL==CreateThread(NULL,	// are we failing here?
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
				dprintf("New thread creation failed");
				
				//FIXME: not a pretty conversion, we should do conversion to mb from whatever system has
				packet_add_tlv_string(response,TLV_TYPE_MIRV_LUA_RETMSG,(LPCSTR) lpMsgBuf); 	

				dwResult = -1;
		}else{	// thread created successfully
			dprintf("New thread creation successful");
			lpMsgBuf=malloc(MAX_DESC);
			strncpy((char *)lpMsgBuf,lua_code,MAX_DESC);
			slot=add_thread_record(threadID,(char *)lpMsgBuf);
			lpMsgBuf=(char *)malloc(1024);
			sprintf((char *)lpMsgBuf,"Thread created successfully, slot %i",slot);
			packet_add_tlv_string(response,TLV_TYPE_MIRV_LUA_RETMSG,(LPCSTR)lpMsgBuf);
			//packet_add_tlv_string(response,TLV_TYPE_MIRV_LUA_RETMSG,"Thread started successfully");
			packet_add_tlv_uint(response,TLV_TYPE_MIRV_RET_THREADID,threadID);
		}
		
	}else{
		lua_ret=do_lua(lua_code,-1);
		packet_add_tlv_string(response,TLV_TYPE_MIRV_LUA_RETMSG,lua_ret);
	}

	dprintf("Transmitting response back\n");
	packet_transmit_response( dwResult, remote, response );
	return dwResult;
}
DWORD request_mirv_thread_list(Remote *remote, Packet *packet)
{
	

	DWORD dwResult    = ERROR_SUCCESS;		
	Packet * response = NULL;
	char *buf;
	int i,j;
	//char **threadlist;
	Tlv threadlist[MAX_THREADS];
	j=0;
	response = packet_create_response( packet );
	//entries[entryCount].header.length = sizeof(DWORD);
	//		entries[entryCount].header.type   = TLV_TYPE_IP;
	//		entries[entryCount].buffer        = (PUCHAR)&table->table[index].dwAddr;
	//		entryCount++;
	for (i=0;i<MAX_THREADS;++i){//FIXME i=>0
		if(threads[i].thread_id!=0){ // a live record

			
			buf=(char *)malloc(1024);
			sprintf(buf,"%i,%s",threads[i].thread_id,threads[i].description);
			dprintf("Thread - %s",buf);
			threadlist[j].header.length=strlen(buf);
			threadlist[j].header.type=TLV_TYPE_MIRV_THREADRECORD;
			threadlist[j].buffer=(PUCHAR)buf;//??? maybe wrong
			j++;

		}
	}
	packet_add_tlv_group(response,TLV_TYPE_MIRV_THREADLIST,threadlist,j);
	packet_transmit_response( dwResult, remote, response );
	//dwResult=j;
	return dwResult;
}
DWORD request_mirv_thread_stop(Remote *remote, Packet *packet)
{
	

	DWORD dwResult    = ERROR_SUCCESS;		
	Packet * response = NULL;
	DWORD thread_id;
	response = packet_create_response( packet );
	thread_id=packet_get_tlv_value_uint(packet,TLV_TYPE_MIRV_RET_THREADID);
	if(send_thread_signal(thread_id,stop)<0){
		dwResult=-1; // thread not found
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

	{ "mirv_thread_stop",
	{ request_mirv_thread_stop,                                    { 0 }, 0 },
	{ EMPTY_DISPATCH_HANDLER                                      },
	},

	{ "mirv_thread_list",
	{ request_mirv_thread_list,                                    { 0 }, 0 },
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
	int i;
	hMetSrv = remote->hMetSrv;

	for (index = 0;
		customCommands[index].method;
		index++)
		command_register(&customCommands[index]);
	for(i=0;i<MAX_THREADS;++i){
		threads[i].thread_id=0;
	}
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
