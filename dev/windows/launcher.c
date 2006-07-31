#include <windows.h>

#define ENABLE_INSERT_MODE 0x0020
#define ENABLE_QUICK_EDIT_MODE 0x0040
#define ENABLE_EXTENDED_FLAGS 0x0080
#define ENABLE_AUTO_POSITION 0x0100 

int WinMain (
	HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow
	) 
{

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	char cmd[4096];
	char exe[4096];
	HANDLE o;
	HMODULE m;
	COORD b;
	COORD c;
	SMALL_RECT w;
	BOOL ok = TRUE;
	COORD nw = { 95, 25 };
	DWORD dwMode;
	char *p;
	int i;

	// Create a console for this process
	AllocConsole();

	o = GetStdHandle(STD_OUTPUT_HANDLE); 
	m = GetModuleHandle(NULL);

	GetModuleFileName(m, exe, 4096);

	for (i = strlen(exe); i > 0; i--)
		if (exe[i] == 0x5c) {
			exe[i] = 0;
			break;
		}
	
	_snprintf_s(cmd, sizeof(cmd), sizeof(cmd) -1, "%s\\%s", exe, "msfconsole.bat");

	// Set Quick Edit mode
	GetConsoleMode(o, &dwMode);
	SetConsoleMode(o, dwMode | ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE | ENABLE_QUICK_EDIT_MODE);

	Sleep(10000);

	// SetConsoleTextAttribute(o, FOREGROUND_RED|FOREGROUND_INTENSITY);

	if (ok) {
		SMALL_RECT sz = {0, 0, 0, 0};
		ok = SetConsoleWindowInfo(o, TRUE, &sz) ? TRUE : FALSE;
	}

	if (ok) {
		ok = SetConsoleScreenBufferSize(o, nw) ? TRUE : FALSE;
	}
	
	if (ok) {
		SMALL_RECT sz = {0, 0, nw.X-1, nw.Y-1};
		SetConsoleWindowInfo(o, TRUE, &sz) ? TRUE : FALSE;
	}

	if (ok) {
		nw.Y = 1000;
		ok = SetConsoleScreenBufferSize(o, nw) ? TRUE : FALSE;
	}

	if (ok) {
		SMALL_RECT sz = {0, 0, nw.X-1, 40};
		SetConsoleWindowInfo(o, TRUE, &sz) ? TRUE : FALSE;
	}

	SetConsoleTitle("Metasploit Framework 3.0 BETA RELEASE");

	// Startup information
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	// The console is inherited by the child
	if(CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	return(0);
}
