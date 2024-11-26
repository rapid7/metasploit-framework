#pragma once

namespace W7EInject
{
	void AttemptOperation(HWND hWnd, bool bInject, bool bElevate, DWORD dwPid, const wchar_t *szProcName,
						  const wchar_t *szCmd, const wchar_t *szArgs, const wchar_t *szDir,
						  const wchar_t *szPathToOurDll, 
						  DWORD (__stdcall *Redirector)(void));
}
