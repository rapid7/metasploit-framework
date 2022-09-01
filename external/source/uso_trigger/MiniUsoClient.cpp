
#include "MiniUsoClient.h"

#pragma comment(lib, "rpcrt4.lib")

MiniUsoClient::MiniUsoClient()
{
	HRESULT hResult;

	hResult = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hResult))
	{
		//wprintf_s(L"    |__ CoInitializeEx() failed. Error code = 0x%08X\n", hResult);
		_ready = false;
	}
	else
	{
		_ready = true;
	}
}

MiniUsoClient::~MiniUsoClient()
{
	CoUninitialize();
}

void MiniUsoClient::ThrowOnError(HRESULT hResult)
{
	if (hResult != 0)
	{
		throw _com_error(hResult);
	}
}


bool MiniUsoClient::Run(UsoAction action)
{
	HRESULT hResult;

	if (this->_ready)
	{
		//wprintf_s(L"    |__ Creating instance of 'UpdateSessionOrchestrator'... ");

		GUID CLSID_UpdateSessionOrchestrator = { 0xb91d5831, 0xb1bd, 0x4608, { 0x81, 0x98, 0xd7, 0x2e, 0x15, 0x50, 0x20, 0xf7 } };
		IUpdateSessionOrchestratorPtr updateSessionOrchestrator;
		hResult = CoCreateInstance(CLSID_UpdateSessionOrchestrator, nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&updateSessionOrchestrator));
		if (FAILED(hResult))
		{
			//wprintf_s(L"\n    |__ CoCreateInstance() failed. Error code = 0x%08X\n", hResult);
			CoUninitialize();
			return false;
		}

		//wprintf_s(L"Done.\n");

		/*
		try
		{
			ThrowOnError(updateSessionOrchestrator->LogTaskRunning(L"StartScan"));
		}
		catch (const _com_error& error)
		{
			//wprintf(L"    |__ LogTaskRunning() - Return code: 0x%08X (\"%s\")\n", error.Error(), error.ErrorMessage());
		}
		*/

		IUsoSessionCommonPtr usoSessionCommon;
		GUID IID_IUsoSessionCommon = { 0xfccc288d, 0xb47e, 0x41fa, { 0x97, 0x0c, 0x93, 0x5e, 0xc9, 0x52, 0xf4, 0xa4 } };
		try
		{
			//wprintf_s(L"    |__ Creating a new Update Session... ");
			updateSessionOrchestrator->CreateUpdateSession(1, &IID_IUsoSessionCommon, &usoSessionCommon);
			//wprintf_s(L"Done.\n");

			//wprintf_s(L"    |__ Calling 'CoSetProxyBlanket()'... ");
			ThrowOnError(CoSetProxyBlanket(usoSessionCommon, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, NULL));
			//wprintf_s(L"Done.\n");

			switch (action)
			{
			case USO_STARTSCAN:
				//wprintf(L"    |__ Calling 'StartScan'... ");
				ThrowOnError(usoSessionCommon->Proc21(0, 0, L"ScanTriggerUsoClient"));
				//wprintf(L"Done.\n");
				break;
			case USO_STARTDOWNLOAD:
				//wprintf(L"    |__ Calling 'StartDownload'... ");
				ThrowOnError(usoSessionCommon->Proc22(0));
				//wprintf(L"Done.\n");
				break;
			case USO_STARTINTERACTIVESCAN:
				//wprintf(L"    |__ Calling 'StartInteractiveScan'... ");
				ThrowOnError(usoSessionCommon->Proc21(-1, 0, L"ScanTriggerUsoClientInteractive"));
				//wprintf(L"Done.\n");
				break;
			}

		}
		catch (const _com_error&)
		{
			return false;
		}
	}
	else
	{
		return false;
	}

	return true;
}
