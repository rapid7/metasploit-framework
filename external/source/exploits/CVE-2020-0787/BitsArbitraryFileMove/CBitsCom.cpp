#include "CBitsCom.h"

CBitsCom::CBitsCom()
{
	HRESULT hRes;
	
	m_guidGroup = BITSCOM_GUID_GROUP;
	hRes = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	hRes = CoCreateGuid(&m_guidJob);
	m_pUnkNewJobInterface = nullptr;
}

CBitsCom::~CBitsCom()
{
	m_pUnkNewJobInterface = nullptr;
	m_pBackgroundCopyJob1->Release();
	m_pBackgroundCopyGroup->Release();
	m_pBackgroundCopyQMgr->Release();
	CoUninitialize();
	// NOTE: CoUninitialize() OK
}

DWORD CBitsCom::PrepareJob(LPCWSTR pwszJobLocalFilename)
{
	HRESULT hRes;

	// --- Create an instance of BackgroundCopyQMgr --- 
	//IBackgroundCopyQMgr* pBackgroundCopyQMgr;

	//hRes = CoCreateInstance(__uuidof(BackgroundCopyQMgr), NULL, CLSCTX_LOCAL_SERVER, __uuidof(IBackgroundCopyQMgr), (void**)&pBackgroundCopyQMgr);
	hRes = CoCreateInstance(__uuidof(BackgroundCopyQMgr), NULL, CLSCTX_LOCAL_SERVER, __uuidof(IBackgroundCopyQMgr), (void**)&m_pBackgroundCopyQMgr);
	if (FAILED(hRes))
	{
		wprintf(L"[-] CoCreateInstance() failed. HRESULT=0x%08Xd\n", hRes); 
		return BITSCOM_ERR_COCREATEINSTANCE_BCQMGR;
	}

	if (DEBUG) { wprintf_s(L"[DEBUG] CoCreateInstance() OK\n"); }

	
	// --- Create a Group or use existing one --- 
	OLECHAR* groupGuidStr;
	//IBackgroundCopyGroup* pBackgroundCopyGroup;

	hRes = StringFromCLSID(m_guidGroup, &groupGuidStr);

	if (DEBUG) { wprintf_s(L"[DEBUG] Using Group GUID %ls\n", groupGuidStr); }

	//hRes = pBackgroundCopyQMgr->GetGroup(m_guidGroup, &pBackgroundCopyGroup);
	//hRes = m_pBackgroundCopyQMgr->GetGroup(m_guidGroup, &pBackgroundCopyGroup);
	hRes = m_pBackgroundCopyQMgr->GetGroup(m_guidGroup, &m_pBackgroundCopyGroup);
	if (SUCCEEDED(hRes))
	{
		//hRes = pBackgroundCopyGroup->CancelGroup();
		hRes = m_pBackgroundCopyGroup->CancelGroup();
		if (FAILED(hRes))
		{
			wprintf(L"[-] IBackgroundCopyGroup->CancelGroup() failed.\n");
			wprintf(L"    |__ HRESULT = 0x%08X\n", hRes);
			return BITSCOM_ERR_CANCELGROUP;
		}
	}

	if (DEBUG) { wprintf_s(L"[DEBUG] IBackgroundCopyGroup->CancelGroup() OK\n"); }

	//hRes = pBackgroundCopyQMgr->CreateGroup(m_guidGroup, &pBackgroundCopyGroup);
	//hRes = m_pBackgroundCopyQMgr->CreateGroup(m_guidGroup, &pBackgroundCopyGroup);
	hRes = m_pBackgroundCopyQMgr->CreateGroup(m_guidGroup, &m_pBackgroundCopyGroup);
	if (FAILED(hRes))
	{
		wprintf(L"[-] IBackgroundCopyQMgr->CreateGroup() failed.\n");
		wprintf(L"    |__ Group GUID = %ls\n", groupGuidStr);
		//wprintf(L"    |__ IBackgroundCopyGroup = %p\n", (void*)pBackgroundCopyGroup);
		wprintf(L"    |__ IBackgroundCopyGroup = %p\n", (void*)m_pBackgroundCopyGroup);
		wprintf(L"    |__ HRESULT = 0x%08X\n", hRes);
		return BITSCOM_ERR_CREATEGROUP;
	}

	if (DEBUG) { wprintf_s(L"[DEBUG] IBackgroundCopyQMgr->CreateGroup() OK\n"); }


	// --- Create a Job ---
	OLECHAR* jobGuidStr;
	//IBackgroundCopyJob1* backgroundCopyJob1;

	hRes = StringFromCLSID(m_guidJob, &jobGuidStr);

	if (DEBUG) { wprintf_s(L"[DEBUG] Using Job GUID %ls\n", jobGuidStr); }

	//hRes = pBackgroundCopyGroup->CreateJob(m_guidJob, &backgroundCopyJob1);
	//hRes = pBackgroundCopyGroup->CreateJob(m_guidJob, &m_pBackgroundCopyJob1);
	hRes = m_pBackgroundCopyGroup->CreateJob(m_guidJob, &m_pBackgroundCopyJob1);
	if (FAILED(hRes))
	{
		wprintf(L"[-] IBackgroundCopyGroup->CreateJob() failed.\n");
		wprintf(L"    |__ Job GUID = %ls\n", jobGuidStr);
		//wprintf(L"    |__ IBackgroundCopyJob1 = %p\n", (void *)backgroundCopyJob1);
		wprintf(L"    |__ IBackgroundCopyJob1 = %p\n", (void *)m_pBackgroundCopyJob1);
		wprintf(L"    |__ HRESULT = 0x%08X\n", hRes);
		return BITSCOM_ERR_CREATEJOB;
	}

	if (DEBUG) { wprintf_s(L"[DEBUG] IBackgroundCopyGroup->CreateJob() OK\n"); }


	// --- Add file to job --- 
	FILESETINFO fileSetInfo;
	BSTR  bstrRemoteFile = SysAllocString(L"\\\\127.0.0.1\\C$\\Windows\\System32\\drivers\\etc\\hosts");
	BSTR  bstrLocalFile = SysAllocString(pwszJobLocalFilename);

	fileSetInfo.bstrRemoteFile = bstrRemoteFile;
	fileSetInfo.bstrLocalFile = bstrLocalFile;

	FILESETINFO* fileSetInfoArray = (FILESETINFO*)malloc(1 * sizeof(FILESETINFO));
	if (!fileSetInfoArray)
	{	
		SysFreeString(bstrRemoteFile);
		SysFreeString(bstrLocalFile);
		wprintf(L"[-] malloc() failed (Err: %d).\n", GetLastError());
		return BITSCOM_ERR_ALLOC_FILESETINFO;
	}

	fileSetInfoArray[0] = fileSetInfo;

	//hRes = backgroundCopyJob1->AddFiles(1, &fileSetInfoArray);
	hRes = m_pBackgroundCopyJob1->AddFiles(1, &fileSetInfoArray);
	if (FAILED(hRes))
	{
		wprintf(L"[-] IBackgroundCopyJob1->AddFiles() failed.\n");
		wprintf(L"    |__ HRESULT = 0x%08X\n", hRes);
		free(fileSetInfoArray);
		SysFreeString(bstrRemoteFile);
		SysFreeString(bstrLocalFile);
		return BITSCOM_ERR_ALLOC_ADDFILES;
	}

	free(fileSetInfoArray);
	SysFreeString(bstrRemoteFile);
	SysFreeString(bstrLocalFile);

	if (DEBUG) { wprintf_s(L"[DEBUG] IBackgroundCopyJob1->AddFiles() OK\n"); }

	return BITSCOM_ERR_SUCCESS;
}

DWORD CBitsCom::ResumeJob()
{
	HRESULT hRes;

	// --- Query new job interface --- 
	hRes = m_pBackgroundCopyGroup->QueryNewJobInterface(__uuidof(IBackgroundCopyJob), &m_pUnkNewJobInterface);
	if (FAILED(hRes))
	{
		wprintf(L"[-] IBackgroundCopyJob1->QueryNewJobInterface() failed.\n");
		wprintf(L"    |__ HRESULT = 0x%08X\n", hRes);
		return BITSCOM_ERR_QUERYNEWJOBINTERFACE;
	}

	if (DEBUG) { wprintf_s(L"[DEBUG] IBackgroundCopyJob1->QueryNewJobInterface() OK"); }

	CComQIPtr<IBackgroundCopyJob> pBackgrounCopyJob(m_pUnkNewJobInterface);
	if (!pBackgrounCopyJob)
	{
		wprintf(L"[-] Interface pointer cast failed.\n");
		return BITSCOM_ERR_JOBINTERFACECAST;
	}


	// --- Resume job --- 
	hRes = pBackgrounCopyJob->Resume();
	if (FAILED(hRes))
	{
		wprintf(L"[-] IBackgroundCopyJob->Resume() failed. HRESULT=0x%08X\n", hRes);
		return BITSCOM_ERR_RESUMEJOB;
	}

	if (DEBUG) { wprintf_s(L"[DEBUG] IBackgroundCopyJob->Resume() OK"); }


	return BITSCOM_ERR_SUCCESS;
}

DWORD CBitsCom::CompleteJob()
{
	HRESULT hRes;

	// --- Check whether we have a valid interface pointer --- 
	if (m_pUnkNewJobInterface == nullptr)
	{
		wprintf(L"[-] New job interface pointer is null.\n");
		return BITSCOM_ERR_NEWJOBINTERFACEISNULL;
	}


	// --- Cast interface poiter to IBackgroundCopyJob --- 
	CComQIPtr<IBackgroundCopyJob> pBackgrounCopyJob(m_pUnkNewJobInterface);
	if (!pBackgrounCopyJob)
	{
		wprintf(L"[-] Interface pointer cast failed.\n");
		return BITSCOM_ERR_JOBINTERFACECAST;
	}


	// --- Monitor job state --- 
	DWORD dwJobState = -1;
	DWORD dwMaxAttempts = 10;

	do {
		BG_JOB_STATE bgJobStateCurrent;

		hRes = pBackgrounCopyJob->GetState(&bgJobStateCurrent);
		if (FAILED(hRes))
		{
			wprintf(L"[-] IBackgroundCopyJob->GetState() failed.\n");
			wprintf(L"    |__ HRESULT = 0x%08X\n", hRes);
		}

		if (bgJobStateCurrent != dwJobState)
		{
			WCHAR bgJobStateName[MAX_JOBSTATE_NAME];
			ZeroMemory(bgJobStateName, MAX_JOBSTATE_NAME * sizeof(WCHAR));
			GetJobStateName(bgJobStateCurrent, bgJobStateName);

			wprintf(L"[*] Job state: %ls\n", bgJobStateName);
			dwJobState = bgJobStateCurrent;
		}

		dwMaxAttempts--;
		Sleep(1000);
	} while (dwJobState != BG_JOB_STATE_TRANSFERRED && dwMaxAttempts != 0);

	// If job state isn't BG_JOB_STATE_TRANSFERRED, the job failed
	if (dwJobState != BG_JOB_STATE_TRANSFERRED) 
	{
		return BITSCOM_ERR_JOB;
	}

	// --- Complete job --- 
	hRes = pBackgrounCopyJob->Complete();
	if (FAILED(hRes))
	{
		wprintf(L"[-] IBackgroundCopyJob->Complete() failed.\n");
		wprintf(L"    |__ HRESULT = 0x%08X\n", hRes);
		return BITSCOM_ERR_COMPLETEJOB;
	}

	if (DEBUG) { wprintf_s(L"[DEBUG] IBackgroundCopyJob->Complete() OK\n"); }

	return BITSCOM_ERR_SUCCESS;
}

BOOL CBitsCom::GetJobStateName(BG_JOB_STATE bgJobState, LPWSTR pwszJobName)
{
	const WCHAR* res;
	BOOL bRes = TRUE;

	switch (bgJobState)
	{
	case BG_JOB_STATE_QUEUED:
		res = L"BG_JOB_STATE_QUEUED";
		break;
	case BG_JOB_STATE_CONNECTING:
		res = L"BG_JOB_STATE_CONNECTING";
		break;
	case BG_JOB_STATE_TRANSFERRING:
		res = L"BG_JOB_STATE_TRANSFERRING";
		break;
	case BG_JOB_STATE_SUSPENDED:
		res = L"BG_JOB_STATE_SUSPENDED";
		break;
	case BG_JOB_STATE_ERROR:
		res = L"BG_JOB_STATE_ERROR";
		break;
	case BG_JOB_STATE_TRANSIENT_ERROR:
		res = L"BG_JOB_STATE_TRANSIENT_ERROR";
		break;
	case BG_JOB_STATE_TRANSFERRED:
		res = L"BG_JOB_STATE_TRANSFERRED";
		break;
	case BG_JOB_STATE_ACKNOWLEDGED:
		res = L"BG_JOB_STATE_ACKNOWLEDGED";
		break;
	case BG_JOB_STATE_CANCELLED:
		res = L"BG_JOB_STATE_CANCELLED";
		break;
	default:
		res = L"UNKNOWN";
		bRes = FALSE;
	}

	swprintf_s(pwszJobName, MAX_JOBSTATE_NAME, L"%ls", res);

	return bRes;
}
