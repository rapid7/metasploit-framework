#pragma once

#include <Windows.h>
#include <iostream>
#include <qmgr.h>
#include <Bits.h>
#include <atlbase.h>
#include <strsafe.h>

#define DEBUG FALSE
#define BITSCOM_GUID_GROUP { 0x63B45B2D, 0xA84B, 0x463E, { 0x9C, 0xD4, 0xC0, 0x48, 0xC1, 0xBF, 0x9E, 0x72 } }
#define MAX_JOBSTATE_NAME 64

enum PrepareJobError
{
	BITSCOM_ERR_SUCCESS,
	BITSCOM_ERR_COCREATEINSTANCE_BCQMGR,
	BITSCOM_ERR_CREATEGROUP,
	BITSCOM_ERR_GETGROUP,
	BITSCOM_ERR_CANCELGROUP,
	BITSCOM_ERR_CREATEJOB,
	BITSCOM_ERR_GETJOB,
	BITSCOM_ERR_RESUMEJOB,
	BITSCOM_ERR_JOB,
	BITSCOM_ERR_COMPLETEJOB,
	BITSCOM_ERR_ALLOC_FILESETINFO,
	BITSCOM_ERR_ALLOC_ADDFILES,
	BITSCOM_ERR_QUERYNEWJOBINTERFACE,
	BITSCOM_ERR_JOBINTERFACECAST,
	BITSCOM_ERR_NEWJOBINTERFACEISNULL
};

class CBitsCom
{
private:
	GUID m_guidGroup;
	GUID m_guidJob;
	IBackgroundCopyQMgr* m_pBackgroundCopyQMgr;
	IBackgroundCopyGroup* m_pBackgroundCopyGroup;
	IBackgroundCopyJob1* m_pBackgroundCopyJob1;
	CComPtr<IUnknown> m_pUnkNewJobInterface;

public:
	CBitsCom();
	~CBitsCom();

public:
	DWORD PrepareJob(LPCWSTR pwszJobLocalFilename);
	DWORD ResumeJob();
	DWORD CompleteJob();

private:
	BOOL GetJobStateName(BG_JOB_STATE bgJobState, LPWSTR pwszJobName);
};

