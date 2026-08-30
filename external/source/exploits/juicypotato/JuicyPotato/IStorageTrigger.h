#pragma once
#include "Objidl.h"

class IStorageTrigger : public IMarshal, public IStorage {
private:
	IStorage *_stg;
	int m_cRef;
public:
	IStorageTrigger(IStorage *stg);
	HRESULT STDMETHODCALLTYPE DisconnectObject(DWORD dwReserved);
	HRESULT STDMETHODCALLTYPE GetMarshalSizeMax(const IID &riid, void *pv, DWORD dwDestContext, void *pvDestContext, DWORD mshlflags, DWORD *pSize);
	HRESULT STDMETHODCALLTYPE GetUnmarshalClass(const IID &riid, void *pv, DWORD dwDestContext, void *pvDestContext, DWORD mshlflags, CLSID *pCid);
	HRESULT STDMETHODCALLTYPE MarshalInterface(IStream *pStm, const IID &riid, void *pv, DWORD dwDestContext, void *pvDestContext, DWORD mshlflags);
	HRESULT STDMETHODCALLTYPE ReleaseMarshalData(IStream *pStm);
	HRESULT STDMETHODCALLTYPE UnmarshalInterface(IStream *pStm, const IID &riid, void **ppv);
	HRESULT STDMETHODCALLTYPE Commit(DWORD grfCommitFlags);
	HRESULT STDMETHODCALLTYPE CopyTo(DWORD ciidExclude, const IID *rgiidExclude, SNB snbExclude, IStorage *pstgDest);
	HRESULT STDMETHODCALLTYPE CreateStorage(const OLECHAR *pwcsName, DWORD grfMode, DWORD reserved1, DWORD reserved2, IStorage **ppstg);
	HRESULT STDMETHODCALLTYPE CreateStream(const OLECHAR *pwcsName, DWORD grfMode, DWORD reserved1, DWORD reserved2, IStream **ppstm);
	HRESULT STDMETHODCALLTYPE DestroyElement(const OLECHAR *pwcsName);
	HRESULT STDMETHODCALLTYPE EnumElements(DWORD reserved1, void *reserved2, DWORD reserved3, IEnumSTATSTG **ppenum);
	HRESULT STDMETHODCALLTYPE MoveElementTo(const OLECHAR *pwcsName, IStorage *pstgDest, const OLECHAR *pwcsNewName, DWORD grfFlags);
	HRESULT STDMETHODCALLTYPE OpenStorage(const OLECHAR *pwcsName, IStorage *pstgPriority, DWORD grfMode, SNB snbExclude, DWORD reserved, IStorage **ppstg);
	HRESULT STDMETHODCALLTYPE OpenStream(const OLECHAR *pwcsName, void *reserved1, DWORD grfMode, DWORD reserved2, IStream **ppstm);
	HRESULT STDMETHODCALLTYPE RenameElement(const OLECHAR *pwcsOldName, const OLECHAR *pwcsNewName);
	HRESULT STDMETHODCALLTYPE Revert();
	HRESULT STDMETHODCALLTYPE SetClass(const IID &clsid);
	HRESULT STDMETHODCALLTYPE SetElementTimes(const OLECHAR *pwcsName, const FILETIME *pctime, const FILETIME *patime, const FILETIME *pmtime);
	HRESULT STDMETHODCALLTYPE SetStateBits(DWORD grfStateBits, DWORD grfMask);
	HRESULT STDMETHODCALLTYPE Stat(STATSTG *pstatstg, DWORD grfStatFlag);

	HRESULT STDMETHODCALLTYPE QueryInterface(const IID &riid, void **ppvObject);
	ULONG STDMETHODCALLTYPE AddRef();
	ULONG STDMETHODCALLTYPE Release();
};