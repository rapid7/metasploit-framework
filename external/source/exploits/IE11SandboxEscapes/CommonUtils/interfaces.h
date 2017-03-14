#pragma once

#include <tchar.h>
#include <Windows.h>
#include <comdef.h>
#include <Shtypes.h>
#include <DocObj.h>

struct __declspec(uuid("1AC7516E-E6BB-4A69-B63F-E841904DC5A6")) IIEUserBroker : IUnknown
{
	virtual HRESULT STDMETHODCALLTYPE Initialize(HWND *, LPCWSTR, LPDWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE CreateProcessW(DWORD pid, LPWSTR appName, LPWSTR cmdline, DWORD, DWORD, LPCSTR, WORD*, /* _BROKER_STARTUPINFOW*/ void *, /* _BROKER_PROCESS_INFORMATION */ void*) = 0;
	virtual HRESULT STDMETHODCALLTYPE WinExec(DWORD pid, LPCSTR, DWORD, DWORD*) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerCreateKnownObject(_GUID const &, _GUID const &, IUnknown * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerCoCreateInstance() = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerCoCreateInstanceEx(DWORD pid, _GUID const &, IUnknown *, DWORD, _COSERVERINFO *, DWORD, /* tagBROKER_MULTI_QI */ void *) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerCoGetClassObject(DWORD pid, _GUID const &, DWORD, _COSERVERINFO *, _GUID const &, IUnknown * *) = 0;
};

struct __declspec(uuid("BDB57FF2-79B9-4205-9447-F5FE85F37312")) CIEAxInstallBroker
{
};

struct __declspec(uuid("B2103BDB-B79E-4474-8424-4363161118D5")) IIEAxInstallBrokerBroker : IUnknown
{
	virtual HRESULT STDMETHODCALLTYPE BrokerGetAxInstallBroker(REFCLSID rclsid, REFIID riid, int unknown, int type, HWND, IUnknown** ppv) = 0;
};

_COM_SMARTPTR_TYPEDEF(IIEAxInstallBrokerBroker, __uuidof(IIEAxInstallBrokerBroker));

struct ERF
{
	//+0x000 erfOper          : Int4B
	//	+ 0x004 erfType : Int4B
	//	+ 0x008 fError : Int4B

	int erfOper;
	int erfType;
	int fError;
};

struct FNAME
{
	/*+0x000 pszFilename      : Ptr32 Char
	+ 0x004 pNextName : Ptr32 sFNAME
	+ 0x008 status : Uint4B*/

	char* pszFilenane;
	FNAME* pNextName;
	UINT status;
};

struct SESSION
{
	/*+0x000 cbCabSize        : Uint4B
	+ 0x004 erf : ERF
	+ 0x010 pFileList : Ptr32 sFNAME
	+ 0x014 cFiles : Uint4B
	+ 0x018 flags : Uint4B
	+ 0x01c achLocation : [260] Char
	+ 0x120 achFile : [260] Char
	+ 0x224 achCabPath : [260] Char
	+ 0x328 pFilesToExtract : Ptr32 sFNAME*/

	UINT cbCabSize;
	ERF erf;
	FNAME* pFileList;
	UINT cFiles;
	UINT flags;
	char achLocation[260];
	char achFile[260];
	char achCabPath[260];
	FNAME* pFilesToExtract;
};

struct __declspec(uuid("BC0EC710-A3ED-4F99-B14F-5FD59FDACEA3")) IIeAxiInstaller2 : IUnknown
{
	virtual HRESULT STDMETHODCALLTYPE VerifyFile(BSTR, HWND__ *, BSTR, BSTR, BSTR, unsigned int, unsigned int, _GUID const &, BSTR*, unsigned int *, unsigned char **) = 0;
	virtual HRESULT STDMETHODCALLTYPE RunSetupCommand(BSTR, HWND__ *, BSTR, BSTR, BSTR, BSTR, unsigned int, unsigned int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE InstallFile(BSTR sessionGuid, HWND__ *, BSTR sourcePath, BSTR sourceFile, BSTR destPath, BSTR destFile, unsigned int unk) = 0;
	virtual HRESULT STDMETHODCALLTYPE RegisterExeFile(BSTR sessionGuid, BSTR cmdline, int unk, _PROCESS_INFORMATION *) = 0;
	virtual HRESULT STDMETHODCALLTYPE RegisterDllFile(BSTR, BSTR, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE InstallCatalogFile(BSTR, BSTR) = 0;
	virtual HRESULT STDMETHODCALLTYPE UpdateLanguageCheck(BSTR, unsigned short const *, _FILETIME) = 0;
	virtual HRESULT STDMETHODCALLTYPE UpdateDistributionUnit(BSTR, unsigned short const *, unsigned short const *, unsigned int, unsigned int *, unsigned short const *, int, unsigned short const *, unsigned short const *, long, unsigned short const *, unsigned short const *, unsigned short const *, unsigned int, unsigned short const * *, unsigned int, unsigned short const * *, unsigned int, unsigned short const * *, unsigned short const * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE UpdateModuleUsage(BSTR, char const *, char const *, char const *, char const *, unsigned int) = 0;
	virtual HRESULT STDMETHODCALLTYPE EnumerateFiles(BSTR sessionGuid, char const * cabPath, SESSION *session) = 0;
	virtual HRESULT STDMETHODCALLTYPE ExtractFiles(BSTR sessionGuid, char const * cabPath, SESSION *session) = 0;
	virtual HRESULT STDMETHODCALLTYPE RemoveExtractedFilesAndDirs(BSTR, SESSION *) = 0;
	virtual HRESULT STDMETHODCALLTYPE CreateExtensionsManager(BSTR, _GUID const &, IUnknown * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE RegisterDllFile2(BSTR, BSTR, int, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE UpdateDistributionUnit2(BSTR, unsigned short const *, unsigned short const *, unsigned int, unsigned int *, unsigned short const *, int, unsigned short const *, unsigned short const *, long, unsigned short const *, unsigned short const *, unsigned short const *, unsigned int, unsigned short const * *, int *, unsigned int, unsigned short const * *, unsigned int, unsigned short const * *, unsigned short const * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE UpdateAllowedDomainsList(_GUID const &, BSTR, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE DeleteExtractedFile(char const *) = 0;
};

_COM_SMARTPTR_TYPEDEF(IIeAxiInstaller2, __uuidof(IIeAxiInstaller2));

struct __declspec(uuid("9AEA8A59-E0C9-40F1-87DD-757061D56177")) IIeAxiAdminInstaller : IUnknown
{
	virtual HRESULT STDMETHODCALLTYPE  InitializeAdminInstaller(BSTR, BSTR, BSTR*) = 0;
};

_COM_SMARTPTR_TYPEDEF(IIeAxiAdminInstaller, __uuidof(IIeAxiAdminInstaller));

struct __declspec(uuid("A4AAAE00-22E5-4742-ABB7-379D9493A3B7")) IShdocvwBroker : IUnknown
{
	virtual HRESULT STDMETHODCALLTYPE RedirectUrl(WORD const *, DWORD, /* _BROKER_REDIRECT_DETAIL */ void *, /* IXMicTestMode */ void*) = 0;
	virtual HRESULT STDMETHODCALLTYPE RedirectShortcut(WORD const *, WORD const *, DWORD, /* _BROKER_REDIRECT_DETAIL */ void *) = 0;
	virtual HRESULT STDMETHODCALLTYPE RedirectUrlWithBindInfo(/* _BROKER_BIND_INFO */ void *, /* _BROKER_REDIRECT_DETAIL */ void *, /* IXMicTestMode */ void *) = 0;
	virtual HRESULT STDMETHODCALLTYPE NavigateUrlInNewTabInstance(/* _BROKER_BIND_INFO */ void *, /*_BROKER_REDIRECT_DETAIL */ void *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowInternetOptions(HWND *, WORD const *, WORD const *, long, ITEMIDLIST_ABSOLUTE * *, DWORD, int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowInternetOptionsZones(HWND *, WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowInternetOptionsLanguages(HWND *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowPopupManager(HWND *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowCachesAndDatabases(HWND *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ConfigurePopupExemption(HWND *, int, WORD const *, int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ConfigurePopupMgr(HWND *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE RemoveFirstHomePage(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetHomePage(HWND *, long, ITEMIDLIST_ABSOLUTE * *, long) = 0;
	virtual HRESULT STDMETHODCALLTYPE RemoveHomePage(HWND *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE FixInternetSecurity(HWND *, int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowManageAddons(HWND *, DWORD, _GUID *, DWORD, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE CacheExtFileVersion(_GUID const &, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowAxApprovalDlg(HWND *, _GUID const &, int, WORD const *, WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE SendLink(ITEMIDLIST_ABSOLUTE const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE SendPage(HWND *, IDataObject *) = 0;
	virtual HRESULT STDMETHODCALLTYPE NewMessage(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE ReadMail(HWND *) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetAsBackground(LPCWSTR) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowSaveBrowseFile(HWND *, WORD const *, WORD const *, int, int, WORD * *, DWORD *, DWORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE SaveAsComplete(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE SaveAsFile(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE StartImportExportWizard(int, HWND *) = 0;
	virtual HRESULT STDMETHODCALLTYPE EditWith(HWND *, DWORD, HANDLE, DWORD, LPCWSTR, LPCWSTR, LPCWSTR) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowSaveImage(HWND *, WORD const *, DWORD, WORD * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE SaveImage(WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE CreateShortcut(/* _internet_shortcut_params */ void*, int, HWND *, WORD *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowSynchronizeUI(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE OpenFolderAndSelectItem(WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE DoGetOpenFileNameDialog(/* _SOpenDlg */ void *) = 0;
	virtual HRESULT STDMETHODCALLTYPE DoGetLocationPlatformConsent(HWND *, DWORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowSaveFileName(HWND *, WORD const *, WORD const *, WORD const *, WORD const *, DWORD, WORD *, DWORD, WORD const *, WORD * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE SaveFile(HWND *, DWORD, DWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE VerifyTrustAndExecute(HWND *, WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetFeedByUrl(WORD const *, WORD * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerAddToFavoritesEx(HWND *, ITEMIDLIST_ABSOLUTE const *, WORD const *, DWORD, IOleCommandTarget *, WORD *, DWORD, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE Subscribe(HWND *, WORD const *, WORD const *, int, int, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE MarkAllItemsRead(WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE MarkItemsRead(WORD const *, DWORD *, DWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE Properties(HWND *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE DeleteFeedItem(HWND *, WORD const *, DWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE DeleteFeed(HWND *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE DeleteFolder(HWND *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE Refresh(WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE MoveFeed(HWND *, WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE MoveFeedFolder(HWND *, WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE RenameFeed(HWND *, WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE RenameFeedFolder(HWND *, WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE NewFeedFolder(LPCWSTR) = 0;
	virtual HRESULT STDMETHODCALLTYPE FeedRefreshAll(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowFeedAuthDialog(HWND *, WORD const *, /* FEEDTASKS_AUTHTYPE */ DWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowAddSearchProvider(HWND *, WORD const *, WORD const *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE InitHKCUSearchScopesRegKey(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE DoShowDeleteBrowsingHistoryDialog(HWND *) = 0;
	virtual HRESULT STDMETHODCALLTYPE StartAutoProxyDetection(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE EditAntiPhishingOptinSetting(HWND *, DWORD, int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowMyPictures(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE ChangeIntranetSettings(HWND *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE FixProtectedModeSettings(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowAddService(HWND *, WORD const *, WORD const *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowAddWebFilter(HWND *, WORD const *, WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE DoBrowserRegister() = 0;
	virtual HRESULT STDMETHODCALLTYPE DoBrowserRevoke(long) = 0;
	virtual HRESULT STDMETHODCALLTYPE DoOnNavigate(long, VARIANT *) = 0;
	virtual HRESULT STDMETHODCALLTYPE AddDesktopComponent(WORD *, WORD *, VARIANT *, VARIANT *, VARIANT *, VARIANT *) = 0;
	virtual HRESULT STDMETHODCALLTYPE DoOnCreated(long, IUnknown *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetShellWindows(IUnknown * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE CustomizeSettings(short, short, WORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE OnFocus(int) = 0;
	virtual HRESULT STDMETHODCALLTYPE IsProtectedModeUrl(LPCWSTR) = 0;
	virtual HRESULT STDMETHODCALLTYPE DoDiagnoseConnectionProblems(HWND *, WORD *, WORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE PerformDoDragDrop(HWND *, /* IEDataObjectWrapper */ void *, /* IEDropSourceWrapper */ void *, DWORD, DWORD, DWORD *, long *) = 0;
	virtual HRESULT STDMETHODCALLTYPE TurnOnFeedSyncEngine(HWND *) = 0;
	virtual HRESULT STDMETHODCALLTYPE InternetSetPerSiteCookieDecisionW(WORD const *, DWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetAttachmentUserOverride(LPCWSTR) = 0;
	virtual HRESULT STDMETHODCALLTYPE WriteClassesOfCategory(_GUID const &, int, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerSetFocus(DWORD, HWND *) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerShellNotifyIconA(DWORD, /* _BROKER_NOTIFYICONDATAA */ void *) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerShellNotifyIconW(DWORD, /* _BROKER_NOTIFYICONDATAW */ void*) = 0;
	virtual HRESULT STDMETHODCALLTYPE DisplayVirtualizedFolder(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerSetWindowPos(HWND *, HWND *, int, int, int, int, DWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE WriteUntrustedControlDetails(_GUID const &, WORD const *, WORD const *, DWORD, BYTE *) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetComponentDeclined(char const *, char const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE DoShowPrintDialog(/* _BROKER_PRINTDLG */ void*) = 0;
	virtual HRESULT STDMETHODCALLTYPE NavigateHomePages(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowAxDomainApprovalDlg(HWND *, _GUID const &, int, WORD const *, WORD const *, WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ActivateExtensionFromCLSID(HWND *, WORD const *, DWORD, DWORD, DWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerCoCreateNewIEWindow(DWORD, _GUID const &, void * *, int, DWORD, int, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE BeginFakeModalityForwardingToTab() = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerEnableWindow(int, int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE EndFakeModalityForwardingToTab(HWND *, long) = 0;
	virtual HRESULT STDMETHODCALLTYPE CloseOldTabIfFailed(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE EnableSuggestedSites(HWND *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetProgressValue(HWND *, DWORD, DWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerStartNewIESession(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE CompatDetachInputQueue(HWND *) = 0;
	virtual HRESULT STDMETHODCALLTYPE CompatAttachInputQueue(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetToggleKeys(DWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE RepositionInfrontIE(HWND *, int, int, int, int, DWORD) = 0;
	//virtual HRESULT STDMETHODCALLTYPE ReportShipAssert(DWORD, DWORD, DWORD, WORD const *, WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowOpenSafeOpenDialog(HWND *, /* _BROKER_SAFEOPENDLGPARAM */ void *, DWORD *, DWORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerAddSiteToStart(HWND *, WORD *, WORD const *, long, DWORD) = 0;
	virtual HRESULT STDMETHODCALLTYPE SiteModeAddThumbnailButton(DWORD *, HWND *, WORD *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE SiteModeAddButtonStyle(int *, HWND *, DWORD, WORD *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE IsSiteModeFirstRun(int, WORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE IsImmersiveSiteModeFirstRun(int, WORD const *, WORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetImmersivePinnedState(DWORD, int, int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerDoSiteModeDragDrop(DWORD, long *, DWORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE EnterUILock(long) = 0;
	virtual HRESULT STDMETHODCALLTYPE LeaveUILock(long) = 0;
	virtual HRESULT STDMETHODCALLTYPE CredentialAdd(/* _IECREDENTIAL */ void *) = 0;
	virtual HRESULT STDMETHODCALLTYPE CredentialGet(WORD const *, WORD const *, /*_IECREDENTIAL */ void * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE CredentialFindAllByUrl(WORD const *, DWORD *, /*  _IECREDENTIAL */ void * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE CredentialRemove(WORD const *, WORD const *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowOpenFile(HWND *, DWORD, DWORD, WORD *, WORD *, WORD const *, WORD const *, WORD const *, /* _OPEN_FILE_RESULT */ void * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowImmersiveOpenFilePicker(HWND *, int, WORD const *, IUnknown * *, /* _OPEN_FILE_RESULT */ void * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE RegisterFileDragDrop(HWND *, DWORD, unsigned char *) = 0;
	virtual HRESULT STDMETHODCALLTYPE RevokeFileDragDrop(HWND *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetFileTokensForDragDropA(HWND *, DWORD, char * *, /* _OPEN_FILE_RESULT */ void * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetFileTokensForDragDropW(HWND *, DWORD, WORD * *, /* _OPEN_FILE_RESULT */ void * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowEPMCompatDocHostConsent(HWND *, WORD const *, WORD const *, int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetModuleInfoFromSignature(WORD const *, WORD * *, DWORD, WORD * *, WORD * *, WORD * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShellExecWithActivationHandler(HWND *, LPCWSTR, LPCWSTR, int,  /* _MSLAUNCH_HANDLER_STATUS */ void *) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShellExecFolderUri(LPCWSTR) = 0;
	virtual HRESULT STDMETHODCALLTYPE ShowIMMessageDialog(HWND *, WORD const *, WORD const *, /* _IM_BUTTON_LABEL_ID */ void *, DWORD, DWORD, DWORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetFileHandle(HWND *, BSTR filename, BYTE * hash, DWORD hashlen, HANDLE*) = 0;
	virtual HRESULT STDMETHODCALLTYPE MOTWCreateFileW(DWORD dwProcessId, BSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, int dwOpenMode, DWORD dwFlagsAndAttributes, ULONGLONG* h, DWORD *error) = 0;
	virtual HRESULT STDMETHODCALLTYPE MOTWFindFileW() = 0;
	virtual HRESULT STDMETHODCALLTYPE MOTWGetFileDataW() = 0;
	virtual HRESULT STDMETHODCALLTYPE WinRTInitializeWithWindow(IUnknown *, HWND *) = 0;
	virtual HRESULT STDMETHODCALLTYPE DoProvisionNetworks(HWND *, WORD const *, DWORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetAccessibilityStylesheet(DWORD, unsigned __int64 *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetAppCacheUsage(WORD const *, unsigned __int64 *, unsigned __int64 *) = 0;
	virtual HRESULT STDMETHODCALLTYPE HiddenTabRequest(/* _BROKER_BIND_INFO */ void *, /* _BROKER_REDIRECT_DETAIL */ void *, /* _HIDDENTAB_REQUEST_INFO */ void *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetMaxCpuSpeed(DWORD *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetProofOfPossessionTokensForUrl(WORD const *, DWORD *, /* _IEProofOfPossessionToken */ void * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetLoginUrl(LPWSTR*) = 0;
	virtual HRESULT STDMETHODCALLTYPE ScheduleDeleteEncryptedMediaData() = 0;
	virtual HRESULT STDMETHODCALLTYPE IsDeleteEncryptedMediaDataPending() = 0;
	virtual HRESULT STDMETHODCALLTYPE GetFrameAppDataPathA() = 0;
	virtual HRESULT STDMETHODCALLTYPE BrokerHandlePrivateNetworkFailure() = 0;

};


_COM_SMARTPTR_TYPEDEF(IIEUserBroker, __uuidof(IIEUserBroker));
_COM_SMARTPTR_TYPEDEF(IShdocvwBroker, __uuidof(IShdocvwBroker));