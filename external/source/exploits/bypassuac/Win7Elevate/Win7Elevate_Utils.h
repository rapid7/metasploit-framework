#pragma once

namespace W7EUtils
{
	bool GetProcessList(HWND hWnd, std::map< DWORD, std::wstring > &mapProcs);

	bool OpenProcessToInject(HWND hWnd, HANDLE *pOutProcHandle, DWORD dwPid, const wchar_t *szProcName);

	bool GetElevationType(TOKEN_ELEVATION_TYPE * ptet);

	template < typename T > class GetProcAddr
	{
	public:
		T f;

		__forceinline GetProcAddr(FARPROC (WINAPI *fpGetProcAddress)(HMODULE hModule, LPCSTR lpProcName), HMODULE hModule, const char *lpProcName)
		{
			f = reinterpret_cast< T >(fpGetProcAddress(hModule, lpProcName));
		}
	};

	class CTempResource
	{
	private:
		HINSTANCE m_hInstance;
		int m_iResourceId;
		std::wstring m_strFilePath;
	public:
		CTempResource(HINSTANCE hInstance, int iResourceId);
		virtual ~CTempResource();
		bool GetFilePath(std::wstring &strPath);
	};

	class CRemoteMemory
	{
	private:
		HANDLE m_hRemoteProcess;
		std::list< void * > m_listRemoteAllocations;
		bool m_bAnyFailures;

	private:
		CRemoteMemory(const CRemoteMemory &rhs); // Disallow.
		CRemoteMemory &operator=(const CRemoteMemory &rhs); // Disallow.

	public:
		CRemoteMemory(HANDLE hRemoteProcess);
		virtual ~CRemoteMemory();
		void LeakMemory();
		bool AnyFailures() const;
		void *AllocAndCopyMemory(const void *pLocalBuffer, SIZE_T bufferSize, bool bExecutable, bool bConst = true);
		wchar_t *AllocAndCopyMemory(const wchar_t *szLocalString, bool bConst = true);
		char *AllocAndCopyMemory(const char *szLocalString, bool bConst = true);
	};
}
