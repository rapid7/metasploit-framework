#include "interfaces.h"

#include <vector>

bstr_t GetTemp(LPCWSTR name);
bstr_t GetTempPath();
bstr_t WriteTempFile(LPCWSTR name, unsigned char* buf, size_t len);
std::vector<unsigned char> ReadFileToMem(LPCWSTR name);
void DebugPrintf(LPCSTR lpFormat, ...);
bstr_t GetUserSid();
void DisableImpersonation(IUnknown* pUnk);
void SetCloaking(IUnknown* pUnk);
IIEUserBrokerPtr CreateBroker();
IShdocvwBroker* CreateSHDocVw();
bstr_t GetWindowsSystemDirectory();
bstr_t GetExecutableFileName(HMODULE hModule);
extern "C" int DeleteLink(LPCWSTR par_src);
extern "C" int CreateLink(LPCWSTR par_src, LPCWSTR par_dst, int opt_volatile);
bstr_t GetSessionPath();
LSTATUS CreateRegistryValueString(HKEY hKey, LPCWSTR lpName, LPCWSTR lpString);
LSTATUS CreateRegistryValueDword(HKEY hKey, LPCWSTR lpName, DWORD d);