#pragma once
#include <Windows.h>
#include <Msi.h>
#pragma comment(lib,"msi.lib")

class InstallerDispatcher {

public:
	InstallerDispatcher();
	void RunAdminInstall(WCHAR* targetdir);
	HANDLE InstallerDispatcherThread;
	~InstallerDispatcher();
private:
	
	WCHAR msi_file[MAX_PATH];
	WCHAR InternalInstallDir[MAX_PATH];
	
};