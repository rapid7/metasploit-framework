#pragma once

#include <windows.h>

#include <string>

//
//	By Pavel
//
//	This class is used for holding some data in the memory that can be accessed
//	from any saparate process in the system by its name.
//	It uses memeory mapped files with fixed size sections. Size is enough to hold
//	as many chars as system supports for file paths.
//
//	Once instance was created, it can be accessed from the another progect by the name.
//	This shared object will be cleaned up when the last instance of this class will be destroyed
//	across whole system.
//
//	Generally, it is used following:
//	1. Create the first instance, set up data, keep it alive forever
//	2. Access to created object by its name from another prject by creating
//	   temporary instance of that object. After you dont need this object, destroy it.
//

class CInterprocessStorage {
public:
	static const size_t MaxSize = MAX_PATH;
	static const size_t MaxCount = MAX_PATH / sizeof(TCHAR);

	//
	//	Creates initial named object or opens existing, incrementing its reference count.
	//	Resets all object's contents.
	//
	static CInterprocessStorage *Create( const TCHAR * Name );
	//
	//	Creates initial named object or opens existing, incrementing its reference count, 
	//	sets its value to the specified string
	//
	static CInterprocessStorage *Create( const TCHAR * Name, std::wstring& String );

	//
	//	Opens existing named object. Does not modify its data.
	//
	static CInterprocessStorage *Open( const TCHAR * Name );

	//
	//	Queries object's name.
	//
	std::wstring GetName();

	//
	//	Queries object's value
	//
	void GetString( std::wstring& String );

	//
	//	Tries to get named object's value, accessing one by the name.
	//
	static bool GetString( const TCHAR *Name, std::wstring& String );

	//
	//	Sets object's Value
	//
	void SetString( std::wstring& String );

	~CInterprocessStorage();

private:
	const HANDLE _hMapping;
	const LPVOID _pBase;
	const TCHAR *_Name;
	CInterprocessStorage( const TCHAR *Name, HANDLE Mapping, LPVOID Base );
};

//	
//	Logs data to file.
//	Log takes place ony if one special file exists. File is named as its hosting application
//	appended by .debug
//	Example: Code runs in the explorer.exe => log will be allowed if near the exe 
//	will be placed file explorer.exe.debug
//	
//	It uses mutual execution to prevent unreadable content of the log file.
//	Log file has path = %temp%w7e.og
//
//	FILE_FLAG_WRITE_THROUGH flag is used to prevent log to be unsaved if application crashed.
//
class CLogger {
public:
	static void LogLine( std::wstring& Text );
	static void LogLine( const TCHAR *Text );
	static void LogLine( );
	static void Log( std::wstring& Text );
	static void Log( const TCHAR *Text );
	static void Log( const TCHAR Char );
	static void Reset( );

private:
	static std::wstring GetPath();
};

//
//	Formats system error codes that were obtained by calling GetLastError.
//	
class CError {
public:
	static std::wstring Format( DWORD ErrorCode );
	static std::wstring Format( DWORD ErrorCode, const TCHAR *Title, const TCHAR *API );
};
