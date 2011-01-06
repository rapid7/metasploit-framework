#include "stdafx.h"

#include "CMMN.h"

#include <Shlobj.h>

#include <sstream>
#include <windows.h>
#include <WinIOCtl.h>

/*************************************************************************************************/
/*************************************************************************************************/
/*************************************************************************************************/

std::wstring CError::Format( DWORD ErrorCode ) 
{
	return Format( ErrorCode, NULL, NULL );
}

std::wstring CError::Format(DWORD ErrorCode, const TCHAR *Title, const TCHAR *API) 
{
   LPVOID lpvMessageBuffer;

   FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, ErrorCode,
			MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
			(LPTSTR)&lpvMessageBuffer, 0, NULL);

   std::wstring result;

	std::wostringstream es(TEXT(""));
	es << ErrorCode;

	if ( Title )
		{ result.append( Title ); result.append( TEXT("\n") ); }
	else
		{ result.append( TEXT("ERROR") ); result.append( TEXT("\n") ); }

	if ( API )
	{ result.append( TEXT("API        = ") );result.append( API ); result.append( TEXT("\n") ); }
	  result.append( TEXT("error code = ") );result.append( es.str() );result.append( TEXT("\n") );
	if( lpvMessageBuffer )
	{ result.append( TEXT("message    = ") );result.append( (TCHAR *)lpvMessageBuffer );result.append( TEXT("\n") ); }

	if ( lpvMessageBuffer )
	{ LocalFree(lpvMessageBuffer); }

   return result;
}

/*************************************************************************************************/
/*************************************************************************************************/
/*************************************************************************************************/

CInterprocessStorage *CInterprocessStorage::Create(const TCHAR *Name, std::wstring& String) 
{
	CInterprocessStorage *storage = Create( Name );
	if ( !storage )
		return NULL;

	storage->SetString( String );
	return storage;
}

CInterprocessStorage *CInterprocessStorage::Create(const TCHAR *Name) 
{
	if ( !Name )
		return NULL;

	HANDLE hMap = CreateFileMapping( NULL, NULL, PAGE_READWRITE, 0, MaxSize, Name );
	if ( hMap )
	{
		LPVOID view = MapViewOfFile( hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0 );
		if ( view )
		{
			memset( view, 0, MaxSize );
			return new CInterprocessStorage( Name, hMap, view );
		}

		CloseHandle( hMap );
	}

	return NULL;
}

CInterprocessStorage *CInterprocessStorage::Open(const TCHAR *Name) 
{
	if ( !Name )
		return NULL;

	HANDLE hMap = OpenFileMapping( FILE_MAP_ALL_ACCESS, TRUE, Name );
	if ( hMap )
	{
		LPVOID view = MapViewOfFile( hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0 );
		if ( view )
			return new CInterprocessStorage( Name, hMap, view );

		CloseHandle( hMap );
	}

	return NULL;
}

CInterprocessStorage::CInterprocessStorage(const TCHAR *Name, HANDLE Mapping, LPVOID Base)
: _Name(Name), _hMapping(Mapping), _pBase(Base)
{
}

std::wstring CInterprocessStorage::GetName()
{
	return std::wstring( _Name );
}

void CInterprocessStorage::GetString(std::wstring &String)
{
	String.assign( reinterpret_cast<TCHAR *>(_pBase) );
}

void CInterprocessStorage::SetString(std::wstring &String)
{
	size_t count = min( String.size(), MaxCount - 1 );
	memcpy( _pBase, String.data(), count * sizeof(TCHAR) );
	*(reinterpret_cast<TCHAR *>(_pBase) + count) = 0;
}

bool CInterprocessStorage::GetString( const TCHAR *Name, std::wstring& String )
{
	CInterprocessStorage *storage = Open( Name );
	if ( !storage )
		return false;

	storage->GetString( String );
	delete storage;

	return true;
}

CInterprocessStorage::~CInterprocessStorage()
{
	UnmapViewOfFile( _pBase );
	CloseHandle( _hMapping );
}

/*************************************************************************************************/
/*************************************************************************************************/
/*************************************************************************************************/

std::wstring CLogger::GetPath()
{
	std::wstring path;

	TCHAR buffer[MAX_PATH];
	if ( GetTempPath( MAX_PATH, buffer ) )
	{
		path.assign( buffer );
		path.append( TEXT("w7e.log") );
	}

	return path;
}

void CLogger::Reset()
{
	DeleteFile( GetPath().c_str() );
}

void CLogger::LogLine( std::wstring& Text )
{
	std::wstring tmp( Text.c_str() );
	tmp.append( TEXT("\n") );
	Log( tmp );
}

void CLogger::LogLine( )
{
	Log( TEXT("\n") );
}

void CLogger::LogLine( const TCHAR *Text )
{
	if ( Text )
		LogLine( std::wstring( Text ) );
}

void CLogger::Log( const TCHAR Char )
{
	std::wstring tmp;
	tmp.append( &Char, 1 );
	Log( tmp );
}

void CLogger::Log( const TCHAR *Text )
{
	if ( Text )
		Log( std::wstring( Text ) );
}

void CLogger::Log( std::wstring& Text )
{
	TCHAR buffer[MAX_PATH];
	//
	//	We have to check it every time to be reflective if user created this file 
	//	while program was runnig.
	//
	if ( GetModuleFileName( NULL, buffer, MAX_PATH ) )
	{
		std::wstring dbg( buffer );
		dbg.append( TEXT(".debug") );
		HANDLE hdbg =  CreateFile( dbg.c_str(), FILE_READ_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL );
		if ( INVALID_HANDLE_VALUE == hdbg )
			return;

		CloseHandle( hdbg );
	}

	HANDLE mutex = CreateMutex( NULL, FALSE, TEXT("CLoggerSync") );
	if ( mutex ) WaitForSingleObject( mutex , INFINITE );
		HANDLE hFile = CreateFile( GetPath().c_str(), FILE_ALL_ACCESS, 0, NULL, OPEN_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL );
		if( INVALID_HANDLE_VALUE != hFile )
		{
			SetFilePointer( hFile, 0, NULL, FILE_END );

			DWORD written;
			WriteFile( hFile, Text.data(), Text.size() * sizeof(TCHAR), &written, NULL );

			CloseHandle( hFile );
		}
	if ( mutex ) ReleaseMutex( mutex );
	if ( mutex ) CloseHandle( mutex );
}