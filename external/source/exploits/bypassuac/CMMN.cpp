#include "stdafx.h"

#include "CMMN.h"

#include <Shlobj.h>

#include <sstream>
#include <windows.h>
#include <WinIOCtl.h>


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

