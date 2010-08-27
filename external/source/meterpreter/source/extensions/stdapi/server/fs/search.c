#include "precomp.h"
#include "fs.h"
#include "search.h"

/*
 * Helper function to add a search result to the response packet.
 */
VOID search_add_result( Packet * pResponse, char * cpDirectory, char * cpFileName, DWORD dwFileSize )
{	
	Tlv entry[3] = {0};
	DWORD dwSize = 0;

	do
	{
		entry[0].header.type   = TLV_TYPE_FILE_PATH;
		entry[0].header.length = (DWORD)( strlen(cpDirectory) + 1 );
		entry[0].buffer        = cpDirectory;

		entry[1].header.type   = TLV_TYPE_FILE_NAME;
		entry[1].header.length = (DWORD)( strlen(cpFileName) + 1 );
		entry[1].buffer        = cpFileName;

		dwSize = htonl( dwFileSize );
		entry[2].header.type   = TLV_TYPE_FILE_SIZE;
		entry[2].header.length = sizeof(DWORD);
		entry[2].buffer        = (PUCHAR)&dwSize;

		packet_add_tlv_group( pResponse, TLV_TYPE_SEARCH_RESULTS, entry, 3 );

	} while( 0 );
}

/*
 * Helper function to initilize the Windows Desktop Search 3.0 COM interface (if available).
 */
VOID wds3_startup( WDS3_INTERFACE * pWDS3Interface )
{
	DWORD dwResult = ERROR_SUCCESS;
	HRESULT hr     = 0;

	do
	{
		if( !pWDS3Interface )
			BREAK_WITH_ERROR( "[SEARCH] wds3_startup: !pWDS3Interface", ERROR_INVALID_HANDLE );

		memset( pWDS3Interface, 0, sizeof(WDS3_INTERFACE) );

		hr = CoInitialize( NULL );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_startup: CoInitializeEx Failed", hr );
	
		hr = CoCreateInstance( &_CLSID_CSearchManager, NULL, CLSCTX_ALL, &_IID_ISearchManager, (LPVOID *)&pWDS3Interface->pSearchManager );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_startup: CoCreateInstance _IID_ISearchManager Failed", hr );

		hr = ISearchManager_GetCatalog( pWDS3Interface->pSearchManager, L"SystemIndex", &pWDS3Interface->pSearchCatalogManager );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_startup: ISearchManager_GetCatalog Failed", hr );

		hr = ISearchCatalogManager_GetCrawlScopeManager( pWDS3Interface->pSearchCatalogManager, &pWDS3Interface->pCrawlScopeManager );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_startup: ISearchCatalogManager_GetCrawlScopeManager Failed", hr );
			
		pWDS3Interface->bWDS3Available = TRUE;

	} while( 0 );

	if( dwResult != ERROR_SUCCESS && pWDS3Interface )
		pWDS3Interface->bWDS3Available = FALSE;
}

/*
 * Helper function to cleanup the Windows Desktop Search 3.0 COM interface.
 */
VOID wds3_shutdown( WDS3_INTERFACE * pWDS3Interface )
{
	do
	{
		if( !pWDS3Interface )
			break;

		if( pWDS3Interface->pCrawlScopeManager )
		{
			ISearchCrawlScopeManager_Release( pWDS3Interface->pCrawlScopeManager );
			pWDS3Interface->pCrawlScopeManager = NULL;
		}

		if( pWDS3Interface->pSearchCatalogManager )
		{
			ISearchCatalogManager_Release( pWDS3Interface->pSearchCatalogManager );
			pWDS3Interface->pSearchCatalogManager = NULL;
		}

		if( pWDS3Interface->pSearchManager )
		{
			ISearchManager_Release( pWDS3Interface->pSearchManager );
			pWDS3Interface->pSearchManager = NULL;
		}

		pWDS3Interface->bWDS3Available = FALSE;

		CoUninitialize();

	} while( 0 );
}

/*
 * Helper function to check if a given directory is indexed in the WDS crawl scope
 */
BOOL wds3_indexed( WDS3_INTERFACE * pWDS3Interface, char * cpDirectory )
{
	HRESULT hr          = 0;
	size_t dwLength     = 0;
	WCHAR * wpDirectory = NULL;
	BOOL bResult        = FALSE;

	do
	{
		if( !pWDS3Interface->bWDS3Available )
			break;

		dwLength = mbstowcs( NULL, cpDirectory, 0 ) + 1;

		wpDirectory = (WCHAR *)malloc( dwLength * sizeof(WCHAR) );
		if( !wpDirectory )
			break;

		memset( wpDirectory, 0, dwLength * sizeof(WCHAR) );
				
		if( mbstowcs( wpDirectory, cpDirectory, dwLength ) == -1 )
			break;

		ISearchCrawlScopeManager_IncludedInCrawlScope( pWDS3Interface->pCrawlScopeManager, wpDirectory, &bResult );

	} while( 0 );

	if( wpDirectory )
		free( wpDirectory );

	return bResult;
}

/*
 * Search via Windows Desktop Search >= 3.0 via COM ...yuk! would a kernel32!FileSearch( "*.doc" ) have killed them!?!?
 */
DWORD wds3_search( WDS3_INTERFACE * pWDS3Interface, WCHAR * wpProtocol, char * cpCurrentDirectory, SEARCH_OPTIONS * pOptions, Packet * pResponse )
{
	DWORD dwResult                    = ERROR_ACCESS_DENIED;
	WCHAR * wpSQL                     = NULL;
	WCHAR * wpQuery                   = NULL;
	WCHAR * wpConnectionString        = NULL;
	ISearchQueryHelper * pQueryHelper = NULL;
	IDataInitialize * pDataInitialize = NULL;
	IDBInitialize * pIDBInitialize    = NULL;
	IDBCreateSession * pSession       = NULL;
	IOpenRowset * pOpenRowset         = NULL;
	IDBCreateCommand * pCreateCommand = NULL;
	ICommand * pCommand               = NULL;
	ICommandText * pCommandText       = NULL;
	IRowset * pRowset                 = NULL;
	IAccessor * pAccessor             = NULL;
	size_t dwLength                   = 0;
	HRESULT hr                        = 0;
	HACCESSOR hAccessor               = 0;
	DBCOUNTITEM dbCount               = 0;
	DBBINDING dbBindings[2]           = {0};
	SEARCH_ROW rowSearchResults       = {0};
	HROW hRow[1]                      = {0};
	HROW * pRows                      = &hRow[0];

	dprintf( "[SEARCH] wds3_search: Starting..." );

	do
	{
		if( !pWDS3Interface  )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: !pWDS3Interface", ERROR_INVALID_PARAMETER );

		if( !pWDS3Interface->bWDS3Available )
			break;

		if( !pResponse || !pOptions || !wpProtocol  )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: !pResultList || !pOptions || !wpProtocol", ERROR_INVALID_PARAMETER );

		if( !cpCurrentDirectory )
			cpCurrentDirectory = pOptions->cpRootDirectory;

		hr = ISearchCatalogManager_GetQueryHelper( pWDS3Interface->pSearchCatalogManager, &pQueryHelper );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: ISearchCatalogManager_GetQueryHelper Failed", hr );

		hr = ISearchQueryHelper_put_QuerySelectColumns( pQueryHelper, L"size,path" );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: ISearchQueryHelper_put_QuerySelectColumns Failed", hr );
		
		if( cpCurrentDirectory )
		{
			WCHAR * wpWhere         = NULL;
			WCHAR * wpRootDirectory = NULL;

			do
			{
				dwLength = mbstowcs( NULL, cpCurrentDirectory, 0 ) + 1;

				wpWhere = (WCHAR * )malloc( (dwLength+128) * sizeof(WCHAR) );
				if( !wpWhere )
					BREAK_WITH_ERROR( "[SEARCH] wds3_search: !wpWhere", ERROR_OUTOFMEMORY );

				wpRootDirectory = (WCHAR * )malloc( dwLength * sizeof(WCHAR) );
				if( !wpRootDirectory )
					BREAK_WITH_ERROR( "[SEARCH] wds3_search: !wpRootDirectory", ERROR_OUTOFMEMORY );

				memset( wpRootDirectory, 0, dwLength * sizeof(WCHAR) );

				if( mbstowcs( wpRootDirectory, cpCurrentDirectory, dwLength ) == -1 )
					BREAK_WITH_ERROR( "[SEARCH] wds3_search: mbstowcs wpRootDirectory failed", ERROR_INVALID_PARAMETER );

				if( pOptions->bResursive )
					wsprintfW( (LPWSTR)wpWhere, L"AND SCOPE='%s:%s'", wpProtocol, wpRootDirectory );
				else
					wsprintfW( (LPWSTR)wpWhere, L"AND DIRECTORY='%s:%s'", wpProtocol, wpRootDirectory );
			
				hr = ISearchQueryHelper_put_QueryWhereRestrictions( pQueryHelper, wpWhere );
				if( FAILED( hr ) )
					BREAK_WITH_ERROR( "[SEARCH] wds3_search: ISearchQueryHelper_put_QueryWhereRestrictions Failed", hr );

			} while( 0 );

			if( wpWhere )
				free( wpWhere );

			if( wpRootDirectory )
				free( wpRootDirectory );
		}

		dwLength = mbstowcs( NULL, pOptions->cpFileGlob, 0 ) + 1;

		wpQuery = (WCHAR *)malloc( dwLength * sizeof(WCHAR) );
		if( !wpQuery )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: !wpQuery", ERROR_OUTOFMEMORY );

		memset( wpQuery, 0, dwLength * sizeof(WCHAR) );

		if( mbstowcs( wpQuery, pOptions->cpFileGlob, dwLength ) == -1 )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: mbstowcs wpQuery failed", ERROR_INVALID_PARAMETER );

		hr = ISearchQueryHelper_GenerateSQLFromUserQuery( pQueryHelper, wpQuery, &wpSQL );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: ISearchQueryHelper_GenerateSQLFromUserQuery Failed", hr );
		
		hr = CoCreateInstance( &_CLSID_MSDAInitialize, NULL, CLSCTX_ALL, &_IID_IDataInitialize, (LPVOID *)&pDataInitialize );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: CoCreateInstance _IID_IDataInitialize Failed", hr );

		hr = ISearchQueryHelper_get_ConnectionString( pQueryHelper, &wpConnectionString );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: ISearchQueryHelper_get_ConnectionString _IID_IDataInitialize Failed", hr );

		hr = IDataInitialize_GetDataSource( pDataInitialize, NULL, CLSCTX_INPROC_SERVER, wpConnectionString, &_IID_IDBInitialize, (IUnknown**)&pIDBInitialize );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: IDataInitialize_GetDataSource Failed", hr );

		hr = IDBInitialize_Initialize( pIDBInitialize );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: IDBInitialize_Initialize Failed", hr );

		hr = IDBInitialize_QueryInterface( pIDBInitialize, &_IID_IDBCreateSession, (LPVOID *)&pSession );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: IDBInitialize_QueryInterface Failed", hr );

		hr = IDBCreateSession_CreateSession( pSession, NULL, &_IID_IOpenRowset, (IUnknown**)&pOpenRowset );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: IDBCreateSession_CreateSession Failed", hr );

		hr = IOpenRowset_QueryInterface( pOpenRowset, &_IID_IDBCreateCommand, (LPVOID *)&pCreateCommand );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: IOpenRowset_QueryInterface Failed", hr );

		hr = IDBCreateCommand_CreateCommand( pCreateCommand, NULL, &_IID_ICommand, (IUnknown**)&pCommand );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: IDBCreateCommand_CreateCommand Failed", hr );

		hr = ICommand_QueryInterface( pCommand, &_IID_ICommandText, (LPVOID *)&pCommandText );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: ICommand_QueryInterface Failed", hr );

#ifdef DEBUGTRACE
		OutputDebugStringW( wpSQL );
#endif

		hr = ICommandText_SetCommandText( pCommandText, &DBGUID_DEFAULT, wpSQL ); 
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: ICommandText_SetCommandText Failed", hr );

		hr = ICommand_Execute( pCommand, NULL, &_IID_IRowset, NULL, NULL, (IUnknown**)&pRowset );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: ICommand_Execute Failed", hr );
		
		hr = IRowset_QueryInterface( pRowset, &_IID_IAccessor, (LPVOID *)&pAccessor );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: IRowset_QueryInterface _IID_IAccessor Failed", hr );

		memset( &dbBindings, 0, sizeof(DBBINDING)*2 );

		dbBindings[0].iOrdinal   = 1;
		dbBindings[0].dwPart     = DBPART_STATUS | DBPART_LENGTH | DBPART_VALUE;
		dbBindings[0].dwMemOwner = DBMEMOWNER_CLIENTOWNED;
		dbBindings[0].cbMaxLen   = sizeof(DWORD);
		dbBindings[0].dwFlags    = 0;
		dbBindings[0].eParamIO   = DBPARAMIO_NOTPARAM;
		dbBindings[0].wType      = DBTYPE_I4;
		dbBindings[0].obStatus   = offsetof( SEARCH_ROW, dbSizeStatus );
		dbBindings[0].obLength   = offsetof( SEARCH_ROW, dwSizeLength );
		dbBindings[0].obValue    = offsetof( SEARCH_ROW, dwSizeValue );

		dbBindings[1].iOrdinal   = 2;
		dbBindings[1].dwPart     = DBPART_STATUS | DBPART_LENGTH | DBPART_VALUE;
		dbBindings[1].dwMemOwner = DBMEMOWNER_CLIENTOWNED;
		dbBindings[1].cbMaxLen   = MAX_PATH;
		dbBindings[1].dwFlags    = 0;
		dbBindings[1].eParamIO   = DBPARAMIO_NOTPARAM;
		dbBindings[1].wType      = DBTYPE_STR;
		dbBindings[1].obStatus   = offsetof( SEARCH_ROW, dbPathStatus );
		dbBindings[1].obLength   = offsetof( SEARCH_ROW, dwPathLength );
		dbBindings[1].obValue    = offsetof( SEARCH_ROW, cPathValue );

		hr = IAccessor_CreateAccessor( pAccessor, DBACCESSOR_ROWDATA, 2, (DBBINDING *)&dbBindings, 0, &hAccessor, NULL );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: IAccessor_CreateAccessor Failed", hr );
		
		while( TRUE )
		{
			memset( &rowSearchResults, 0, sizeof(SEARCH_ROW) );

			hr = IRowset_GetNextRows( pRowset, DB_NULL_HCHAPTER, 0, 1, &dbCount, (HROW **)&pRows );
			if( FAILED( hr ) )
				BREAK_WITH_ERROR( "[SEARCH] wds3_search: IRowset_GetNextRows Failed", hr );

			if( !dbCount )
				BREAK_WITH_ERROR( "[SEARCH] wds3_search: No more rows to get.", ERROR_SUCCESS );

			hr = IRowset_GetData( pRowset, hRow[0], hAccessor, &rowSearchResults );
			if( FAILED( hr ) )
				BREAK_WITH_ERROR( "[SEARCH] wds3_search: IRowset_GetData Failed", hr );

			if( rowSearchResults.dwSizeValue > 0 && _memicmp( "file:", rowSearchResults.cPathValue, strlen("file:") ) == 0 )
			{
				size_t i           = 0;
				char * cpFileName  = "";
				char * cpFile      = "";
				char * cpDirectory = (char *)( rowSearchResults.cPathValue + strlen("file:") );

				for( i=0 ; i<strlen(cpDirectory) ; i++ )
				{
					if( cpDirectory[i] == '/' )
						cpDirectory[i] = '\\';
				}

				cpFile = strrchr( cpDirectory, '\\' );
				if( cpFile )
				{
					*cpFile    = '\x00';
					cpFileName = cpFile + 1;
				}
				else
				{
					cpDirectory = "";
					cpFileName  = cpDirectory;
				}

				search_add_result( pResponse, cpDirectory, cpFileName, rowSearchResults.dwSizeValue );

				dprintf( "[SEARCH] wds3_search. Found: %s\\%s", cpDirectory, cpFileName );
			}
			else if( _memicmp( "iehistory:", rowSearchResults.cPathValue, 10 ) == 0 )
			{
				// "iehistory://{*}/"
				char * cpHistory = strstr( rowSearchResults.cPathValue, "}" );
				if( cpHistory )
					search_add_result( pResponse, "", cpHistory+2, 0 );
			}
			else if( _memicmp( "mapi:", rowSearchResults.cPathValue, 5 ) == 0 )
			{
				// "mapi://{*}/"
				char * cpHistory = strstr( rowSearchResults.cPathValue, "}" );
				if( cpHistory )
					search_add_result( pResponse, "", cpHistory+2, 0 );
			}

			hr = IRowset_ReleaseRows( pRowset, dbCount, pRows, NULL, NULL, NULL );
			if( FAILED( hr ) )
				BREAK_WITH_ERROR( "[SEARCH] wds3_search: IRowset_ReleaseRows Failed", hr );
		}

	} while( 0 );

	dprintf( "[SEARCH] wds3_search: Releasing COM objects..." );

	if( pAccessor )
	{
		IAccessor_ReleaseAccessor( pAccessor, hAccessor, NULL );

		IAccessor_Release( pAccessor );
	}

	if( pRowset )
		IRowset_Release( pRowset );

	if( pCommandText )
		ICommandText_Release( pCommandText );

	if( pCreateCommand )
		IDBCreateCommand_Release( pCreateCommand );

	if( pCommand )
		ICommand_Release( pCommand );

	if( pOpenRowset )
		IOpenRowset_Release( pOpenRowset );

	if( pSession )
		IDBCreateSession_Release( pSession );
	
	if( pQueryHelper )
		ISearchQueryHelper_Release( pQueryHelper );

	if( pIDBInitialize )
		IDBInitialize_Release( pIDBInitialize );

	if( pDataInitialize )
		IDataInitialize_Release( pDataInitialize );

	if( wpQuery )
		free( wpQuery );

	dprintf( "[SEARCH] wds3_search: Finished." );

	return dwResult;
}

/*
 * Search a directory for files.
 */
DWORD search_directory( char * cpDirectory, SEARCH_OPTIONS * pOptions, Packet * pResponse )
{
	DWORD dwResult           = ERROR_SUCCESS;
	HANDLE hFile             = NULL;
	char * cpFirstFile       = NULL;
	WIN32_FIND_DATA FindData = {0};
	size_t dwLength          = 0;

	do
	{
		dwLength    = strlen( cpDirectory ) + strlen( pOptions->cpFileGlob ) + 32;
		cpFirstFile = (char *)malloc( dwLength );
		if( !cpFirstFile )
			BREAK_WITH_ERROR( "[SEARCH] search_directory: !cpFirstFile", ERROR_OUTOFMEMORY );

		sprintf_s( cpFirstFile, dwLength, "%s\\%s", cpDirectory, pOptions->cpFileGlob );

		hFile = FindFirstFile( cpFirstFile, &FindData );
		if( hFile == INVALID_HANDLE_VALUE )
		{
			// if not files in this directory matched our pattern, finish with success
			if( GetLastError() == ERROR_FILE_NOT_FOUND )
				break;
			// otherwise we fail with an error
			BREAK_ON_ERROR( "[SEARCH] search_directory: FindFirstFile Failed." );
		}

		do
		{
			do
			{
				if( strcmp( FindData.cFileName, "." ) == 0 )
					break;

				if( strcmp( FindData.cFileName, ".." ) == 0 )
					break;
				
				if( FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
					break;

				search_add_result( pResponse, cpDirectory, FindData.cFileName, FindData.nFileSizeLow );

				dprintf( "[SEARCH] search_directory. Found: %s\\%s", cpDirectory, FindData.cFileName  );

			} while( 0 );

		} while( FindNextFile( hFile, &FindData ) != 0  );

	} while( 0 );

	if( cpFirstFile )
		free( cpFirstFile );

	if( hFile )
		FindClose( hFile );

	return dwResult;
}

/*
 * Perform a file search using Windows Desktop Search if available and falling back
 * to a FindFirstFile/FindNextFile search technique if not.
 */
DWORD search( WDS3_INTERFACE * pWDS3Interface, char * cpCurrentDirectory, SEARCH_OPTIONS * pOptions, Packet * pResponse )
{
	DWORD dwResult           = ERROR_SUCCESS;
	HANDLE hFile             = NULL;
	char * cpFirstFile       = NULL;
	BOOL bAllreadySearched   = FALSE;
	WIN32_FIND_DATA FindData = {0};
	size_t dwLength          = 0;

	do
	{
		if( !pResponse || !pOptions )
			BREAK_WITH_ERROR( "[SEARCH] search: !pResponse || !pOptions", ERROR_INVALID_PARAMETER );

		if( !cpCurrentDirectory )
			cpCurrentDirectory = pOptions->cpRootDirectory;

		if( wds3_indexed( pWDS3Interface, cpCurrentDirectory ) )
		{
			dwResult = wds3_search( pWDS3Interface , L"file", cpCurrentDirectory, pOptions, pResponse );
		}
		else
		{
			dwLength    = strlen( cpCurrentDirectory ) + 32;
			cpFirstFile = (char *)malloc( dwLength );
			if( !cpFirstFile )
				BREAK_WITH_ERROR( "[SEARCH] search: !cpFirstFile", ERROR_OUTOFMEMORY );

			sprintf_s( cpFirstFile, dwLength, "%s\\*.*", cpCurrentDirectory );

			hFile = FindFirstFile( cpFirstFile, &FindData );
			if( hFile == INVALID_HANDLE_VALUE )
				BREAK_ON_ERROR( "[SEARCH] search: FindFirstFile Failed." );

			do
			{
				if( FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
				{
					do
					{
						char * cpNextDirectory = NULL;
						
						if( !pOptions->bResursive )
							break;

						if( strcmp( FindData.cFileName, "." ) == 0 )
							break;

						if( strcmp( FindData.cFileName, ".." ) == 0 )
							break;

						dwLength        = strlen( cpCurrentDirectory ) + strlen( FindData.cFileName ) + 32;
						cpNextDirectory = (char *)malloc( dwLength );
						if( !cpNextDirectory )
							break;

						sprintf_s( cpNextDirectory, dwLength, "%s\\%s", cpCurrentDirectory, FindData.cFileName );

						search( pWDS3Interface, cpNextDirectory, pOptions, pResponse );

						free( cpNextDirectory );

					} while( 0 );
				}
				else
				{
					if( !bAllreadySearched )
					{
						// we call search_dir_via_api() to avail of glob searching via a second 
						// FindFirstFile() loop (which is available on NT4 and up, unlike PathMatchSpec())
						search_directory( cpCurrentDirectory, pOptions, pResponse );
	
						bAllreadySearched = TRUE;
					}
				}

			} while( FindNextFile( hFile, &FindData ) != 0  );
		}

	} while( 0 );

	if( cpFirstFile )
		free( cpFirstFile );

	if( hFile )
		FindClose( hFile );

	return dwResult;
}

/*
 * Request routine for performing a file search.
 */
DWORD request_fs_search( Remote * pRemote, Packet * pPacket )
{
	DWORD dwResult               = ERROR_SUCCESS;
	Packet * pResponse           = NULL;
	SEARCH_OPTIONS * pOptions    = NULL;
	WDS3_INTERFACE WDS3Interface = {0};

	dprintf( "[SEARCH] request_fs_search. Starting." );

	do
	{
		pResponse = packet_create_response( pPacket );
		if( !pResponse )
			BREAK_WITH_ERROR( "[SEARCH] request_fs_search: pResponse == NULL", ERROR_INVALID_HANDLE );

		pOptions = (SEARCH_OPTIONS *)malloc( sizeof(SEARCH_OPTIONS) );
		if( !pOptions )
			BREAK_WITH_ERROR( "[SEARCH] search_via_api: !pOptions", ERROR_OUTOFMEMORY );

		pOptions->cpRootDirectory = packet_get_tlv_value_string( pPacket, TLV_TYPE_SEARCH_ROOT );
		if( !pOptions->cpRootDirectory )
			pOptions->cpRootDirectory = "";

		if( strlen( pOptions->cpRootDirectory ) == 0 )
			pOptions->cpRootDirectory = NULL;

		pOptions->bResursive = packet_get_tlv_value_bool( pPacket, TLV_TYPE_SEARCH_RECURSE );

		pOptions->cpFileGlob = packet_get_tlv_value_string( pPacket, TLV_TYPE_SEARCH_GLOB );
		if( !pOptions->cpFileGlob )
			pOptions->cpFileGlob = "*.*";

		wds3_startup( &WDS3Interface );

		if( !pOptions->cpRootDirectory )
		{
			DWORD dwLogicalDrives = 0;
			char cIndex           = 0;

			dwLogicalDrives = GetLogicalDrives();

			for( cIndex='a' ; cIndex<='z' ; cIndex++ )
			{
				if( dwLogicalDrives & ( 1 << (cIndex-'a')) )
				{
					DWORD dwType   = 0;
					char cDrive[4] = {0};

					sprintf_s( cDrive, 4, "%c:\\\x00", cIndex );
				
					dwType = GetDriveType( cDrive );

					if( dwType == DRIVE_FIXED || dwType == DRIVE_REMOTE )
					{
						sprintf_s( cDrive, 4, "%c:\x00", cIndex );

						pOptions->cpRootDirectory = (char *)&cDrive;

						dprintf( "[SEARCH] request_fs_search. Searching drive %s (type=%d)...", pOptions->cpRootDirectory, dwType );

						search( &WDS3Interface, NULL, pOptions, pResponse );
					}

				}
			}

			pOptions->cpRootDirectory = "";

			wds3_search( &WDS3Interface, L"iehistory", NULL, pOptions, pResponse );
			wds3_search( &WDS3Interface, L"mapi", NULL, pOptions, pResponse );
		}
		else
		{
			if( strcmp( pOptions->cpRootDirectory, "iehistory" ) == 0 )
			{
				pOptions->cpRootDirectory = "";
				wds3_search( &WDS3Interface, L"iehistory", NULL, pOptions, pResponse );
			}
			else if( strcmp( pOptions->cpRootDirectory, "mapi" ) == 0 )
			{
				pOptions->cpRootDirectory = "";
				wds3_search( &WDS3Interface, L"mapi", NULL, pOptions, pResponse );
			}
			else
			{
				dwResult = search( &WDS3Interface, NULL, pOptions, pResponse );
			}
		}


	} while( 0 );

	if( pResponse )
	{
		packet_add_tlv_uint( pResponse, TLV_TYPE_RESULT, dwResult );

		dwResult = packet_transmit( pRemote, pResponse, NULL );
	}

	wds3_shutdown( &WDS3Interface );

	if( pOptions )
		free( pOptions );

	dprintf( "[SEARCH] request_fs_search: Finished. dwResult=0x%08X", dwResult );

	return dwResult;
}