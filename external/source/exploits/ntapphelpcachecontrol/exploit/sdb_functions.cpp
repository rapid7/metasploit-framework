#include "stdafx.h"
#include "sdb.h"

BaseFlushAppcompatCache BaseFlushAppcompatCachePtr = NULL;
SdbBeginWriteListTag SdbBeginWriteListTagPtr = NULL;
SdbCloseDatabase SdbCloseDatabasePtr = NULL;
SdbCloseDatabaseWrite SdbCloseDatabaseWritePtr = NULL;
SdbCommitIndexes SdbCommitIndexesPtr = NULL;
SdbCreateDatabase SdbCreateDatabasePtr = NULL;
SdbDeclareIndex SdbDeclareIndexPtr = NULL;
SdbEndWriteListTag SdbEndWriteListTagPtr = NULL;
SdbFindFirstDWORDIndexedTag SdbFindFirstDWORDIndexedTagPtr = NULL;
SdbFindFirstTag SdbFindFirstTagPtr = NULL;
SdbFindNextTag SdbFindNextTagPtr = NULL;
SdbFormatAttribute SdbFormatAttributePtr = NULL;
SdbFreeFileAttributes SdbFreeFileAttributesPtr = NULL;
SdbGetAppPatchDir SdbGetAppPatchDirPtr = NULL;
SdbGetBinaryTagData SdbGetBinaryTagDataPtr = NULL;
SdbGetFileAttributes SdbGetFileAttributesPtr = NULL;
SdbGetFirstChild SdbGetFirstChildPtr = NULL;
SdbGetIndex SdbGetIndexPtr = NULL;
SdbGetMatchingExe SdbGetMatchingExePtr = NULL;
SdbGetNextChild SdbGetNextChildPtr = NULL;
SdbGetStringTagPtr SdbGetStringTagPtrPtr = NULL;
SdbGetTagFromTagID SdbGetTagFromTagIDPtr = NULL;
SdbInitDatabase SdbInitDatabasePtr = NULL;
SdbIsStandardDatabase SdbIsStandardDatabasePtr = NULL;
SdbMakeIndexKeyFromString SdbMakeIndexKeyFromStringPtr = NULL;
SdbOpenApphelpDetailsDatabase SdbOpenApphelpDetailsDatabasePtr = NULL;
SdbOpenApphelpResourceFile SdbOpenApphelpResourceFilePtr = NULL;
SdbOpenDatabase SdbOpenDatabasePtr = NULL;
SdbQueryDataExTagID SdbQueryDataExTagIDPtr = NULL;
SdbReadApphelpDetailsData SdbReadApphelpDetailsDataPtr = NULL;
SdbReadBinaryTag SdbReadBinaryTagPtr = NULL;
SdbReadDWORDTag SdbReadDWORDTagPtr = NULL;
SdbReadWORDTag SdbReadWORDTagPtr = NULL;
SdbReadQWORDTag SdbReadQWORDTagPtr = NULL;
SdbReadStringTag SdbReadStringTagPtr = NULL;
SdbRegisterDatabaseEx SdbRegisterDatabaseExPtr = NULL;
SdbReleaseDatabase SdbReleaseDatabasePtr = NULL;
SdbReleaseMatchingExe SdbReleaseMatchingExePtr = NULL;
SdbStartIndexing SdbStartIndexingPtr = NULL;
SdbStopIndexing SdbStopIndexingPtr = NULL;
SdbTagRefToTagID SdbTagRefToTagIDPtr = NULL;
SdbTagToString SdbTagToStringPtr = NULL;
SdbUnregisterDatabase SdbUnregisterDatabasePtr = NULL;
SdbWriteBinaryTag SdbWriteBinaryTagPtr = NULL;
SdbWriteBinaryTagFromFile SdbWriteBinaryTagFromFilePtr = NULL;
SdbWriteDWORDTag SdbWriteDWORDTagPtr = NULL;
SdbWriteNULLTag SdbWriteNULLTagPtr = NULL;
SdbWriteQWORDTag SdbWriteQWORDTagPtr = NULL;
SdbWriteStringTag SdbWriteStringTagPtr = NULL;
SdbWriteWORDTag SdbWriteWORDTagPtr = NULL;
ShimFlushCache ShimFlushCachePtr = NULL;
SdbGetTagDataSize SdbGetTagDataSizePtr = NULL;
SdbGetShowDebugInfoOption SdbGetShowDebugInfoOptionPtr = NULL;

BOOL resolveSdbFunctions()
{
	HMODULE apphelpdll;
	HMODULE kernel32dll;
	apphelpdll = LoadLibraryA("apphelp.dll");
	if (!apphelpdll)
	{
		fprintf(stderr, "Failed to load apphelp\n");
		return FALSE;
	}

	kernel32dll = LoadLibraryA("kernel32.dll");
	if (!kernel32dll)
	{
		fprintf(stderr, "Failed to load kernel32\n");
		return FALSE;
	}


	BaseFlushAppcompatCachePtr = (BaseFlushAppcompatCache)GetProcAddress(kernel32dll, "BaseFlushAppcompatCache");
	SdbBeginWriteListTagPtr = (SdbBeginWriteListTag)GetProcAddress(apphelpdll, "SdbBeginWriteListTag");
	SdbCloseDatabasePtr = (SdbCloseDatabase)GetProcAddress(apphelpdll, "SdbCloseDatabase");
	SdbCloseDatabaseWritePtr = (SdbCloseDatabaseWrite)GetProcAddress(apphelpdll, "SdbCloseDatabaseWrite");
	SdbCommitIndexesPtr = (SdbCommitIndexes)GetProcAddress(apphelpdll, "SdbCommitIndexes");
	SdbCreateDatabasePtr = (SdbCreateDatabase)GetProcAddress(apphelpdll, "SdbCreateDatabase");
	SdbDeclareIndexPtr = (SdbDeclareIndex)GetProcAddress(apphelpdll, "SdbDeclareIndex");
	SdbEndWriteListTagPtr = (SdbEndWriteListTag)GetProcAddress(apphelpdll, "SdbEndWriteListTag");
	SdbFindFirstDWORDIndexedTagPtr = (SdbFindFirstDWORDIndexedTag)GetProcAddress(apphelpdll, "SdbFindFirstDWORDIndexedTag");
	SdbFindFirstTagPtr = (SdbFindFirstTag)GetProcAddress(apphelpdll, "SdbFindFirstTag");
	SdbFindNextTagPtr = (SdbFindNextTag)GetProcAddress(apphelpdll, "SdbFindNextTag");
	SdbFormatAttributePtr = (SdbFormatAttribute)GetProcAddress(apphelpdll, "SdbFormatAttribute");
	SdbFreeFileAttributesPtr = (SdbFreeFileAttributes)GetProcAddress(apphelpdll, "SdbFreeFileAttributes");
	SdbGetAppPatchDirPtr = (SdbGetAppPatchDir)GetProcAddress(apphelpdll, "SdbGetAppPatchDir");
	SdbGetBinaryTagDataPtr = (SdbGetBinaryTagData)GetProcAddress(apphelpdll, "SdbGetBinaryTagData");
	SdbGetFileAttributesPtr = (SdbGetFileAttributes)GetProcAddress(apphelpdll, "SdbGetFileAttributes");
	SdbGetFirstChildPtr = (SdbGetFirstChild)GetProcAddress(apphelpdll, "SdbGetFirstChild");
	SdbGetIndexPtr = (SdbGetIndex)GetProcAddress(apphelpdll, "SdbGetIndex");
	SdbGetMatchingExePtr = (SdbGetMatchingExe)GetProcAddress(apphelpdll, "SdbGetMatchingExe");
	SdbGetNextChildPtr = (SdbGetNextChild)GetProcAddress(apphelpdll, "SdbGetNextChild");
	SdbGetStringTagPtrPtr = (SdbGetStringTagPtr)GetProcAddress(apphelpdll, "SdbGetStringTagPtr");
	SdbGetTagFromTagIDPtr = (SdbGetTagFromTagID)GetProcAddress(apphelpdll, "SdbGetTagFromTagID");
	SdbInitDatabasePtr = (SdbInitDatabase)GetProcAddress(apphelpdll, "SdbInitDatabase");
	SdbIsStandardDatabasePtr = (SdbIsStandardDatabase)GetProcAddress(apphelpdll, "SdbIsStandardDatabase");
	SdbMakeIndexKeyFromStringPtr = (SdbMakeIndexKeyFromString)GetProcAddress(apphelpdll, "SdbMakeIndexKeyFromString");
	SdbOpenApphelpDetailsDatabasePtr = (SdbOpenApphelpDetailsDatabase)GetProcAddress(apphelpdll, "SdbOpenApphelpDetailsDatabase");
	SdbOpenApphelpResourceFilePtr = (SdbOpenApphelpResourceFile)GetProcAddress(apphelpdll, "SdbOpenApphelpResourceFile");
	SdbOpenDatabasePtr = (SdbOpenDatabase)GetProcAddress(apphelpdll, "SdbOpenDatabase");
	SdbQueryDataExTagIDPtr = (SdbQueryDataExTagID)GetProcAddress(apphelpdll, "SdbQueryDataExTagID");
	SdbReadApphelpDetailsDataPtr = (SdbReadApphelpDetailsData)GetProcAddress(apphelpdll, "SdbReadApphelpDetailsData");
	SdbReadBinaryTagPtr = (SdbReadBinaryTag)GetProcAddress(apphelpdll, "SdbReadBinaryTag");
	SdbReadDWORDTagPtr = (SdbReadDWORDTag)GetProcAddress(apphelpdll, "SdbReadDWORDTag");
	SdbReadWORDTagPtr = (SdbReadWORDTag)GetProcAddress(apphelpdll, "SdbReadWORDTag");
	SdbReadQWORDTagPtr = (SdbReadQWORDTag)GetProcAddress(apphelpdll, "SdbReadQWORDTag");
	SdbReadStringTagPtr = (SdbReadStringTag)GetProcAddress(apphelpdll, "SdbReadStringTag");
	SdbRegisterDatabaseExPtr = (SdbRegisterDatabaseEx)GetProcAddress(apphelpdll, "SdbRegisterDatabaseEx");
	SdbReleaseDatabasePtr = (SdbReleaseDatabase)GetProcAddress(apphelpdll, "SdbReleaseDatabase");
	SdbReleaseMatchingExePtr = (SdbReleaseMatchingExe)GetProcAddress(apphelpdll, "SdbReleaseMatchingExe");
	SdbStartIndexingPtr = (SdbStartIndexing)GetProcAddress(apphelpdll, "SdbStartIndexing");
	SdbStopIndexingPtr = (SdbStopIndexing)GetProcAddress(apphelpdll, "SdbStopIndexing");
	SdbTagRefToTagIDPtr = (SdbTagRefToTagID)GetProcAddress(apphelpdll, "SdbTagRefToTagID");
	SdbTagToStringPtr = (SdbTagToString)GetProcAddress(apphelpdll, "SdbTagToString");
	SdbUnregisterDatabasePtr = (SdbUnregisterDatabase)GetProcAddress(apphelpdll, "SdbUnregisterDatabase");
	SdbWriteBinaryTagPtr = (SdbWriteBinaryTag)GetProcAddress(apphelpdll, "SdbWriteBinaryTag");
	SdbWriteBinaryTagFromFilePtr = (SdbWriteBinaryTagFromFile)GetProcAddress(apphelpdll, "SdbWriteBinaryTagFromFile");
	SdbWriteDWORDTagPtr = (SdbWriteDWORDTag)GetProcAddress(apphelpdll, "SdbWriteDWORDTag");
	SdbWriteNULLTagPtr = (SdbWriteNULLTag)GetProcAddress(apphelpdll, "SdbWriteNULLTag");
	SdbWriteQWORDTagPtr = (SdbWriteQWORDTag)GetProcAddress(apphelpdll, "SdbWriteQWORDTag");
	SdbWriteStringTagPtr = (SdbWriteStringTag)GetProcAddress(apphelpdll, "SdbWriteStringTag");
	SdbWriteWORDTagPtr = (SdbWriteWORDTag)GetProcAddress(apphelpdll, "SdbWriteWORDTag");
	ShimFlushCachePtr = (ShimFlushCache)GetProcAddress(apphelpdll, "ShimFlushCache");
	SdbGetTagDataSizePtr = (SdbGetTagDataSize)GetProcAddress(apphelpdll, "SdbGetTagDataSize");
	SdbGetShowDebugInfoOptionPtr = (SdbGetShowDebugInfoOption)GetProcAddress(apphelpdll, "SdbGetShowDebugInfoOption");

	if (!BaseFlushAppcompatCachePtr
		|| !SdbBeginWriteListTagPtr
		|| !SdbCloseDatabasePtr
		|| !SdbCloseDatabaseWritePtr
		|| !SdbCommitIndexesPtr
		|| !SdbCreateDatabasePtr
		|| !SdbDeclareIndexPtr
		|| !SdbEndWriteListTagPtr
		|| !SdbFindFirstDWORDIndexedTagPtr
		|| !SdbFindFirstTagPtr
		|| !SdbFindNextTagPtr
		|| !SdbFormatAttributePtr
		|| !SdbFreeFileAttributesPtr
		|| !SdbGetAppPatchDirPtr
		|| !SdbGetBinaryTagDataPtr
		|| !SdbGetFileAttributesPtr
		|| !SdbGetFirstChildPtr
		|| !SdbGetIndexPtr
		|| !SdbGetMatchingExePtr
		|| !SdbGetNextChildPtr
		|| !SdbGetStringTagPtrPtr
		|| !SdbGetTagFromTagIDPtr
		|| !SdbInitDatabasePtr
		|| !SdbIsStandardDatabasePtr
		|| !SdbMakeIndexKeyFromStringPtr
		|| !SdbOpenApphelpDetailsDatabasePtr
		|| !SdbOpenApphelpResourceFilePtr
		|| !SdbOpenDatabasePtr
		|| !SdbQueryDataExTagIDPtr
		|| !SdbReadApphelpDetailsDataPtr
		|| !SdbReadBinaryTagPtr
		|| !SdbReadDWORDTagPtr
		|| !SdbReadQWORDTagPtr
		|| !SdbReadStringTagPtr
		|| !SdbRegisterDatabaseExPtr
		|| !SdbReleaseDatabasePtr
		|| !SdbReleaseMatchingExePtr
		|| !SdbStartIndexingPtr
		|| !SdbStopIndexingPtr
		|| !SdbTagRefToTagIDPtr
		|| !SdbTagToStringPtr
		|| !SdbUnregisterDatabasePtr
		|| !SdbWriteBinaryTagPtr
		|| !SdbWriteBinaryTagFromFilePtr
		|| !SdbWriteDWORDTagPtr
		|| !SdbWriteNULLTagPtr
		|| !SdbWriteQWORDTagPtr
		|| !SdbWriteStringTagPtr
		|| !SdbWriteWORDTagPtr
		|| !ShimFlushCachePtr
		|| !SdbReadWORDTagPtr
		|| !SdbGetTagDataSizePtr
		|| !SdbGetShowDebugInfoOptionPtr)
	{
		return FALSE;
	}
	return TRUE;

}

