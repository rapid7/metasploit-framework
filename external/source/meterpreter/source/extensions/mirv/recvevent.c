#include "mirv.h"


#pragma comment(lib, "advapi32.lib")

#define PROVIDER_NAME "System"
//#define RESOURCE_DLL  "C:\\Windows\\System32\\MsAuditE.dl"
//#define KEYBOARD_EVENT     0
#define NOTIFICATION_EVENT 0
//#define DEFAULT_HOST "192.168.183.128"
//#define DEFAULT_PORT "4455"

HANDLE GetMessageResources(char *resource_dll);
DWORD SeekToLastRecord(HANDLE hEventLog);

DWORD GetLastRecordNumber(HANDLE hEventLog, DWORD* pdwMarker);


DWORD ReadRecord(HANDLE hEventLog, PBYTE *pBuffer, DWORD dwRecordNumber, DWORD dwFlags);
//DWORD DumpNewRecords(HANDLE hEventLog, OUT char *message);
DWORD DumpNewRecords(HANDLE hEventLog, char **message, struct event_reader_struct *er);
DWORD GetEventTypeName(DWORD EventType);
LPSTR GetMessageString(DWORD MessageId, DWORD argc, char *argv, struct event_reader_struct *er);
//DWORD ApplyParameterStringsToMessage(CONST LPCSTR pMessage, LPSTR pFinalMessage);
DWORD ApplyParameterStringsToMessage(CONST LPCSTR pMessage, LPSTR pFinalMessage,struct event_reader_struct *er);
//BOOL IsKeyEvent(HANDLE hStdIn);
//char IsKeyEvent(HANDLE hStdIn);
//WSADATA wsaData;
//SOCKET ConnectSocket = INVALID_SOCKET;

char * pEventTypeNames[] = {"Error", "Warning", "Informational", "Audit Success", "Audit Failure"};
//HANDLE g_hResources = NULL;

//HANDLE resources[MAX_RESOURCES]; // FIXME: should be times 3
//int resourceHandleCount;

/* This function loads the DLL resources which help expand event log data into readable text */
int loadResources(messageProvider **mpArray,int count, struct event_reader_struct *er){
	char *candidateResources[MAX_RESOURCES];
	char *finalResources[MAX_RESOURCES];	
	HANDLE h;
	int candidateCount,finalCount,handleCount=0;
	int i,j=0;//,k;
	BOOL isUnique;

	for (i=0;i<count;i++){
		messageProvider *mp=mpArray[i];
		if (mp->CategoryMessageFile)
			candidateResources[j++]=mp->CategoryMessageFile;
		if (mp->EventMessageFile)
			candidateResources[j++]=mp->EventMessageFile;
		if (mp->ParameterMessageFile)
			candidateResources[j++]=mp->ParameterMessageFile;
	}
	candidateCount=i;
	finalCount=0;
	finalResources[finalCount++]=candidateResources[0];

	//_tprintf(_T("Got %i total resources\n"), candidateCount);
	for (i=1;i<candidateCount;++i){
		isUnique=TRUE;
		for(j=0;j<finalCount;j++){
			if (strcmp(candidateResources[i],finalResources[j])==0){
				isUnique=FALSE;
				break;
			}
		}
		if(isUnique)
			finalResources[finalCount++]=candidateResources[i];
	}
	//_tprintf(_T("Got %i  UNIQUE resources\n"), finalCount);
	for (i=0;i<finalCount;++i){
		h=GetMessageResources(finalResources[i]);
		if(h)
			er->resources[handleCount++]=h;
	}
	//_tprintf(_T("Loaded %i resource handles\n"), handleCount);
	return handleCount;

}
/* 
This function sets up the log reading:
* loads resources
* opens the event log
*/
int open_log(char *provider, // Which event log to listen to
struct event_reader_struct *er	// OUT variable for event_reader
	)
{
	//struct event_reader_struct er;

	//HANDLE hEventLog = NULL;
	//HANDLE aWaitHandles[2];
	DWORD status = ERROR_SUCCESS;
	DWORD dwWaitReason = 0;
	DWORD dwLastRecordNumber = 0;
	messageProvider **mpArray;
	int mpArrayCount;
	er->resourceHandleCount=0;
	// Load message resources
	mpArray=(messageProvider**) malloc(MAX_RESOURCES * sizeof(messageProvider));
	ZeroMemory(mpArray,MAX_RESOURCES * sizeof(messageProvider));
	mpArrayCount = getProviders(mpArray);
	er->resourceHandleCount=loadResources(mpArray,mpArrayCount,er);
	free(mpArray);




	// Open the log file. The source name (provider) must exist as 
	// a subkey of Application.
	er->eventLoghandles[NOTIFICATION_EVENT] = OpenEventLogA(NULL, provider);
	if (NULL == er->eventLoghandles[NOTIFICATION_EVENT])
	{
		printf("OpenEventLog failed with 0x%x.\n", GetLastError());
		goto cleanup;
	}

	// Seek to the last record in the event log and read it in order
	// to position the cursor for reading any new records when the
	// service notifies you that new records have been written to the 
	// log file.
	status = SeekToLastRecord(er->eventLoghandles[NOTIFICATION_EVENT]);
	if (ERROR_SUCCESS != status)
	{
		printf("SeekToLastRecord failed with %lu.\n", status);
		goto cleanup;
	}
	er->aWaitHandles[NOTIFICATION_EVENT]=NULL;
	er->aWaitHandles[NOTIFICATION_EVENT] = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == er->aWaitHandles[NOTIFICATION_EVENT])
	{
		printf("CreateEvent failed with %lu.\n", GetLastError());
		goto cleanup;
	}

	// Request notification when events are written to the log.
	if (!NotifyChangeEventLog(er->eventLoghandles[NOTIFICATION_EVENT], er->aWaitHandles[NOTIFICATION_EVENT]))
	{
		printf("NotifyChangeEventLog failed with %lu. \n", GetLastError());
		goto cleanup;
	}
	// set return value
	//er_out=&er;
	return ERROR_SUCCESS;


cleanup:

	if (er->eventLoghandles[NOTIFICATION_EVENT])
		CloseEventLog(er->eventLoghandles[NOTIFICATION_EVENT]);
	if (er->aWaitHandles[NOTIFICATION_EVENT]){
		CloseHandle(er->aWaitHandles[NOTIFICATION_EVENT]);
	}
	return  GetLastError();


}
int get_event(event_reader *er,  char **message){
	DWORD dwWaitReason = 0;
	DWORD dwLastRecordNumber = 0;
	DWORD status = ERROR_SUCCESS;
	//char *out;
	
		dwWaitReason = WaitForMultipleObjects(1, er->aWaitHandles, FALSE, MAX_WAIT_TIME);		
		if (NOTIFICATION_EVENT == dwWaitReason - WAIT_OBJECT_0) // Notification results
		{
			if (ERROR_SUCCESS != (status = DumpNewRecords(er->eventLoghandles[NOTIFICATION_EVENT],message,er)))
			{
				printf("DumpNewRecords failed.\n");
				return -1;
			}

			//wprintf("\nWaiting for notification of new events (press any key to quit)...\n");
			ResetEvent(er->aWaitHandles[NOTIFICATION_EVENT]);
			;
		}
		else
		{
			if (WAIT_FAILED == dwWaitReason)
			{
				printf("WaitForSingleObject failed with %lu\n", GetLastError());
				return -1;
			}
			
		}
	if(message)
		return ERROR_SUCCESS;
	else return 1;
}

// Get the last record number in the log file and read it.
// This positions the cursor, so that we can begin reading 
// new records when the service notifies us that new records were 
// written to the log file.
DWORD SeekToLastRecord(HANDLE hEventLog)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwLastRecordNumber = 0;
	PBYTE pRecord = NULL;  

	status = GetLastRecordNumber(hEventLog, &dwLastRecordNumber);
	if (ERROR_SUCCESS != status)
	{
		//wprintf("GetLastRecordNumber failed.\n");
		goto cleanup;
	}

	status = ReadRecord(hEventLog, &pRecord, dwLastRecordNumber, EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ);
	if (ERROR_SUCCESS != status)
	{
		//wprintf("ReadRecord failed seeking to record %lu.\n", dwLastRecordNumber);
		goto cleanup;
	}

cleanup:

	if (pRecord)
		free(pRecord);

	return status;
}


// Get the record number to the last record in the log file.
DWORD GetLastRecordNumber(HANDLE hEventLog, DWORD* pdwRecordNumber)
{
	DWORD status = ERROR_SUCCESS;
	DWORD OldestRecordNumber = 0;
	DWORD NumberOfRecords = 0;

	if (!GetOldestEventLogRecord(hEventLog, &OldestRecordNumber))
	{
		//wprintf("GetOldestEventLogRecord failed with %lu.\n", status = GetLastError());
		goto cleanup;
	}

	if (!GetNumberOfEventLogRecords(hEventLog, &NumberOfRecords))
	{
		//wprintf("GetOldestEventLogRecord failed with %lu.\n", status = GetLastError());
		goto cleanup;
	}

	*pdwRecordNumber = OldestRecordNumber + NumberOfRecords - 1;

cleanup:

	return status;
}


// Get the provider DLL that contains the string resources for the
// category strings, event message strings, and parameter insert strings.
// For this example, the path to the DLL is hardcoded but typically,
// you would read the CategoryMessageFile, EventMessageFile, and 
// ParameterMessageFile registry values under the source's registry key located 
// under \SYSTEM\CurrentControlSet\Services\Eventlog\Application in
// the HKLM registry hive. In this example, all resources are included in
// the same resource-only DLL.
//HANDLE GetMessageResources(void){
//	return GetMessageResources(RESOURCE_DLL);	
//}
HANDLE GetMessageResources(char *resource_dll)
{
	HANDLE hResources = NULL;
	char expandedString[2048];

	ExpandEnvironmentStringsA(resource_dll,expandedString,sizeof(expandedString));
	////wprintf("I expanded %s to %s\n", resource_dll, expandedString);
	hResources = LoadLibraryExA(expandedString, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
	if (NULL == hResources)
	{
		//wprintf("LoadLibraryEx of %s failed with %lu.\n", expandedString, GetLastError());
	}else{
		////wprintf("LoadLibraryEx of %s succeeded with %lu.\n", expandedString, GetLastError());
	}

	return hResources;
}



// Read a single record from the event log.
DWORD ReadRecord(HANDLE hEventLog, PBYTE *pBuffer, DWORD dwRecordNumber, DWORD dwFlags)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwBytesToRead = sizeof(EVENTLOGRECORD);
	DWORD dwBytesRead = 0;
	DWORD dwMinimumBytesToRead = 0;
	PBYTE pTemp = NULL;
	//char secret[8192];
	// The initial size of the buffer is not big enough to read a record, but ReadEventLog
	// requires a valid pointer. The ReadEventLog function will fail and return the required 
	// buffer size; reallocate the buffer to the required size.
	pTemp= (PBYTE)malloc(sizeof(EVENTLOGRECORD));

	// Get the required buffer size, reallocate the buffer and then read the event record.
	if (!ReadEventLogA(hEventLog, dwFlags, dwRecordNumber, pTemp, dwBytesToRead, &dwBytesRead, &dwMinimumBytesToRead))
	{
		status = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == status)
		{
			status = ERROR_SUCCESS;

			//pTemp = (PBYTE)realloc(pBuffer, dwMinimumBytesToRead);
			pTemp= (PBYTE)realloc(pTemp, dwMinimumBytesToRead);
			//ZeroMemory(pTemp,dwMinimumBytesToRead);
			if (NULL == pBuffer)
			{
				printf("Failed to reallocate memory for the record buffer (%d bytes).\n", dwMinimumBytesToRead);
				goto cleanup;
			}



			dwBytesToRead = dwMinimumBytesToRead;

			if (!ReadEventLogA(hEventLog, dwFlags, dwRecordNumber, pTemp, dwBytesToRead, &dwBytesRead, &dwMinimumBytesToRead))
			{
				printf("Second ReadEventLog failed with %lu.\n", status = GetLastError());
				goto cleanup;
			}
			*pBuffer = pTemp;
		}
		else 
		{
			if (ERROR_HANDLE_EOF != status)
			{
				printf("ReadEventLog failed with %lu.\n", status);
				goto cleanup;
			}
		}
	}

cleanup:
	return status;
}


// Write the contents of each event record that was written to the log since
// the last notification. The service signals the event object every five seconds
// if an event has been written to the log.
DWORD DumpNewRecords(HANDLE hEventLog, OUT char **message, event_reader *er)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwLastRecordNumber = 0;
	char * pMessage = NULL;
	char * pFinalMessage = NULL;
	PBYTE pRecord = NULL;
	char buffer[8192];
	char *pTemp=NULL;
	size_t  i;
	char dataBuffer[8192];
	unsigned long lastRecord=0;
	// Read the first record to prime the loop.
	status = ReadRecord(hEventLog, &pRecord, 0, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ);

	if (ERROR_SUCCESS != status && ERROR_HANDLE_EOF != status)
	{
		//wprintf("ReadRecord (priming read) failed.\n");
		goto cleanup;
	}

	// During the five second notification period, one or more records could
	// have been written to the log. Read all the records that have been 
	// written since the last notification. 
	while (ERROR_HANDLE_EOF != status)
	{
		// If the event was written by our provider, write the contents of the event.
		//if (1 == wcscmp(PROVIDER_NAME, (LPWSTR)(pRecord + sizeof(EVENTLOGRECORD))))


		//	printf("lastRecord %lu , current record %lu, eval 
		if (lastRecord>=((PEVENTLOGRECORD)pRecord)->RecordNumber)
			continue;
		//buffer=(char *)malloc(8192);
		ZeroMemory(buffer,8192);
		lastRecord=((PEVENTLOGRECORD)pRecord)->RecordNumber;
		////wprintf("record number: %lu ", ((PEVENTLOGRECORD)pRecord)->RecordNumber);
		////wprintf("status code: %d ", ((PEVENTLOGRECORD)pRecord)->EventID & 0xFFFF);
		////wprintf("event type: %s ", pEventTypeNames[GetEventTypeName(((PEVENTLOGRECORD)pRecord)->EventType)]);
		sprintf_s(buffer,8192,"record number: %lu, status code: %d, event type: %s,",
			((PEVENTLOGRECORD)pRecord)->RecordNumber,
			((PEVENTLOGRECORD)pRecord)->EventID & 0xFFFF,
			pEventTypeNames[GetEventTypeName(((PEVENTLOGRECORD)pRecord)->EventType)]
		);

		pMessage = GetMessageString(((PEVENTLOGRECORD)pRecord)->EventCategory, 0, NULL,er);

		if (pMessage)
		{
			////wprintf("event category: %s", pMessage);
			sprintf_s(buffer,8192,"%s event category: %s,",buffer, pMessage);
			LocalFree(pMessage);
			pMessage = NULL;
		}

		pMessage = GetMessageString(((PEVENTLOGRECORD)pRecord)->EventID, 
			((PEVENTLOGRECORD)pRecord)->NumStrings, (LPSTR)(pRecord + ((PEVENTLOGRECORD)pRecord)->StringOffset),er);

		if (pMessage)
		{
			status = ApplyParameterStringsToMessage(pMessage, pFinalMessage,er);

			////wprintf("event message: %s", (pFinalMessage) ? pFinalMessage : pMessage);
			sprintf_s(buffer,8192,"%s event message: %s,",buffer,(pFinalMessage) ? pFinalMessage : pMessage);

			LocalFree(pMessage);
			pMessage = NULL;

			if (pFinalMessage)
			{
				free(pFinalMessage);
				pFinalMessage = NULL;
			}
		}

		// To write the event data, you need to know the format of the data. In
		// this example, we know that the event data is a null-terminated string.
		if (((PEVENTLOGRECORD)pRecord)->DataLength > 0)
		{
			////wprintf("event data: %s\n", (LPWSTR)(pRecord + ((PEVENTLOGRECORD)pRecord)->DataOffset));
			//wcstombs_s(&i,&dataBuffer,(size_t) 8192,buffer,_TRUNCATE);
			wcstombs_s(&i,
				dataBuffer,
				8192,
				(LPWSTR)(pRecord + ((PEVENTLOGRECORD)pRecord)->DataOffset),
				_TRUNCATE);
			sprintf_s(buffer,8192,"%s event data: %s\n",buffer,dataBuffer);
		}

		////wprintf("\n");
		//_tprintf("%s\n",buffer);
		//sendStuffDownTheTubes((char *)buffer,_tcsclen(buffer)*sizeof(TCHAR));
		pTemp=(char *)malloc(strlen(buffer)*sizeof(char)+1);
		strncpy_s(pTemp,strlen(buffer)+1,buffer,_TRUNCATE);
		*message = pTemp;
		//free(buffer);


		// Read sequentially through the records.
		status = ReadRecord(hEventLog, &pRecord, 0, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ);
		if (ERROR_SUCCESS != status && ERROR_HANDLE_EOF != status)
		{
			//wprintf("ReadRecord sequential failed.\n");
			goto cleanup;
		}
	}


	if (ERROR_HANDLE_EOF == status)
	{
		status = ERROR_SUCCESS;
	}

cleanup:

	if (pRecord)
		free(pRecord);

	return status;
}


// Get an index value to the pEventTypeNames array based on 
// the event type value.
DWORD GetEventTypeName(DWORD EventType)
{
	DWORD index = 0;

	switch (EventType)
	{
	case EVENTLOG_ERROR_TYPE:
		index = 0;
		break;
	case EVENTLOG_WARNING_TYPE:
		index = 1;
		break;
	case EVENTLOG_INFORMATION_TYPE:
		index = 2;
		break;
	case EVENTLOG_AUDIT_SUCCESS:
		index = 3;
		break;
	case EVENTLOG_AUDIT_FAILURE:
		index = 4;
		break;
	}

	return index;
}


// Formats the specified message. If the message uses inserts, build
// the argument list to pass to FormatMessage.
LPSTR GetMessageString(DWORD MessageId, DWORD argc, char *argv, event_reader *er)
{
	char * pMessage = NULL;
	DWORD dwFormatFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER;
	DWORD_PTR* pArgs = NULL;
	char * pString = argv;
	DWORD i;
	if (argc > 0)
	{
		pArgs = (DWORD_PTR*)malloc(sizeof(DWORD_PTR) * argc);
		if (pArgs)
		{
			dwFormatFlags |= FORMAT_MESSAGE_ARGUMENT_ARRAY;

			for (i = 0; i < argc; i++)
			{
				pArgs[i] = (DWORD_PTR)pString;
				pString += strlen(pString) + 1;
			}
		}
		else
		{
			dwFormatFlags |= FORMAT_MESSAGE_IGNORE_INSERTS;
			//wprintf("Failed to allocate memory for the insert string array.\n");
		}
	}

	for (i=0;i<er->resourceHandleCount;++i){

		if (FormatMessageA(dwFormatFlags,
			er->resources[i],
			MessageId,
			0,  
			(char *)&pMessage, 
			0, 
			(va_list*)pArgs) >0){
				////wprintf("Format message succeeded!");
				break;
		}
		else
		{
			////wprintf("Format message failed with %lu\n", GetLastError());
		}

	}
	if (pArgs)
		free(pArgs);
	if(pMessage)
		return pMessage;
	else return _strdup(argv);
}

// If the message string contains parameter insertion strings (for example, %%4096),
// you must perform the parameter substitution yourself. To get the parameter message 
// string, call FormatMessage with the message identifier found in the parameter insertion 
// string (for example, 4096 is the message identifier if the parameter insertion string
// is %%4096). You then substitute the parameter insertion string in the message 
// string with the actual parameter message string. 
//
// In this example, the message string for message ID 0x103 is "%1 %%4096 = %2 %%4097.".
// When you call FormatMessage to get the message string, FormatMessage returns 
// "8 %4096 = 2 %4097.". You need to replace %4096 and %4097 with the message strings
// associated with message IDs 4096 and 4097, respectively.

DWORD ApplyParameterStringsToMessage(CONST LPCSTR pMessage, LPSTR pFinalMessage,event_reader *er)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwParameterCount = 0;  // Number of insertion strings found in pMessage
	size_t cbBuffer = 0;         // Size of the buffer in bytes
	size_t cchBuffer = 0;        // Size of the buffer in characters
	size_t cchParameters = 0;    // Number of characters in all the parameter strings
	size_t cch = 0;
	DWORD i = 0;
	LPSTR* pStartingAddresses = NULL;  // Array of pointers to the beginning of each parameter string in pMessage
	LPSTR* pEndingAddresses = NULL;    // Array of pointers to the end of each parameter string in pMessage
	DWORD* pParameterIDs = NULL;        // Array of parameter identifiers found in pMessage
	LPSTR* pParameters = NULL;         // Array of the actual parameter strings
	LPSTR pTempMessage = (LPSTR)pMessage;
	LPSTR pTempFinalMessage = NULL;

	// Determine the number of parameter insertion strings in pMessage.
	while (pTempMessage = strchr(pTempMessage, L'%'))
	{
		dwParameterCount++;
		pTempMessage++;
	}

	// If there are no parameter insertion strings in pMessage, return.
	if (0 == dwParameterCount)
	{
		pFinalMessage = NULL;
		goto cleanup;
	}

	// Allocate an array of pointers that will contain the beginning address 
	// of each parameter insertion string.
	cbBuffer = sizeof(LPWSTR) * dwParameterCount;
	pStartingAddresses = (LPSTR*)malloc(cbBuffer);
	if (NULL == pStartingAddresses)
	{
		//wprintf("Failed to allocate memory for pStartingAddresses.\n");
		status = ERROR_OUTOFMEMORY;
		goto cleanup;
	}

	RtlZeroMemory(pStartingAddresses, cbBuffer);

	// Allocate an array of pointers that will contain the ending address (one
	// character past the of the identifier) of the each parameter insertion string.
	pEndingAddresses = (LPSTR*)malloc(cbBuffer);
	if (NULL == pEndingAddresses)
	{
		//wprintf("Failed to allocate memory for pEndingAddresses.\n");
		status = ERROR_OUTOFMEMORY;
		goto cleanup;
	}

	RtlZeroMemory(pEndingAddresses, cbBuffer);

	// Allocate an array of pointers that will contain pointers to the actual
	// parameter strings.
	pParameters = (LPSTR*)malloc(cbBuffer);
	if (NULL == pParameters)
	{
		//wprintf("Failed to allocate memory for pEndingAddresses.\n");
		status = ERROR_OUTOFMEMORY;
		goto cleanup;
	}

	RtlZeroMemory(pParameters, cbBuffer);

	// Allocate an array of DWORDs that will contain the message identifier
	// for each parameter.
	pParameterIDs = (DWORD*)malloc(cbBuffer);
	if (NULL == pParameterIDs)
	{
		//wprintf("Failed to allocate memory for pParameterIDs.\n");
		status = ERROR_OUTOFMEMORY;
		goto cleanup;
	}

	RtlZeroMemory(pParameterIDs, cbBuffer);

	// Find each parameter in pMessage and get the pointer to the
	// beginning of the insertion string, the end of the insertion string,
	// and the message identifier of the parameter.
	pTempMessage = (LPSTR)pMessage;
	while (pTempMessage = strchr(pTempMessage, L'%'))
	{
		if (isdigit(*(pTempMessage+1)))
		{
			pStartingAddresses[i] = pTempMessage;

			pTempMessage++;
			pParameterIDs[i] = (DWORD)atoi(pTempMessage);

			while (isdigit(*++pTempMessage))
				;

			pEndingAddresses[i] = pTempMessage;

			i++;
		}
	}

	// For each parameter, use the message identifier to get the
	// actual parameter string.
	for ( i = 0; i < dwParameterCount; i++)
	{
		pParameters[i] = GetMessageString(pParameterIDs[i], 0, NULL,er);
		if (NULL == pParameters[i])
		{
			//wprintf("GetMessageString could not find parameter string for insert %lu.\n", i);
			status = ERROR_INVALID_PARAMETER;
			goto cleanup;
		}

		cchParameters += strlen(pParameters[i]);
	}

	// Allocate enough memory for pFinalMessage based on the length of pMessage
	// and the length of each parameter string. The pFinalMessage buffer will contain 
	// the completed parameter substitution.
	pTempMessage = (LPSTR)pMessage;
	cbBuffer = (strlen(pMessage) + cchParameters + 1) * sizeof(WCHAR);
	pFinalMessage = (LPSTR)malloc(cbBuffer);
	if (NULL == pFinalMessage)
	{
		//wprintf("Failed to allocate memory for pFinalMessage.\n");
		status = ERROR_OUTOFMEMORY;
		goto cleanup;
	}

	RtlZeroMemory(pFinalMessage, cbBuffer);
	cchBuffer = cbBuffer / sizeof(WCHAR);
	pTempFinalMessage = pFinalMessage;

	// Build the final message string.
	for ( i = 0; i < dwParameterCount; i++)
	{
		// Append the segment from pMessage. In the first iteration, this is "8 " and in the
		// second iteration, this is " = 2 ".
		strncpy_s(pTempFinalMessage, cchBuffer, pTempMessage, cch = (pStartingAddresses[i] - pTempMessage));
		pTempMessage = pEndingAddresses[i];
		cchBuffer -= cch;

		// Append the parameter string. In the first iteration, this is "quarts" and in the
		// second iteration, this is "gallons"
		pTempFinalMessage += cch;
		strcpy_s(pTempFinalMessage, cchBuffer, pParameters[i]);
		cchBuffer -= cch = strlen(pParameters[i]);

		pTempFinalMessage += cch;
	}

	// Append the last segment from pMessage, which in this example is ".".
	strcpy_s(pTempFinalMessage, cchBuffer, pTempMessage);

cleanup:

	if (ERROR_SUCCESS != status)
		pFinalMessage = (LPSTR)pMessage;

	if (pStartingAddresses)
		free(pStartingAddresses);

	if (pEndingAddresses)
		free(pEndingAddresses);

	if (pParameterIDs)
		free(pParameterIDs);

	for ( i = 0; i < dwParameterCount; i++)
	{
		if (pParameters[i])
			LocalFree(pParameters[i]);
	}

	return status;
}

int close_log(event_reader *er){

	if(er){
		if (er->eventLoghandles[NOTIFICATION_EVENT])
			CloseEventLog(er->eventLoghandles[NOTIFICATION_EVENT]);
		if (er->aWaitHandles[NOTIFICATION_EVENT])
			CloseHandle(er->aWaitHandles[NOTIFICATION_EVENT]);
		free(er);
		
	}
	return ERROR_SUCCESS;
}