#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "byakugan.h"
#include "jutsu.h"
#include "msfpattern.h"
#include "stdwindbg.h"

struct requestQueue	jutsuRequests;
struct trackedBuf	*trackedBufList = NULL;
struct trackedVal	*trackedValList = NULL;

ULONG64				disassemblyBuffer;
HANDLE				processHandle = 0;

SOCKET				ListenSocket = INVALID_SOCKET,
	                ClientSocket = INVALID_SOCKET;


//IDebugClient		msfClient;


char *regs[] = {
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esp",
    "ebp",
    "eip",
    NULL
};

void helpJutsu(void) {
	return;
}

void memDiffJutsu(char *inputType, DWORD size, char *input, ULONG64 address) {
	DWORD	i, j, valResult, readSize, numBadChars = 0;
	BOOL	upperFlag, lowerFlag, nullFlag;
	char	*pureBuf = NULL, findValExpression[64] = {'\x00'};
	char	lineExpected[16], lineActual[16];
	
	struct trackedBuf *curr = trackedBufList;
	struct corruption *badChars;

	// Valid inputs: ASCII, hex, file, buf
	if (!_stricmp(inputType, "ASCII")) {
		pureBuf = input;
	} else if (!_stricmp(inputType, "hex")) {
		if (size != parseHexInput(input, size, pureBuf)) {
			dprintf("[J] Failed to parse %d bytes from hex input.\n", size);
			return;
		}
	} else if (!_stricmp(inputType, "file")) {
		readSize = readFileIntoBuf(input, size, &pureBuf);
		if ((size && size != readSize) || readSize == 0) {
			dprintf("[J] Failed to read %d bytes from %s.\n", size, input);
			return;
		}
		size = (size ? size : readSize);
	} else if (!_stricmp(inputType, "buf")) {
		// Grab the buf by name from the trackedBufList
     
    	while (curr != NULL) {
        	if(!_stricmp(input, curr->bufName)) {
				pureBuf = curr->bufPatt;
            	break;
			}
        	curr = curr->next;
    	}
		if (pureBuf == NULL) {
			dprintf("[J] Unable to find buffer: %s\n", input);
			return;
		}	
	} else {
		dprintf("[J] The valid input types are buf, hex, and file.\n");
		return;
	}

	upperFlag = lowerFlag = nullFlag = FALSE;
	badChars = (struct corruption *) malloc(size * sizeof (struct corruption));

	dprintf("\t\t\tACTUAL\t\t\t\t\t\t\t\tEXPECTED\n");
	for (i = 0; i < size; i++) {
		// Get byte at the important memory location
		StringCchPrintf(findValExpression, sizeof(findValExpression), 
				"poi(0x%08x)", address + i);
		valResult = (GetExpression(findValExpression) & 0xFF);
		
		lineExpected[i%16] = pureBuf[i];
		lineActual[i%16] = valResult;

		if (pureBuf[i] != valResult) {
			badChars[numBadChars].value = pureBuf[i];
			badChars[numBadChars].offset = i;
			badChars[numBadChars].seenAgain = FALSE;
			badChars[numBadChars].seenBefore = FALSE;
			for (j = 0; j < numBadChars; j++) {
				if (badChars[j].value == badChars[numBadChars].value) {
					badChars[numBadChars].seenBefore = TRUE;
				}
			}
			numBadChars++;
		} else {
			for (j = 0; j < numBadChars; j++)
				if (valResult == badChars[j].value)
					badChars[j].seenAgain = TRUE;
		}


		if (i % 16 == 15 || i == size-1) {
			// Print the actual characters with differences in bold
			for (j = 0; j != i % 16 + 1; j++) {
				// Diff the two locations
				if (lineActual[j] != lineExpected[j]) {
					// Store badchars, and bad offsets
					// Print this character in bold!
					StringCchPrintf(findValExpression, sizeof(findValExpression), 
					".printf /D \"<b><red>%02x</red></b> \"", lineActual[j]);
					g_ExtControl->Execute(DEBUG_OUTCTL_THIS_CLIENT, findValExpression, 
										DEBUG_EXECUTE_NOT_LOGGED);

				} else {
					dprintf("%02x ", lineActual[j]);
				}

				// Take note of upper / lower / null exclusions
			}
			if (i == size-1)
				for (j = 0; j < 15 - i % 16; j+=2)
					dprintf("\t");
			dprintf("\t");

			// Now print the Expected characters
			for (j = 0; j != i % 16 + 1; j++) { 
				dprintf("%02x ", lineExpected[j]);
			}
			dprintf("\n");
		}
	}

	// Display bad chars
	i = 0;
	if (numBadChars) {
		dprintf("\n[J] Bytes replaced: ");
		while (i < numBadChars) {
			if (!badChars[i].seenAgain && !badChars[i].seenBefore)
				dprintf("0x%02x ", badChars[i].value);
			i++;
		}
		i = 0;
		dprintf("\n[J] Offset corruption occurs at: ");
        while (i < numBadChars) {
            if (badChars[i].seenAgain) 
                dprintf("%02x ", badChars[i].offset);
            i++;
        }
		dprintf("\n");
	}
	
	// Unless pureBuf came from a tracked buffer, free the memory
	if (_stricmp(inputType, "buf"))
		free(pureBuf);
	free(badChars);
}

void listTrackedVals() {
	struct trackedVal   *newTrackedVal;

	if (trackedValList == NULL) {
		dprintf("[J] Currently tracking no primitive values.\n");
		return;
	}

	dprintf("[J] Currently tracking:\n");

	newTrackedVal = trackedValList;
	while (newTrackedVal != NULL) {
		dprintf("\tName: %s\t\tSize: %d\tCandidates: %d\n", 
				newTrackedVal->valName, newTrackedVal->valSize, newTrackedVal->candidates);
		newTrackedVal = newTrackedVal->next;
	}
}

void listTrackedValByName(char *name) {
	struct trackedVal   *newTrackedVal;
	struct valInstance	*curr;

	newTrackedVal = trackedValList;
	if (newTrackedVal == NULL) goto nada;

	while (newTrackedVal != NULL) {
        if (!_stricmp(newTrackedVal->valName, name))
            break;
        newTrackedVal = newTrackedVal->next;
    }

	if (newTrackedVal) {

		curr = newTrackedVal->instances;
		
		if (curr != NULL)
			dprintf("[J] Currently tracking %d candidates for %s:\n", 
					newTrackedVal->candidates, newTrackedVal->valName);
		else
			goto nada;

		while (curr != NULL) {
			dprintf("\tAddress: 0x%08x\n", curr->address);
			curr = curr->next;
		}
		return;
	}
nada:
	dprintf("[J] No candidates are being tracked for %s.\n", name);	
}

void trackValJutsu(char *name, DWORD size, DWORD value) {
    struct trackedVal   *newTrackedVal, *parent = NULL;
	struct valInstance	*last, *curr;
	char				findValExpression[18] =  {'\x00'};
	DWORD				valResult, andExpression;

	switch(size) {
		case 1: andExpression = 0xFF;			break;
		case 2: andExpression = 0xFFFF;			break;
		case 4: andExpression = 0xFFFFFFFF;		break;
		default:
			dprintf("[J] Valid primitive sizes are 1, 2, and 4.\n");
			return;
	}                    	
	
	newTrackedVal = trackedValList;
	while (newTrackedVal != NULL) {
		if (!_stricmp(newTrackedVal->valName, name))
			break;
		newTrackedVal = newTrackedVal->next;
	}

	// Search the list for the new value, purge old addresses
	if (newTrackedVal) {
		dprintf("[J] Narrowing down candidate list for %s from %d candidates.\n", name, newTrackedVal->candidates);
		curr = newTrackedVal->instances;
		last = NULL;

		while (curr != NULL) {
			StringCchPrintf(findValExpression, sizeof(findValExpression), "poi(0x%08x)", curr->address);
			valResult = (GetExpression(findValExpression) & andExpression);
        	if (value != valResult) {
				if (last) {
					last->next = curr->next;
					free(curr);
					curr = last->next;
				} else {
					newTrackedVal->instances = curr->next;
					free(curr);
					curr = newTrackedVal->instances;
				}
				newTrackedVal->candidates--;
				if (newTrackedVal->candidates == 1) {
					dprintf("[J] Value %s is stored at address 0x%08x\n", 
							newTrackedVal->valName, newTrackedVal->instances->address);
					return;
				}
			} else {
				last = curr; curr = curr->next;
			}
		}
		dprintf("[J] Narrowed down address of %s to %d possible candidates.\n", name, newTrackedVal->candidates);
		return;
	} 
	dprintf("[J] Creating new list of candidates for %s.\n", name);

	// Create a new list and search all memory for the value
    newTrackedVal = (struct trackedVal *) malloc(sizeof (struct trackedVal));
    if (newTrackedVal == NULL) {
        dprintf("[J] OOM!");
        return;
    }
    newTrackedVal->next 		= NULL;
	newTrackedVal->valSize 		= size;
	newTrackedVal->valName 		= _strdup(name);
	if(!newTrackedVal->valName) {
		free(newTrackedVal);
		dprintf("[J] OOM!\n");
		return;
	}

	newTrackedVal->candidates = findAllVals((BYTE*) &value, size, &(newTrackedVal->instances));	
	dprintf("[J] Discovered %d possible candidate addresses for %s\n", newTrackedVal->candidates, name);

	newTrackedVal->next = trackedValList;
	trackedValList = newTrackedVal;

	return;
}

void bindJutsu(char  *bindPort) {
	HANDLE					hThread;
	DWORD					dwThreadId;
	IDebugOutputCallbacks	*fuzzerOutputCallback;

	// Initialize Request Queue
	memset(&jutsuRequests, 0, sizeof (struct requestQueue));

	// Fire up backchannel thread
    hThread = CreateThread(     NULL,
                                0,
                                listenJutsu,
                                (LPVOID) bindPort,
                                0,
                                &dwThreadId);

    if (hThread == NULL)
        dprintf("[Byakugan] CreateThread() failed.\n");
}

DWORD WINAPI listenJutsu(LPVOID lpvParam) {
	WSADATA		wsaData;
    char		recvbuf[DEFAULT_BUFLEN];
    ULONG		iResult, iSendResult;
    ULONG		recvbuflen = DEFAULT_BUFLEN;
	char		*bindPort = (char *) lpvParam;
    struct addrinfo		*result = NULL,
						hints;
	

	dprintf("[J] Creating Metasploit back channel on port %s... ", bindPort);

	if (WSAStartup( MAKEWORD( 2, 2 ), &wsaData) != 0) {
        dprintf("Failed!: %d\n", WSAGetLastError());
		return (-1);
	}

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, bindPort, &hints, &result);
    if ( iResult != 0 ) {
        dprintf("Failed!: %d\n", WSAGetLastError());
        WSACleanup();
        return (-1);
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        dprintf("Failed!: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return (-1);
    }

    // Setup the TCP listening socket
    iResult = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        dprintf("Failed!: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return (-1);
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        dprintf("Failed!: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return (-1);
    }

	dprintf("Listening.\n");
    
	// Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        dprintf("[J] Back channel accept failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return (-1);
    }

    // No longer need server socket
    closesocket(ListenSocket);

	// Register new output callback
	//fuzzerOutputCallback = new IDebugOutputCallbacks();

	// Register new event callback

    // Receive until the peer shuts down the connection
    do {
		memset(recvbuf, 0, DEFAULT_BUFLEN);
        
		iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0)
			parseJutsu(recvbuf, iResult);
        else if (iResult == 0)
            dprintf("[J] Back channel connection closing...\n");
        else  {
            dprintf("[J] Back channel recv failed: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return (-1);
        }
    } while (iResult > 0);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        dprintf("[J] Back channel shutdown failed: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return (-1);
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();


	return (0);
}

void parseJutsu(char *buf, ULONG buflen) {
	struct request			*newRequest, *node;
	struct requestHeader	*reqHead;

	//dprintf("[J] Back channel got: %s\n", buf);
	
	reqHead = (struct requestHeader *) buf;
	if ((reqHead->length + 4) > buflen || buflen < 5 || reqHead->length > 0xFFFD) {
		dprintf("[J] Received a malformed jutsu request! :(\n");
		return;
	}
		
	newRequest = (struct request *) malloc(sizeof (struct request));
	if (newRequest == NULL) {
		dprintf("[J] Failed to allocate! :(\n");
		return;
	}
	
	newRequest->type	= reqHead->type;
	newRequest->length	= reqHead->length;
	newRequest->data	= (BYTE *) malloc(newRequest->length + 1);
	if (newRequest->data == NULL) {
		dprintf("[J] Failed to allocate! :(\n"); 
		free(newRequest);
		return; 
	}
	newRequest->next	= NULL;

	memcpy(newRequest->data, (buf+4), newRequest->length);

	if (jutsuRequests.head != NULL) {
		node = jutsuRequests.head;
		while (node->next != NULL)
			node = node->next;
		node->next = newRequest;
	} else {
		jutsuRequests.head = newRequest;
	}
	jutsuRequests.length++;

	return;
}

void showRequestsJutsu() {
	struct request	*node;
	USHORT			i;

	dprintf("[J] Currently waiting on %d requests:\n", jutsuRequests.length);

	node = jutsuRequests.head;
	while (node != NULL) {
		dprintf("Type: 0x%04x\tLength: 0x%04x\nData:",
				node->type, node->length);
		for (i = 0; i < node->length; i++) {
			if (i % 32 == 0) dprintf("\n");
			if (i % 8 == 0) dprintf("\t0x");
			dprintf("%01x", node->data[i]);
		}
		dprintf("\n\n");
		node = node->next;
	}
}
void identBufJutsu(char *inputType, char *bufName, char *bufPatt, DWORD size) {
	struct trackedBuf	*newTrackedBuf, *curBuf;
	char				*msfPattern;
	DWORD				readSize;
	HANDLE				hFile;

	if (trackedBufList != NULL) {
		curBuf = trackedBufList;
		while (curBuf->next != NULL) {
			if (!_stricmp(bufName, curBuf->bufName)) {
				dprintf("[J] Buf %s already exists. Please delete it first.\n", bufName);
				return;
			}
			curBuf = curBuf->next;
		}
	}

	newTrackedBuf = (struct trackedBuf *) malloc(sizeof (struct trackedBuf));
	if (newTrackedBuf == NULL) {
		dprintf("[J] OOM!");
		return;
	}

	newTrackedBuf->next = NULL;
	newTrackedBuf->prev = NULL;
	if (!_stricmp(inputType, "msfpattern")) {
		size = strtoul(bufPatt, NULL, 10);
		msfPattern = (char *) malloc(size+1);
		if (msfPattern == NULL) {
			dprintf("[J] Failed to allocate %d bytes!\n", size+1);
			return;
		}
		msf_pattern_create(size, msfPattern);
		msfPattern[size] = '\x00';
		newTrackedBuf->bufPatt = msfPattern;
	} else if (!_stricmp(inputType, "ascii")){
		newTrackedBuf->bufPatt = _strdup(bufPatt);
		size = strlen(bufPatt);
	} else if (!_stricmp(inputType, "file")) {
		readSize = readFileIntoBuf(bufPatt, size, &(newTrackedBuf->bufPatt));
		if ((size && readSize != size) || readSize == 0) {
			dprintf("[J] Unable to read %d bytes from %s\n", size, bufName);
			return;
		}
		size = (size ? size : readSize);
	}


	newTrackedBuf->bufName = _strdup(bufName);
	newTrackedBuf->bufSize = size;
	if (newTrackedBuf->bufName == NULL || newTrackedBuf->bufPatt == NULL) {
		dprintf("[J] OOM!");
		return;
	}

	if (trackedBufList == NULL) {
		trackedBufList = newTrackedBuf;
	} else {
		curBuf->next			= newTrackedBuf;
		newTrackedBuf->prev		= curBuf;
	}
	dprintf("[J] Creating buffer %s.\n", bufName);
}

void rmBufJutsu(char *bufName) {
	struct trackedBuf	*curBuf;
	
	curBuf = trackedBufList;
	while (curBuf != NULL) {
		if(!_stricmp(bufName, curBuf->bufName))
			break;
		curBuf = curBuf->next;
	}
	if (curBuf != NULL) {
		if (curBuf->prev != NULL)
			curBuf->prev->next = curBuf->next;
		if (curBuf->next != NULL)
			curBuf->next->prev = curBuf->prev;
		if (curBuf == trackedBufList)
			trackedBufList = curBuf->next;
		free(curBuf->bufName);
		free(curBuf->bufPatt);
		free(curBuf);
		dprintf("[J] Removed buffer: %s\n", bufName);
	} else {
		dprintf("[J] Unable to find buffer: %s\n", bufName);
	}
}

void listTrackedBufJutsu() {
	struct trackedBuf	*curBuf;
	DWORD				i;

	curBuf = trackedBufList;
	if (curBuf == NULL) {
		dprintf("[J] Currntly tracking no buffer patterns.\n");
	} else {
		dprintf("[J] Currently tracked buffer patterns:\n");
		while (curBuf != NULL) {
			dprintf("\tBuf: %s\tPattern: ", curBuf->bufName);
			for (i = 0; i < curBuf->bufSize; i++)
				dprintf("%c", curBuf->bufPatt[i]);
			dprintf("\n");
			curBuf = curBuf->next;
		}
	}
	dprintf("\n");
}

void hunterJutsu() {
	struct trackedBuf	*curBuf;
	struct bufInstance	*instance;
	ULONG				i, j, range, addr, *nextNum, foundInstance;
	BOOLEAN				caught;
	char				*corUpper, *corLower, *corUni;

    for (i = 0; regs[i] != NULL; i++) {
		addr = GetExpression(regs[i]);
		curBuf = trackedBufList;
		caught = FALSE;
    	while (curBuf != NULL) {
			range = curBuf->bufSize;
			for (j = 0; j < range-3; j++) {
				nextNum = (ULONG *) ((curBuf->bufPatt) + j);
				if (addr != 0 && *nextNum == addr) {
					dprintf("[J] Controlling %s with %s at offset %d.\n", 
							regs[i], curBuf->bufName, j);
					caught = TRUE;
					break;
				}
			}
			curBuf = curBuf->next;
			if (caught)
				break;
		}

    }
	
	// Now, find all instances of buffers in memory with a fuzzy match! :)
	curBuf = trackedBufList;
	while (curBuf != NULL) {
		foundInstance = searchMemory((unsigned char *) curBuf->bufPatt, 
				(curBuf->bufSize > 32) ? 32 : curBuf->bufSize);
		if (foundInstance != 0) {
			// try for larger increments
			instance = (struct bufInstance *) malloc(sizeof (struct bufInstance));
			memset(instance, 0, sizeof (struct bufInstance));
			instance->address = foundInstance;
			dprintf("[J] Found buffer %s @ 0x%08x\n", curBuf->bufName, foundInstance);
		}
			// try standard corruptions
			range = (curBuf->bufSize > 32) ? 32 : curBuf->bufSize;
			corUpper	= (char *) malloc(range + 1);
			corLower	= (char *) malloc(range + 1);
			corUni		= (char *) malloc((range + 1) * 2);
			for (i = j = 0; i < range; i++) {
				corUpper[i] = (char) toupper(curBuf->bufPatt[i]);
				corLower[i] = (char) tolower(curBuf->bufPatt[i]);
				corUni[j++] = curBuf->bufPatt[i];
				corUni[j++] = '\x00';
			}
			if ((foundInstance = searchMemory((unsigned char *) corUpper, range)) != 0)
				dprintf("[J] Found buffer %s @ 0x%08x - Victim of toUpper!\n",
						curBuf->bufName, foundInstance);
			if ((foundInstance = searchMemory((unsigned char *) corLower, range)) != 0)
				dprintf("[J] Found buffer %s @ 0x%08x - Victim of toLower!\n",
						curBuf->bufName, foundInstance);
			if ((foundInstance = searchMemory((unsigned char *) corUni, range*2)) != 0)
				dprintf("[J] Found buffer %s @ 0x%08x - Victim of Unicode Conversion!\n",
						curBuf->bufName, foundInstance);
			free(corUpper);
			free(corLower);
			free(corUni);
		

		curBuf = curBuf->next;
	}
	
}

ULONG64 allocateMemoryBlock(unsigned long size){
	unsigned long processId = 0;
	void * allocBuffer = 0;

	if(g_ExtSystem->GetCurrentProcessSystemId(&processId) != S_OK){
		dprintf("[J] failed to find process id\n");
		return 0;
	}

	if(!(processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId))){
		dprintf("[J] OpenProcess failed\n");
		return 0;
	}

	if(!(allocBuffer = VirtualAllocEx(processHandle, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE))){
		dprintf("[J] VirtualAllocEx failed\n");
		CloseHandle(processHandle);
		return 0;
	}

	//CloseHandle(processHandle);

	return ((ULONG64)allocBuffer);
}

unsigned short getInstructionBytes(char * instruction, unsigned char * opcodeBuffer){
	BYTE zero = 0;
	BYTE byteCounter = 0;
	ULONG64 byteEnd = 0;
	BYTE i = 0;

    if(!disassemblyBuffer){
        if(!(disassemblyBuffer = allocateMemoryBlock(0x1000))){
            dprintf("[J] allocateMemoryBlock failed\n");
            return (0);
        }
    }
	

	if(g_ExtControl->Assemble(disassemblyBuffer, instruction, &byteEnd) != S_OK){
		dprintf("[J] failed to assemble instruction\n");
		return (0);
	}

	if(!ReadMemory(disassemblyBuffer, opcodeBuffer, (byteEnd-disassemblyBuffer), NULL)){
		dprintf("[J] failed to read opcode sequence\n");
		return (0);
	}

	for(i=0; i<(byteEnd-disassemblyBuffer); i++){
		if(!WriteMemory((disassemblyBuffer+i), &zero, 1, NULL)){ 
			dprintf("[J] failed to zero memory\n");
			return (0);
		}
	}
#if 0
	dprintf("[J] Opcode sequence for instruction %s:", instruction);

	for(byteCounter=0; ((disassemblyBuffer+byteCounter)<byteEnd); byteCounter++){
		dprintf("%02x ", opcodeBuffer[byteCounter]);
	}

	dprintf("\n");
#endif
	return (byteEnd-disassemblyBuffer);
}

ULONG64 searchMemory(unsigned char * byteBuffer, unsigned long length){
	ULONG64 addressHit = 0;
	HRESULT memSearch = S_OK;

	if((memSearch = g_ExtData->SearchVirtual((ULONG64)0, (ULONG64)-1, byteBuffer, 
		length, 1, &addressHit)) != S_OK){
#if 0
			if(memSearch == HRESULT_FROM_NT(STATUS_NO_MORE_ENTRIES)){
				dprintf("[J] byte sequence not found in virtual memory\n");
			}
			else{
				dprintf("[J] byte search failed for another reason\n");
			}
#endif
			return (0);
	}
	return (addressHit);
}

DWORD	findAllVals(unsigned char *byteBuffer, BYTE size, struct valInstance **instance) {
	ULONG64 addressHit = 0;
	DWORD	addressCount = 0;
	HRESULT memSearch;
	struct	valInstance	*newValInstance;
	
	*instance = NULL;

	while ((memSearch = g_ExtData->SearchVirtual(addressHit+size, (ULONG64)-1, byteBuffer,
        size, 1, &addressHit)) == S_OK) {
		
		if (!*instance) {
			*instance = (struct valInstance *) malloc(sizeof (struct valInstance));
			newValInstance = *instance;
		} else {
			newValInstance->next = (struct valInstance *) malloc(sizeof (struct valInstance));
			newValInstance = newValInstance->next;
		}
		newValInstance->address = addressHit;
		newValInstance->next = NULL;
		addressCount++;
	}

	return (addressCount);
}

BOOL checkExecutability(ULONG64 checkAddress){
	MEMORY_BASIC_INFORMATION protectionInfo;

	if(!VirtualQueryEx(processHandle, (LPVOID)checkAddress, &protectionInfo, sizeof(MEMORY_BASIC_INFORMATION))){
		dprintf("[J] Unable to obtain protection information for address 0x%08x\n", checkAddress);
		return FALSE;
	}

	//dprintf("allocation info: 0x%08x and 0x%08x\n", protectionInfo.AllocationProtect, protectionInfo.Protect);

	if((protectionInfo.Protect & PAGE_EXECUTE_READ) != 0)
		return TRUE;

	//dprintf("[J] 0x%08x isn't executable\n");
	return FALSE;
}

void searchOpcodes(char *instructions) {
	char			**instructionList;
	unsigned char	*byteSequence;
	DWORD			length, i, j, semiCount = 1, offset = 0; 
	ULONG64			ptr;

	// Split instructions into seperate strings at pipes
	length = 0;
	while (instructions[length] != NULL) {
		if (instructions[length] == '|')
			semiCount++; 
		length++;
	}

	// Malloc space for instructionList;
	instructionList = (char **) malloc((semiCount+1) * sizeof (char *));
	if (instructionList == NULL) {
		dprintf("[J] OOM!\n");
		return;
	}
	instructionList[0] = instructions;
	dprintf("[J] Searching for:\n");
	i = 0; j = 0;
	while (i < length) {
		if (instructions[i] == '|') {
			instructions[i] = '\x00';
			dprintf("> %s\n", instructionList[j++]);
			instructionList[j] = &(instructions[i+1]);
		}
		i++;
	}
	dprintf("> %s\n", instructionList[j]);


	// Allocate space for byteSequence
	byteSequence = (unsigned char *) malloc(semiCount * 6);
	if (byteSequence == NULL) {
		dprintf("[J] OOM!\n");
		return;
	}

	// Generate byte sequence and display it
	for (i = 0; i < semiCount; i++) {
		unsigned char	tmpbuf[8];
		offset += getInstructionBytes(instructionList[i], byteSequence+offset);
	}
	
	dprintf("[J] Machine Code:\n> ");
	for (i = 0; i < offset; i++) {
		dprintf("%02x ", byteSequence[i]);
		if (i != 0 && !(i % 16))
			dprintf("\n> ");
	}
	dprintf("\n");

	// Search for sequence in executable memory
	ptr = searchMemory(byteSequence, offset);
	if (ptr && checkExecutability(ptr))
		dprintf("[J] Executable opcode sequence found at: 0x%08x\n", ptr);
	return;
}

void returnAddressHuntJutsu(){
	struct trackedBuf *curBuf;
	int i = 0, bufferIndex = 0;
	ULONG offset = 0, bytes = 0;	
	char findBufferExpression[25];
	ULONG64 returnAddress = 0;
	HRESULT memSearch = S_OK;

	//disassembly variables
	char returnInstruction[30];
	unsigned char opcodeBuffer[30];
	unsigned short instructionLength = 0;
	dprintf("[J] started return address hunt\n");


	for(i; i<6; i++){			//6, because we don't want to waste time on the eip register
		curBuf = trackedBufList;	
		memset(findBufferExpression, 0x00, sizeof(findBufferExpression));

		if(!(bytes = GetExpression(regs[i]))){
			dprintf("[J] skipping %s as register - it is a null pointer\n", regs[i]);
			continue;
		}

		StringCchPrintf(findBufferExpression, sizeof(findBufferExpression), "poi(%s)", regs[i]);
		bytes = GetExpression(findBufferExpression);
	
		//tests if a register points to a location in user controlled data
		while(curBuf != NULL){
			for(bufferIndex=0; bufferIndex < curBuf->bufSize; bufferIndex++){
				if(*(PULONG)((curBuf->bufPatt)+bufferIndex) == bytes){
					memset(opcodeBuffer, 0x00, sizeof(opcodeBuffer));
					memset(returnInstruction, 0x00, sizeof(returnInstruction));

					//find the opcodes for the desired instruction

					//first, for call reg
					StringCchPrintf(returnInstruction, sizeof(returnInstruction), "call %s", regs[i]);
					if(!(instructionLength = getInstructionBytes(returnInstruction, opcodeBuffer)))
						dprintf("[J] getInstructionBytes failed for '%s'\n", returnInstruction);
					if(returnAddress = searchMemory(opcodeBuffer, instructionLength)){
						if(checkExecutability(returnAddress))
							dprintf("[J] valid return address (call %s) found at 0x%08x\n", regs[i], returnAddress);
					}
							

					//now, for jmp reg
					memset(returnInstruction, 0x00, sizeof(returnInstruction));
					StringCchPrintf(returnInstruction, sizeof(returnInstruction), "jmp %s", regs[i]);
					if(!(instructionLength = getInstructionBytes(returnInstruction, opcodeBuffer)))
						dprintf("[J] getInstructionBytes failed for '%s'\n", returnInstruction);
					if(returnAddress = searchMemory(opcodeBuffer, instructionLength)){
						if(checkExecutability(returnAddress))
							dprintf("[J] valid return address (jmp %s) found at 0x%08x\n", regs[i], returnAddress);
					}
				}
			}
			curBuf = curBuf->next;
		}

		curBuf = trackedBufList;	

		for(offset=0; offset<0x1000; offset+=4){
			memset(findBufferExpression, 0x00, sizeof(findBufferExpression));
			StringCchPrintf(findBufferExpression, sizeof(findBufferExpression), "poi(poi(%s+0x%08x))", regs[i], offset);
			if(!(bytes = GetExpression(findBufferExpression)))
				continue;								//this is basically a replacement for the
													//ddp windbg command, except more automated
			//walk through the buffer to see if any dword in there matches the current 
			//value returned by the expression 
			while(curBuf != NULL){
				for(bufferIndex=0; bufferIndex < curBuf->bufSize; bufferIndex++){
					if(*(PULONG)((curBuf->bufPatt)+bufferIndex) == bytes){
						memset(opcodeBuffer, 0x00, sizeof(opcodeBuffer));
						memset(returnInstruction, 0x00, sizeof(returnInstruction));
						dprintf("[J] %s + 0x%08x points into offset 0x%x of buffer %s\n",
								regs[i], offset, bufferIndex, curBuf->bufName);

						
						//first, build the instruction to find the bytes for
						//for now, we will support jmp [reg+offset] and call [reg+offset]

						//first, for call [reg+offset]
						StringCchPrintf(returnInstruction, sizeof(returnInstruction), "call [%s+%x]", regs[i], offset);
						if(!(instructionLength = getInstructionBytes(returnInstruction, opcodeBuffer)))
							dprintf("[J] getInstructionBytes failed for '%s'\n", returnInstruction);
						if(returnAddress = searchMemory(opcodeBuffer, instructionLength)){
							if(checkExecutability(returnAddress))
								dprintf("[J] valid return address (call [%s+%x]) found at 0x%08x\n", regs[i], offset, returnAddress);
						}


						//now, for jmp [reg+offset]
						memset(returnInstruction, 0x00, sizeof(returnInstruction));
						StringCchPrintf(returnInstruction, sizeof(returnInstruction), "jmp [%s+%x]", regs[i], offset);
						if(!(instructionLength = getInstructionBytes(returnInstruction, opcodeBuffer)))
							dprintf("[J] getInstructionBytes failed for '%s'\n", returnInstruction);
						if(returnAddress = searchMemory(opcodeBuffer, instructionLength)){
							if(checkExecutability(returnAddress))
								dprintf("[J] valid return address (jmp [%s+%x]) found at 0x%08x\n", regs[i], offset, returnAddress);
						}
					}	
				}
			curBuf = curBuf->next;
			}
		curBuf = trackedBufList;	
		}
	}
}
