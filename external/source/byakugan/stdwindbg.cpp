#include <stdio.h>
#include <string.h>

#include "byakugan.h"
#include "stdwindbg.h"

char bypassFalse[] =    "\x33\xc0"          // xor eax, eax
                        "\xc2\x08\x00";     // ret 8

struct debugClientNode	*headDebugClient = NULL;


detectionCallBack::detectionCallBack() : type(NULL), count(0) {}

HRESULT __stdcall detectionCallBack::QueryInterface(const IID & iid, PVOID * ref) {
	*ref = NULL;
		
	if (iid == __uuidof(IDebugEventCallbacks))
		*ref = this;
	else if (iid == __uuidof(IUnknown))
		*ref = static_cast<IUnknown *>(this);
	else
		return E_NOINTERFACE;
	
	return S_OK;
}
	
ULONG __stdcall detectionCallBack::AddRef(void) {
	return InterlockedIncrement(&count);
}

ULONG __stdcall detectionCallBack::Release(void) {
	ULONG c = InterlockedDecrement(&count);
	if (c == 0)
		delete this;
	return c;
}

HRESULT __stdcall detectionCallBack::Breakpoint(PDEBUG_BREAKPOINT bp) {
	typeNode	*detected = type;
	ULONG		bpid;
	dprintf("CAUGHT A BP\n");
	bp->GetId(&bpid);
	while (detected != NULL && detected->bpid != bpid)
		detected = detected->next;
	if (detected == NULL) // Not one of ours.
		return (DEBUG_STATUS_BREAK);

	dprintf("[Mushishi] Detected %s anti-debugging technique.\n", detected->name);		
	return (DEBUG_STATUS_BREAK);
	//return (DEBUG_STATUS_BREAK);
}

HRESULT __stdcall detectionCallBack::GetInterestMask(PULONG mask) {
   	if (mask != NULL)
		*mask = DEBUG_EVENT_BREAKPOINT;
   	return (S_OK);
}

HRESULT __stdcall detectionCallBack::Exception(PEXCEPTION_RECORD64 exception, ULONG firstChance) {
   	return E_NOTIMPL;
}
    
HRESULT __stdcall detectionCallBack::CreateThread(ULONG64 handle, ULONG64 dataOffset, ULONG64 startOffset) {
   	return E_NOTIMPL;
}

HRESULT __stdcall detectionCallBack::ExitThread(ULONG exitCode) {
	return E_NOTIMPL;
}
	
HRESULT __stdcall detectionCallBack::CreateProcess(
	ULONG64 imageFileHandle,
	ULONG64 handle,
	ULONG64 baseOffset,
	ULONG moduleSize,
	PCSTR moduleName,
	PCSTR imageName,
	ULONG checkSum,
	ULONG timeDateStamp,
	ULONG64 initialThreadHandle,
	ULONG64 threadDataOffset,
	ULONG64 startOffset) {
		return E_NOTIMPL;
}

HRESULT __stdcall detectionCallBack::ExitProcess(ULONG exitCode) {
	return E_NOTIMPL;
}

HRESULT __stdcall detectionCallBack::LoadModule(
	ULONG64 imageFileHandle,
	ULONG64 baseOffset,
	ULONG moduleSize,
	PCSTR moduleName,
	PCSTR imageName,
	ULONG checkSum,
	ULONG timeDateStamp) {
		return E_NOTIMPL;
}

HRESULT __stdcall detectionCallBack::UnloadModule(PCSTR imageBaseName, ULONG64 baseOffset) {
	return E_NOTIMPL;
}

HRESULT __stdcall detectionCallBack::SystemError(ULONG error, ULONG level) {
	return E_NOTIMPL;
}

HRESULT __stdcall detectionCallBack::SessionStatus(ULONG status) {
	return E_NOTIMPL;
}

HRESULT __stdcall detectionCallBack::ChangeDebuggeeState(ULONG flags, ULONG64 argument) {
	return E_NOTIMPL;
}

HRESULT __stdcall detectionCallBack::ChangeEngineState(ULONG flags, ULONG64 argument) {
	return E_NOTIMPL;
}

HRESULT __stdcall detectionCallBack::ChangeSymbolState(ULONG flags, ULONG64 argument) {
	return E_NOTIMPL;
}
	

void detectionCallBack::addType(ULONG bpid, char *name) {
	typeNode *curr, *newType;

	newType = (typeNode *) malloc(sizeof (typeNode));
	if (newType == NULL)
		return;
	
	newType->bpid = bpid;
	newType->name = (char *) malloc(strlen(name) + 2);
	if (newType->name == NULL) {
		free(newType);
		return;
	}
	strncpy(newType->name, name, strlen(name));

	newType->next = type;
	type = newType;
}

void detectionCallBack::recTypeNuke(typeNode *type) {
	if (type == NULL)
		return;
	recTypeNuke(type->next);
	free(type->name);
	free(type);
}
	
detectionCallBack::~detectionCallBack() {
	recTypeNuke(type);
}

struct debugClientNode *addDebugClient(void) {

#if 0
	struct debugClientNode	*newNode, *cur;
	
	newNode = (struct debugClientNode *) malloc(sizeof(struct debugClientNode));
	if (newNode == NULL)
		return (newNode);

	g_ExtClient->CreateClient(&(newNode->debugClient));
	newNode->dcb = new detectionCallBack;

	if (headDebugClient == NULL)
		headDebugClient = newNode;
	else {
		cur = headDebugClient;
		while (cur->next != NULL)
			cur = cur->next;
		cur->next = newNode;
	}
#endif

	if (headDebugClient == NULL) {
		headDebugClient = (struct debugClientNode *) malloc(sizeof(struct debugClientNode));
		g_ExtClient->CreateClient(&(headDebugClient->debugClient));
		headDebugClient->dcb = new detectionCallBack;
	}
	return (headDebugClient);
}

// Take a function name, resolve it, and replace the first 5 bytes with
// a bypass that returns false.
BOOL disableFunctionFalse(char *funcName) {
    ULONG64         funcAddr64;

    if ((funcAddr64 = resolveFunctionByName(funcName)) == NULL)
        return (FALSE);
    g_ExtData->WriteVirtual(funcAddr64, (PVOID) bypassFalse, 5, NULL);
    return (TRUE);
}


ULONG64 resolveFunctionByName(char *funcName) {
    ULONG64         funcAddr64;

    g_ExtSymbols->Reload("/f kernel32.dll");
    if (g_ExtSymbols->GetOffsetByName(funcName, &funcAddr64) == E_FAIL)
        funcAddr64 = NULL;
    if (funcAddr64 != NULL)
        dprintf("[Byakugan] Resolved function '%s' @ 0x%16x.\n", funcName, funcAddr64);
    else {
        dprintf("[Byakugan] Unable to resolve function '%s' :(\n", funcName);
        return (NULL);
    }
	return (funcAddr64);
}

BOOL detectCallByName(char *funcName, char *detectionName) {
	if (detectExecByAddr(resolveFunctionByName(funcName), detectionName) == NULL)
		return (FALSE);
	return (TRUE);
}

PDEBUG_BREAKPOINT detectExecByAddr(ULONG64 funcAddr64, char *detectionName) {
	HRESULT						retCode;
	IDebugBreakpoint			*bp;
	ULONG						id;
	struct debugClientNode		*newDebugClient;
	
	if (funcAddr64 == NULL)
		return (NULL);

	newDebugClient = addDebugClient();

    g_ExtControl->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp);
    bp->SetOffset(funcAddr64);
    bp->SetFlags(DEBUG_BREAKPOINT_ENABLED|DEBUG_BREAKPOINT_ONE_SHOT);	
	bp->GetId(&id);
	newDebugClient->dcb->addType(id, detectionName);
	retCode = newDebugClient->debugClient->SetEventCallbacks(newDebugClient->dcb);
	//dprintf("[Mushishi] SetEventCallbacks: 0x%08x\n", retCode);
	return (bp);
}

PDEBUG_BREAKPOINT detectWriteByAddr(ULONG64 funcAddr64, char *detectionName) {
    HRESULT                     retCode;
    IDebugBreakpoint            *bp;
    ULONG                       id;
    struct debugClientNode      *newDebugClient;

    if (funcAddr64 == NULL)
        return (NULL);

    newDebugClient = addDebugClient();

    g_ExtControl->AddBreakpoint(DEBUG_BREAKPOINT_DATA, DEBUG_ANY_ID, &bp);
    bp->SetOffset(funcAddr64);
	bp->SetDataParameters(4, DEBUG_BREAK_WRITE);
    bp->SetFlags(DEBUG_BREAKPOINT_ENABLED);
    bp->GetId(&id);
    
	newDebugClient->dcb->addType(id, detectionName);
    retCode = newDebugClient->debugClient->SetEventCallbacks(newDebugClient->dcb);
    //dprintf("[Mushishi] SetEventCallbacks: 0x%08x\n", retCode);
    return (bp);
}

PDEBUG_BREAKPOINT detectReadByAddr(ULONG64 funcAddr64, char *detectionName) {
    HRESULT                     retCode;
    IDebugBreakpoint            *bp;
    ULONG                       id;
    struct debugClientNode      *newDebugClient;

    if (funcAddr64 == NULL)
        return (NULL);

    newDebugClient = addDebugClient();

    g_ExtControl->AddBreakpoint(DEBUG_BREAKPOINT_DATA, DEBUG_ANY_ID, &bp);
    bp->SetOffset(funcAddr64);
	bp->SetDataParameters(4, DEBUG_BREAK_READ);
    bp->SetFlags(DEBUG_BREAKPOINT_ENABLED);
    bp->GetId(&id);
    newDebugClient->dcb->addType(id, detectionName);
    retCode = newDebugClient->debugClient->SetEventCallbacks(newDebugClient->dcb);
    //dprintf("[Mushishi] SetEventCallbacks: 0x%08x\n", retCode);
    return (bp);
}

DWORD parseHexInput(char *hexInput, DWORD size, char *output) {
	return (0);
}

DWORD readFileIntoBuf(char *path, DWORD size, char **output) {
    HANDLE      inputFile;
    DWORD       readOut = 1, i = 0;
    char        out;
    BYTE        state = 0;

    if((inputFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        dprintf("[S] Unable to open file: %s\n", path);
        return (-1);
    }
	if (size == 0)
		size = GetFileSize(inputFile, NULL) - 1;
	
	*output = (char *) malloc(size + 1);
	if (!*output) {
		dprintf("[S] Unable to allocate memory for %s\n", path);
		return (0);
	}

    while (readOut > 0 && i < size) {
        ReadFile(inputFile, &out, 1, &readOut, NULL);
    	(*output)[i++] = out;
	}
    return (i);
}
