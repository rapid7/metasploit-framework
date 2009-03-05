struct typeNode {
    ULONG       bpid;
    char        *name;

    typeNode    *next;
};

BOOL disableFunctionFalse(char *);
ULONG64	resolveFunctionByName(char *);
BOOL detectCallByName(char *, char *);
PDEBUG_BREAKPOINT detectExecByAddr(ULONG64, char *);
PDEBUG_BREAKPOINT detectReadByAddr(ULONG64, char *);
PDEBUG_BREAKPOINT detectWriteByAddr(ULONG64, char *);
DWORD parseHexInput(char *, DWORD, char *);
DWORD readFileIntoBuf(char *, DWORD, char **);

class detectionCallBack : public IDebugEventCallbacks {
    public:
    typeNode	*type;
	LONG		count;

	HRESULT __stdcall QueryInterface(const IID &, PVOID *);
	ULONG __stdcall AddRef(void);
	ULONG __stdcall Release(void);

    detectionCallBack();

    HRESULT __stdcall Breakpoint(PDEBUG_BREAKPOINT bp);
    HRESULT __stdcall GetInterestMask(PULONG mask);
    HRESULT __stdcall Exception(PEXCEPTION_RECORD64 exception, ULONG firstChance);
    HRESULT __stdcall CreateThread(ULONG64 handle, ULONG64 dataOffset, ULONG64 startOffset);
    HRESULT __stdcall ExitThread(ULONG exitCode);
    HRESULT __stdcall CreateProcess(
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
        ULONG64 startOffset);
    HRESULT __stdcall ExitProcess(ULONG exitCode);
    HRESULT __stdcall LoadModule(
        ULONG64 imageFileHandle,
        ULONG64 baseOffset,
        ULONG moduleSize,
        PCSTR moduleName,
        PCSTR imageName,
        ULONG checkSum,
        ULONG timeDateStamp);
    HRESULT __stdcall UnloadModule(PCSTR imageBaseName, ULONG64 baseOffset);
    HRESULT __stdcall SystemError(ULONG error, ULONG level);
    HRESULT __stdcall SessionStatus(ULONG status);
    HRESULT __stdcall ChangeDebuggeeState(ULONG flags, ULONG64 argument);
    HRESULT __stdcall ChangeEngineState(ULONG flags, ULONG64 argument);
    HRESULT __stdcall ChangeSymbolState(ULONG flags, ULONG64 argument);
    void addType(ULONG, char *);
    void recTypeNuke(typeNode *);
    ~detectionCallBack();
};

struct debugClientNode {
    PDEBUG_CLIENT           debugClient;
    detectionCallBack       *dcb;
    struct debugClientNode  *next;
};

