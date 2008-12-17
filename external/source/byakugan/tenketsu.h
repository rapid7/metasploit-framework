/* UNDOCUMENTED HEAP STRUCTURES */

typedef struct _RTL_HEAP_DEFINITION {
  ULONG                   Length;
  ULONG                   Unknown1;
  ULONG                   Unknown2;
  ULONG                   Unknown3;
  ULONG                   Unknown4;
  ULONG                   Unknown5;
  ULONG                   Unknown6;
  ULONG                   Unknown7;
  ULONG                   Unknown8;
  ULONG                   Unknown9;
  ULONG                   Unknown10;
  ULONG                   Unknown11;
  ULONG                   Unknown12;
} RTL_HEAP_DEFINITION, *PRTL_HEAP_DEFINITION;



/* FUNCTIONS */

int hookRtlHeap(void);
int tenkListener(void);
void tenkListHeaps(void);
void tenkListChunks(PVOID);
void tenkValidate(PVOID);
void tenkHelp(void);
DWORD WINAPI tenkBackChannel(LPVOID);
HRESULT CALLBACK showHeap(void);


