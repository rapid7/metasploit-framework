#define	ALLOCATESTRUCT			0x0
#define	REALLOCATESTRUCT		0x1
#define	FREESTRUCT				0x2
#define	CREATESTRUCT			0x3
#define	DESTROYSTRUCT			0x4
#define COALESCESTRUCT			0x5

#define CHUNK(x)				(heap->chunks[x])
#define NULLNODE				0xffffffff

// Space between chunks on vista
#define SPACEBETWEEN			0x18 

// Dont use a direct access list here because looping should
// be faster for our number of heaps (I think!)
struct HeapState {
	ULONG			numHeaps;
	ULONG			hPoolListLen;
	struct HPool	*heaps;
};

struct HPool {
	PVOID				base;
	ULONG				numChunks;
	ULONG				chunkListLen;
	ULONG				flags;
	ULONG				reserve;
	ULONG				commit;
	BOOLEAN				lock;
	ULONG				*map;
	struct HeapChunk	*chunks;
	ULONG				inUseHead;
	ULONG				lastInUse;
	BOOLEAN				inUse;
};

struct HeapChunk {
	PVOID		addr;
	PVOID		heapHandle;
	ULONG		size;
	ULONG		flags;
	ULONG		nextBucket;
	ULONG		nextInUse;
	BOOLEAN		free;
	BOOLEAN		inUse;
};

struct AllocateStruct {
	BYTE		type;
	PVOID		heapHandle;
	ULONG		flags;
	ULONG		size;
	PVOID		ret;
};

struct ReallocateStruct {
	BYTE		type;
	PVOID		heapHandle;
	ULONG		flags;
	PVOID		memoryPointer;
	ULONG		size;
	PVOID		ret;
};

struct FreeStruct {
	BYTE		type;
	PVOID		heapHandle;
	ULONG		flags;
	PVOID		memoryPointer;
	PVOID		ret;
};

struct CreateStruct {
	BYTE		type;
	ULONG 		flags;
    PVOID 		base;
   	ULONG 		reserve;
   	ULONG 		commit;
    BOOLEAN 	lock;
    PVOID 		RtlHeapParams;	// Wont get this info back now - maybe later
	PVOID		ret;			// if we think we really need it?

};

struct DestroyStruct {
	BYTE		type;
	PVOID		heapHandle;
	NTSTATUS 	ret;
};

struct CoalesceStruct {
	BYTE		type;
	PVOID		heapHandle;
	ULONG		arg2;
	ULONG		arg3;
	ULONG		arg4;
	PVOID		ret;
};

void initializeHeapModel(struct HeapState *);
void heapAllocate(struct HeapState *heapModel, struct AllocateStruct *aStruct);
void heapReallocate(struct HeapState *heapModel, struct ReallocateStruct *aStruct);
void heapFree(struct HeapState *heapModel, struct FreeStruct *fStruct);
void heapCreate(struct HeapState *heapModel, struct CreateStruct *cStruct);
void heapDestroy(struct HeapState *heapModel, struct DestroyStruct *dStruct);
void heapCoalesce(struct HeapState *heapModel, struct CoalesceStruct *cfbStruct);
struct HPool *getHeap(struct HeapState *heapModel, PVOID heapHandle);
struct HeapChunk *getChunk(struct HPool *heap, PVOID memoryPointer, ULONG inAfter);
int  FindOffsetForChunk(struct HPool *heap, PVOID memoryPointer); //quickly match a (heap, chunkAddress) into an offset in heap.chunks

