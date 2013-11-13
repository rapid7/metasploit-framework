typedef void VOID;
typedef unsigned __int8  UINT8;
typedef unsigned __int16 UINT16;
typedef __int32 LONG32;
typedef unsigned __int32 ULONG32;
typedef unsigned __int64 UINT64;

// pseudo struct, for the PEB heap list
struct HEAPTABLE {
	struct _HEAP *list[16];
};

struct _LIST_ENTRY {
	struct _LIST_ENTRY *FLink;
	struct _LIST_ENTRY *BLink;
};

union _SLIST_HEADER {
	struct _LIST_ENTRY le;
};

typedef struct _HEAP_ENTRY             // 7 elements, 0x8 bytes (sizeof)
{
//              union                              // 2 elements, 0x4 bytes (sizeof)
//              {
//                  struct                         // 2 elements, 0x4 bytes (sizeof)
//                  {
/*0x000*/             UINT16       Size;
/*0x002*/             UINT16       PreviousSize;
//                  };
///*0x000*/         VOID*        SubSegmentCode;
//              };
/*0x004*/     UINT8        SmallTagIndex;
/*0x005*/     UINT8        Flags;
/*0x006*/     UINT8        UnusedBytes;
/*0x007*/     UINT8        SegmentIndex;
}HEAP_ENTRY, *PHEAP_ENTRY;

typedef struct _HEAP                                         // 36 elements, 0x588 bytes (sizeof)
{
/*0x000*/     struct _HEAP_ENTRY Entry;                                // 7 elements, 0x8 bytes (sizeof)
/*0x008*/     ULONG32      Signature;
/*0x00C*/     ULONG32      Flags;
/*0x010*/     ULONG32      ForceFlags;
/*0x014*/     ULONG32      VirtualMemoryThreshold;
/*0x018*/     ULONG32      SegmentReserve;
/*0x01C*/     ULONG32      SegmentCommit;
/*0x020*/     ULONG32      DeCommitFreeBlockThreshold;
/*0x024*/     ULONG32      DeCommitTotalFreeThreshold;
/*0x028*/     ULONG32      TotalFreeSize;
/*0x02C*/     ULONG32      MaximumAllocationSize;
/*0x030*/     UINT16       ProcessHeapsListIndex;
/*0x032*/     UINT16       HeaderValidateLength;
/*0x034*/     VOID*        HeaderValidateCopy;
/*0x038*/     UINT16       NextAvailableTagIndex;
/*0x03A*/     UINT16       MaximumTagIndex;
/*0x03C*/     struct _HEAP_TAG_ENTRY* TagEntries;
/*0x040*/     struct _HEAP_UCR_SEGMENT* UCRSegments;
/*0x044*/     struct _HEAP_UNCOMMMTTED_RANGE* UnusedUnCommittedRanges;
/*0x048*/     ULONG32      AlignRound;
/*0x04C*/     ULONG32      AlignMask;
/*0x050*/     struct _LIST_ENTRY VirtualAllocdBlocks;                  // 2 elements, 0x8 bytes (sizeof)
/*0x058*/     struct _HEAP_SEGMENT* Segments[64];
	union                                                    // 2 elements, 0x10 bytes (sizeof)
	{
/*0x158*/         ULONG32      FreeListsInUseUlong[4];
/*0x158*/         UINT8        FreeListsInUseBytes[16];
	}u;
	union                                                    // 2 elements, 0x2 bytes (sizeof)
	{
/*0x168*/         UINT16       FreeListsInUseTerminate;
/*0x168*/         UINT16       DecommitCount;
	}u2;
/*0x16A*/     UINT16       AllocatorBackTraceIndex;
/*0x16C*/     ULONG32      NonDedicatedListLength;
/*0x170*/     VOID*        LargeBlocksIndex;
/*0x174*/     struct _HEAP_PSEUDO_TAG_ENTRY* PseudoTagEntries;
/*0x178*/     struct _LIST_ENTRY FreeLists[128];
/*0x578*/     struct _HEAP_LOCK* LockVariable;
///*0x57C*/     FUNCT_0049_0C5F_CommitRoutine* CommitRoutine;
/*0x57C*/     VOID* CommitRoutine;
/*0x580*/     VOID*        FrontEndHeap;
/*0x584*/     UINT16       FrontHeapLockCount;
/*0x586*/     UINT8        FrontEndHeapType;
/*0x587*/     UINT8        LastSegmentIndex;
}HEAP, *PHEAP;

typedef struct _HEAP_UNCOMMMTTED_RANGE    // 4 elements, 0x10 bytes (sizeof)
{
/*0x000*/     struct _HEAP_UNCOMMMTTED_RANGE* Next;
/*0x004*/     ULONG32      Address;
/*0x008*/     ULONG32      Size;
/*0x00C*/     ULONG32      filler;
}HEAP_UNCOMMMTTED_RANGE, *PHEAP_UNCOMMMTTED_RANGE;

typedef struct _HEAP_ENTRY_EXTRA                  // 4 elements, 0x8 bytes (sizeof)
{
	union                                         // 2 elements, 0x8 bytes (sizeof)
	{
		struct                                    // 3 elements, 0x8 bytes (sizeof)
		{
/*0x000*/             UINT16       AllocatorBackTraceIndex;
/*0x002*/             UINT16       TagIndex;
/*0x004*/             ULONG32      Settable;
		};
/*0x000*/         UINT64       ZeroInit;
	};
}HEAP_ENTRY_EXTRA, *PHEAP_ENTRY_EXTRA;

typedef struct _HEAP_VIRTUAL_ALLOC_ENTRY // 5 elements, 0x20 bytes (sizeof)
{
/*0x000*/     struct _LIST_ENTRY Entry;            // 2 elements, 0x8 bytes (sizeof)
/*0x008*/     struct _HEAP_ENTRY_EXTRA ExtraStuff; // 4 elements, 0x8 bytes (sizeof)
/*0x010*/     ULONG32      CommitSize;
/*0x014*/     ULONG32      ReserveSize;
/*0x018*/     struct _HEAP_ENTRY BusyBlock;        // 7 elements, 0x8 bytes (sizeof)
}HEAP_VIRTUAL_ALLOC_ENTRY, *PHEAP_VIRTUAL_ALLOC_ENTRY;


typedef struct _HEAP_FREE_ENTRY        // 8 elements, 0x10 bytes (sizeof)
{
	union                              // 2 elements, 0x4 bytes (sizeof)
	{
		struct                         // 2 elements, 0x4 bytes (sizeof)
		{
/*0x000*/             UINT16       Size;
/*0x002*/             UINT16       PreviousSize;
		};
/*0x000*/         VOID*        SubSegmentCode;
	};
/*0x004*/     UINT8        SmallTagIndex;
/*0x005*/     UINT8        Flags;
/*0x006*/     UINT8        UnusedBytes;
/*0x007*/     UINT8        SegmentIndex;
/*0x008*/     struct _LIST_ENTRY FreeList;       // 2 elements, 0x8 bytes (sizeof)
}HEAP_FREE_ENTRY, *PHEAP_FREE_ENTRY;

typedef struct _HEAP_LOOKASIDE       // 10 elements, 0x30 bytes (sizeof)
{
/*0x000*/     union _SLIST_HEADER ListHead;    // 4 elements, 0x8 bytes (sizeof)
/*0x008*/     UINT16       Depth;
/*0x00A*/     UINT16       MaximumDepth;
/*0x00C*/     ULONG32      TotalAllocates;
/*0x010*/     ULONG32      AllocateMisses;
/*0x014*/     ULONG32      TotalFrees;
/*0x018*/     ULONG32      FreeMisses;
/*0x01C*/     ULONG32      LastTotalAllocates;
/*0x020*/     ULONG32      LastAllocateMisses;
/*0x024*/     ULONG32      Counters[2];
/*0x02C*/     UINT8        _PADDING0_[0x4];
}HEAP_LOOKASIDE, *PHEAP_LOOKASIDE;

struct FRONTEND1 {
	struct _HEAP_LOOKASIDE l[128];
};

typedef struct _HEAP_SEGMENT                           // 15 elements, 0x3C bytes (sizeof)
{
/*0x000*/     struct _HEAP_ENTRY Entry;                          // 7 elements, 0x8 bytes (sizeof)
/*0x008*/     ULONG32      Signature;
/*0x00C*/     ULONG32      Flags;
/*0x010*/     struct _HEAP* Heap;
/*0x014*/     ULONG32      LargestUnCommittedRange;
/*0x018*/     VOID*        BaseAddress;
/*0x01C*/     ULONG32      NumberOfPages;
/*0x020*/     struct _HEAP_ENTRY* FirstEntry;
/*0x024*/     struct _HEAP_ENTRY* LastValidEntry;
/*0x028*/     ULONG32      NumberOfUnCommittedPages;
/*0x02C*/     ULONG32      NumberOfUnCommittedRanges;
/*0x030*/     struct _HEAP_UNCOMMMTTED_RANGE* UnCommittedRanges;
/*0x034*/     UINT16       AllocatorBackTraceIndex;
/*0x036*/     UINT16       Reserved;
/*0x038*/     struct _HEAP_ENTRY* LastEntryInSegment;
}HEAP_SEGMENT, *PHEAP_SEGMENT;
