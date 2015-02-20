typedef void VOID;
typedef unsigned __int8  UINT8;
typedef unsigned __int16 UINT16, WCHAR;
typedef __int32 LONG32;
typedef unsigned __int32 ULONG32;
typedef __int64 INT64;
typedef unsigned __int64 UINT64;

struct HEAPTABLE {
	struct _HEAP *list[16];
};

struct _LIST_ENTRY {
	struct _LIST_ENTRY *FLink;
	struct _LIST_ENTRY *BLink;
};

typedef struct _SLIST_HEADER {
	struct _SLIST_HEADER *Next;
	UINT16       Depth;
	UINT16       Sequence;
} SLIST_HEADER, *PSLIST_HEADER;

struct _SINGLE_LIST_ENTRY {
	struct _SINGLE_LIST_ENTRY *Next;
};


typedef struct _HEAP_ENTRY {
	VOID*        PreviousBlockPrivateData;
	UINT16       Size;
	UINT8        Flags;
	UINT8        SmallTagIndex;
	UINT16       PreviousSize;
	union
	{
		UINT8        SegmentOffset;
		UINT8        LFHFlags;
	};
	UINT8        UnusedBytes;
} HEAP_ENTRY, *PHEAP_ENTRY;

typedef struct _HEAP_COUNTERS
{
	ULONG32      TotalMemoryReserved;
	ULONG32      TotalMemoryCommitted;
	ULONG32      TotalMemoryLargeUCR;
	ULONG32      TotalSizeInVirtualBlocks;
	ULONG32      TotalSegments;
	ULONG32      TotalUCRs;
	ULONG32      CommittOps;
	ULONG32      DeCommitOps;
	ULONG32      LockAcquires;
	ULONG32      LockCollisions;
	ULONG32      CommitRate;
	ULONG32      DecommittRate;
	ULONG32      CommitFailures;
	ULONG32      InBlockCommitFailures;
	ULONG32      CompactHeapCalls;
	ULONG32      CompactedUCRs;
	ULONG32      AllocAndFreeOps;
	ULONG32      InBlockDeccommits;
	ULONG32      InBlockDeccomitSize;
	ULONG32      HighWatermarkSize;
	ULONG32      LastPolledSize;
} HEAP_COUNTERS, *PHEAP_COUNTERS;

typedef struct _HEAP_TUNING_PARAMETERS
{
	ULONG32      CommittThresholdShift;
	ULONG32      MaxPreCommittThreshold;
} HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS;

typedef struct _HEAP_SEGMENT
{
	struct _HEAP_ENTRY Entry;
	ULONG32      SegmentSignature;
	ULONG32      SegmentFlags;
	struct _LIST_ENTRY SegmentListEntry;
	struct _HEAP* Heap;
	VOID*        BaseAddress;
	ULONG32      NumberOfPages;
	struct _HEAP_ENTRY* FirstEntry;
	struct _HEAP_ENTRY* LastValidEntry;
	ULONG32      NumberOfUnCommittedPages;
	ULONG32      NumberOfUnCommittedRanges;
	UINT16       SegmentAllocatorBackTraceIndex;
	UINT16       Reserved;
	struct _LIST_ENTRY UCRSegmentList;
} HEAP_SEGMENT, *PHEAP_SEGMENT;

typedef struct _HEAP
{
	struct _HEAP_SEGMENT Segment;
	ULONG32      Flags;
	ULONG32      ForceFlags;
	ULONG32      CompatibilityFlags;
	ULONG32      EncodeFlagMask;
	struct _HEAP_ENTRY Encoding;
	ULONG32      PointerKey;
	ULONG32      Interceptor;
	ULONG32      VirtualMemoryThreshold;
	ULONG32      Signature;
	ULONG32      SegmentReserve;
	ULONG32      SegmentCommit;
	ULONG32      DeCommitFreeBlockThreshold;
	ULONG32      DeCommitTotalFreeThreshold;
	ULONG32      TotalFreeSize;
	ULONG32      MaximumAllocationSize;
	UINT16       ProcessHeapsListIndex;
	UINT16       HeaderValidateLength;
	VOID*        HeaderValidateCopy;
	UINT16       NextAvailableTagIndex;
	UINT16       MaximumTagIndex;
	struct _HEAP_TAG_ENTRY* TagEntries;
	struct _LIST_ENTRY UCRList;
	ULONG32      AlignRound;
	ULONG32      AlignMask;
	struct _LIST_ENTRY VirtualAllocdBlocks;
	struct _LIST_ENTRY SegmentList;
	UINT16       AllocatorBackTraceIndex;
	UINT8        _PADDING0_[0x2];
	ULONG32      NonDedicatedListLength;
	VOID*        BlocksIndex;
	VOID*        UCRIndex;
	struct _HEAP_PSEUDO_TAG_ENTRY* PseudoTagEntries;
	struct _LIST_ENTRY FreeLists;
	struct _HEAP_LOCK* LockVariable;
	VOID* CommitRoutine;
	VOID*        FrontEndHeap;
	UINT16       FrontHeapLockCount;
	UINT8        FrontEndHeapType;
	UINT8        _PADDING1_[0x1];
	struct _HEAP_COUNTERS Counters;
	struct _HEAP_TUNING_PARAMETERS TuningParameters;
} HEAP, *PHEAP;

typedef struct _HEAP_ENTRY_EXTRA
{
	union
	{
		struct
		{
			UINT16       AllocatorBackTraceIndex;
			UINT16       TagIndex;
			ULONG32      Settable;
		};
		UINT64       ZeroInit;
	};
} HEAP_ENTRY_EXTRA, *PHEAP_ENTRY_EXTRA;

typedef struct _HEAP_FREE_ENTRY
{
	struct _HEAP_ENTRY Entry;
	struct _LIST_ENTRY FreeList;
} HEAP_FREE_ENTRY, *PHEAP_FREE_ENTRY;

typedef struct _HEAP_LIST_LOOKUP
{
	struct _HEAP_LIST_LOOKUP* ExtendedLookup;
	ULONG32      ArraySize;
	ULONG32      ExtraItem;
	ULONG32      ItemCount;
	ULONG32      OutOfRangeItems;
	ULONG32      BaseIndex;
	struct _LIST_ENTRY* ListHead;
	ULONG32*     ListsInUseUlong;
	struct _LIST_ENTRY** ListHints;
} HEAP_LIST_LOOKUP, *PHEAP_LIST_LOOKUP;

typedef struct _HEAP_LOOKASIDE
{
	struct _SLIST_HEADER ListHead;
	UINT16       Depth;
	UINT16       MaximumDepth;
	ULONG32      TotalAllocates;
	ULONG32      AllocateMisses;
	ULONG32      TotalFrees;
	ULONG32      FreeMisses;
	ULONG32      LastTotalAllocates;
	ULONG32      LastAllocateMisses;
	ULONG32      Counters[2];
	UINT8        _PADDING0_[0x4];
} HEAP_LOOKASIDE, *PHEAP_LOOKASIDE;

typedef struct _INTERLOCK_SEQ
{
	union
	{
		struct
		{
			UINT16       Depth;
			UINT16       FreeEntryOffset;
			UINT8        _PADDING0_[0x4];
		};
		struct
		{
			ULONG32      OffsetAndDepth;
			ULONG32      Sequence;
		};
		INT64        Exchg;
	};
}INTERLOCK_SEQ, *PINTERLOCK_SEQ;

typedef struct _HEAP_TAG_ENTRY
{
	ULONG32      Allocs;
	ULONG32      Frees;
	ULONG32      Size;
	UINT16       TagIndex;
	UINT16       CreatorBackTraceIndex;
	WCHAR        TagName[24];
} HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY;

typedef struct _HEAP_UCR_DESCRIPTOR
{
	struct _LIST_ENTRY ListEntry;
	struct _LIST_ENTRY SegmentEntry;
	VOID*        Address;
	ULONG32      Size;
} HEAP_UCR_DESCRIPTOR, *PHEAP_UCR_DESCRIPTOR;

typedef struct _HEAP_USERDATA_HEADER
{
	union
	{
		struct _SINGLE_LIST_ENTRY SFreeListEntry;
		struct _HEAP_SUBSEGMENT* SubSegment;
	};
	VOID*        Reserved;
	ULONG32      SizeIndex;
	ULONG32      Signature;
} HEAP_USERDATA_HEADER, *PHEAP_USERDATA_HEADER;

typedef struct _HEAP_VIRTUAL_ALLOC_ENTRY
{
	struct _LIST_ENTRY Entry;
	struct _HEAP_ENTRY_EXTRA ExtraStuff;
	ULONG32      CommitSize;
	ULONG32      ReserveSize;
	struct _HEAP_ENTRY BusyBlock;
} HEAP_VIRTUAL_ALLOC_ENTRY, *PHEAP_VIRTUAL_ALLOC_ENTRY;

struct _USER_MEMORY_CACHE_ENTRY {
	ULONG32 Foo[4];
};
struct _HEAP_BUCKET {
	ULONG32 Foo;
};
struct _HEAP_BUCKET_COUNTERS {
	ULONG32 Foo[2];
};

typedef struct _HEAP_LOCAL_SEGMENT_INFO
{
	struct _HEAP_SUBSEGMENT* Hint;
	struct _HEAP_SUBSEGMENT* ActiveSubsegment;
	struct _HEAP_SUBSEGMENT* CachedItems[16];
	struct _SLIST_HEADER SListHeader;
	struct _HEAP_BUCKET_COUNTERS Counters;
	struct _HEAP_LOCAL_DATA* LocalData;
	ULONG32 LastOpSequence;
	UINT16 BucketIndex;
	UINT16 LastUsed;
	ULONG32 Pad;
} HEAP_LOCAL_SEGMENT_INFO, *PHEAP_LOCAL_SEGMENT_INFO;

typedef struct _HEAP_LOCAL_DATA {
	struct _SLIST_HEADER DeletedSubSegments;
	struct _LFH_BLOCK_ZONE* CrtZone;
	struct _LFH_HEAP* LowFragHeap;
	ULONG32 Sequence;
	struct _HEAP_LOCAL_SEGMENT_INFO SegmentInfo[128];
} HEAP_LOCAL_DATA;

typedef struct _HEAP_SUBSEGMENT
{
	struct _HEAP_LOCAL_SEGMENT_INFO* LocalInfo;
	struct _HEAP_USERDATA_HEADER* UserBlocks;
	struct _INTERLOCK_SEQ AggregateExchg;
	UINT16       BlockSize;
	UINT16       Flags;
	UINT16       BlockCount;
	UINT8        SizeIndex;
	UINT8        AffinityIndex;
	struct _SINGLE_LIST_ENTRY SFreeListEntry;
	ULONG32      Lock;
} HEAP_SUBSEGMENT, *PHEAP_SUBSEGMENT;

typedef struct _LFH_HEAP
{
	ULONG32 Lock[6];
	struct _LIST_ENTRY SubSegmentZones;
	ULONG32 ZoneBlockSize;
	VOID* Heap;
	ULONG32 SegmentChange;
	ULONG32 SegmentCreate;
	ULONG32 SegmentInsertInFree;
	ULONG32 SegmentDelete;
	ULONG32 CacheAllocs;
	ULONG32 CacheFrees;
	ULONG32 SizeInCache;
	ULONG32 RunInfo[3];
	struct _USER_MEMORY_CACHE_ENTRY UserBlockCache[12];
	struct _HEAP_BUCKET Buckets[128];
	struct _HEAP_LOCAL_DATA LocalData[1];
} LFH_HEAP;
