#include "byakugan.h"
#include "heapStructs.h"

// Get offset into the hash map
ULONG hash(PVOID addr, struct HPool *heap) {
    ULONG   offset;

    // assume 8 bit alignment, and use the golden ratio of 2^32
    offset  = (((ULONG) addr >> 3) * (2654435761)) % (0x007fffff/8);
    //dprintf("[XXX] Hashed to bucket %d\n", offset);

    return (offset);
}

/*
 * added by jc. I need to be able to find the offset of a chunk inide the chunks array quickly.
 * returns < 0 on error.
 */
int FindOffsetForChunk(struct HPool *heap, PVOID memoryPointer)
{
    ULONG                   i;

    i = hash(memoryPointer, heap);
    i = heap->map[i];
    while (i != NULLNODE) {
        if (CHUNK(i).addr == memoryPointer)
            return (i);
        i = CHUNK(i).nextBucket;
    }
    return (NULLNODE); // error
}

ULONG insertBucket(ULONG newC, struct HPool *heap, ULONG inAfter) {
    ULONG   offset, lastNum, checkNum;

    heap->numChunks++;
    CHUNK(newC).inUse       = TRUE;

    // Set up nextInUse list
	if (inAfter == NULLNODE) {
		if (heap->inUseHead == NULLNODE) heap->inUseHead = newC;
		else CHUNK(heap->lastInUse).nextInUse = newC;
		heap->lastInUse = newC;
		CHUNK(newC).nextInUse = NULLNODE;
		//dprintf("[T] Inserting new chunk %d at the end\n", newC);
	} else {
		//dprintf("[T] Inserting new chunk %d after chunk %d\n", newC, inAfter);
		if (heap->lastInUse == inAfter) heap->lastInUse = newC;
		CHUNK(newC).nextInUse = CHUNK(inAfter).nextInUse;
		CHUNK(inAfter).nextInUse = newC;
	}

    offset = hash(CHUNK(newC).addr, heap);

    if (heap->map[offset] == NULLNODE) {
        heap->map[offset] = newC;
        CHUNK(newC).nextBucket = NULLNODE;
    } else {
        offset = heap->map[offset];
        while (CHUNK(offset).nextBucket != NULLNODE)
            offset = CHUNK(offset).nextBucket;
        CHUNK(newC).nextBucket  = NULLNODE;
        CHUNK(offset).nextBucket = newC;
    }
    return (newC);
}

void removeBucket(PVOID addr, struct HPool *heap) {
    ULONG   offset, chunkNum, last = NULLNODE;

    if (heap == NULL)
        return;
	

    offset 		= hash(addr, heap);
	chunkNum 	= heap->map[offset];

    // Find our bucket and the bucket before it
    while (chunkNum != NULLNODE && CHUNK(chunkNum).addr != addr) {
        last = chunkNum;
        chunkNum = CHUNK(chunkNum).nextBucket;
    }

    // remove our bucket from the list if we found it
    if (chunkNum != NULLNODE) {
		//dprintf("[T] Deleting node %d\n", chunkNum);
    	CHUNK(chunkNum).inUse       = FALSE;
        
		if (last == NULLNODE)
            heap->map[offset] = NULLNODE;
        else
            CHUNK(last).nextBucket = CHUNK(chunkNum).nextBucket;
		
		heap->numChunks--;
    } else 
		dprintf("[T] Couldnt find chunk 0x%08x to delete :(\n", addr);


	// Head of the list case
	chunkNum = heap->inUseHead;
	if (CHUNK(chunkNum).addr == addr) {
		heap->inUseHead = CHUNK(chunkNum).nextInUse;
		return;
	}

	// search the list for the previous chunk
	while (chunkNum != NULLNODE && CHUNK(chunkNum).addr != addr) {
			last = chunkNum;
			chunkNum = CHUNK(chunkNum).nextInUse;
	}
	if (chunkNum != NULLNODE) {
		CHUNK(last).nextInUse = CHUNK(chunkNum).nextInUse;
		if (heap->lastInUse == chunkNum) heap->lastInUse = last;
	}
}

void initializeHeapModel(struct HeapState *heapModel) {
	
	memset(heapModel+1, 0, sizeof (struct HeapState));
	heapModel->hPoolListLen = 16;
	heapModel->heaps = (struct HPool *) calloc(heapModel->hPoolListLen, sizeof (struct HPool));
}

void logAllocate(struct HeapState *heapModel, struct AllocateStruct *aStruct) {
}

void logReallocate(struct HeapState *heapModel, struct ReallocateStruct *rStruct) {
}

void logFree(struct HeapState *heapModel, struct FreeStruct *fStruct) {
}

void heapAllocate(struct HeapState *heapModel, struct AllocateStruct *aStruct) {
	struct	HPool		*myHeap;
	struct	HeapChunk	*myChunk, *remainder;

	if (aStruct->heapHandle == 0 || aStruct->ret == 0)
		return;

	myHeap	= getHeap(heapModel, aStruct->heapHandle);
	myChunk = getChunk(myHeap, aStruct->ret, NULLNODE);
	
	if (myChunk == NULL)
		return;

	if (myChunk->size > aStruct->size + SPACEBETWEEN) {
		//dprintf("[T] Splitting chunk at 0x%08x:\n", aStruct->ret);
		//dprintf("\tNew Chunk 0x%08x, size %d bytes, after chunk %u\n",
		//		((ULONG) aStruct->ret + aStruct->size + SPACEBETWEEN),
		//		(myChunk->size - aStruct->size - SPACEBETWEEN),
		//		FindOffsetForChunk(myHeap, myChunk->addr));
		remainder		=	getChunk(myHeap, 
							(PVOID) ((ULONG) aStruct->ret + aStruct->size + SPACEBETWEEN), 
							FindOffsetForChunk(myHeap, myChunk->addr));
		remainder->size = (myChunk->size - aStruct->size) - SPACEBETWEEN;
		remainder->free = TRUE;
	}
	
	myChunk->size		= aStruct->size;
	myChunk->flags		= aStruct->flags;
	myChunk->free		= FALSE;
}

void heapReallocate(struct HeapState *heapModel, struct ReallocateStruct *rStruct) {
    struct  HPool   *myHeap; 
	struct	HeapChunk	*oChunk, *nChunk, *remainder;
	    
    if (rStruct->heapHandle == 0 || rStruct->ret == 0)
        return;

	myHeap = getHeap(heapModel, rStruct->heapHandle);
	nChunk = getChunk(myHeap, rStruct->ret, NULLNODE);
	if (nChunk == NULL)
		return;

	if (rStruct->ret != rStruct->memoryPointer && rStruct->memoryPointer != 0) {
		oChunk = getChunk(myHeap, rStruct->memoryPointer, NULLNODE);
		if (oChunk != NULL)
			oChunk->free = TRUE;
	}

	// Split new chunk on realloc move if necessary
    if (nChunk->size > rStruct->size + SPACEBETWEEN) {
        remainder       =   getChunk(myHeap,
                            (PVOID) ((ULONG) rStruct->ret + rStruct->size + SPACEBETWEEN),
							FindOffsetForChunk(myHeap, nChunk->addr));
        remainder->size = (nChunk->size - rStruct->size) - SPACEBETWEEN;
        remainder->free = TRUE;
    }

	nChunk->size	= rStruct->size;
	nChunk->flags	= rStruct->flags;
	nChunk->free	= FALSE;
}

void heapFree(struct HeapState *heapModel, struct FreeStruct *fStruct) {
    struct  HPool   *myHeap; 
	struct	HeapChunk	*myChunk;
	
	//dprintf("[XXX] Freeing 0x%08x\n", fStruct->memoryPointer);

	if (fStruct->heapHandle == 0 || fStruct->memoryPointer == 0x00000000) { 
		// So many of these that it slows us down :(
		//dprintf("[T] Program attempted to free a NULL pointer.\n\n");
		return;
	}
	myHeap	= getHeap(heapModel, fStruct->heapHandle);
	myChunk	= getChunk(myHeap, fStruct->memoryPointer, NULLNODE);
	if (myChunk == NULL)
		return; // dupe free :(

	#if 0
	if (myChunk->free == 2)
		dprintf("[T] Possible 'double free' of chunk @ 0x%08x:0x%x\n\n", 
				myChunk->addr, myChunk->free);
	#endif

	myChunk->flags	= fStruct->flags;
	myChunk->free	+= 1;
}

void heapCreate(struct HeapState *heapModel, struct CreateStruct *cStruct) {
	struct HPool	*newHeap;
	ULONG			i;

    if (cStruct->base == 0)
		return;

	newHeap = getHeap(heapModel, cStruct->base);
    newHeap->commit		= cStruct->commit;
    newHeap->reserve	= cStruct->reserve;
    newHeap->lock		= cStruct->lock;
    newHeap->flags		= cStruct->flags;
}

void heapDestroy(struct HeapState *heapModel, struct DestroyStruct *dStruct) {
	// Only place we mark heaps as not in use
	struct HPool	*deadHeap;

	if (dStruct->heapHandle == 0)
		return;

	deadHeap = getHeap(heapModel, dStruct->heapHandle);
	free(deadHeap->chunks);
	memset(deadHeap, 0, sizeof(struct HPool));
	heapModel->numHeaps--;
}

void heapCoalesce(struct HeapState *heapModel, struct CoalesceStruct *cfbStruct) {
	// Only place we mark chunks as not in use
	ULONG                   i, j, latest, last, offset;
	struct HPool			*heap;

	if (heapModel->numHeaps == 0)
		return;

	// Get the heap handle from the CoalesceStruct
	heap = getHeap(heapModel, cfbStruct->heapHandle);

	if (heap->numChunks < 2)
		return;
 
	//dprintf("[T] Attempting to coalese heap 0x%08x...\n", cfbStruct->heapHandle);
	
	i = heap->inUseHead;

	//dprintf("[T] Starting with chunk %d at 0x%08x\n", i, CHUNK(i).addr);

	// Walk the list Coalescing consecutive free chunks
	// This assumes that two chunks in a row are actually consecutive...
	// This is wrong. If I alloc two large blocks, free the first, then alloc
	// a small one, then free the small one and the second one, then coalesce
	// the result will ignore the space in between, so we need to take addresses
	// into account, and/or we need to create free spaceholder chunks when creating
	// chunks in a smaller space than is currently existing.
	while (i != NULLNODE) {
		if (CHUNK(i).free) {
			//dprintf("[T] Found free chunk %d at 0x%08x\n", i, CHUNK(i).addr);
			j = FindOffsetForChunk(heap, NEXTADDR(i));
			while (j != NULLNODE && CHUNK(j).free) {

				//dprintf("[T] Found free chunk %d at 0x%08x\n", j, CHUNK(j).addr);
				
				// XXX Handle this by address for unknown chunks
				CHUNK(i).size += CHUNK(j).size + SPACEBETWEEN;	// This is only right on Vista... and only
															// most of the time - win2k is insane and 
															// goes backwards :(
				
				// fix up hash bucket list
				removeBucket(CHUNK(j).addr, heap);

				//dprintf("[T] Coalescing 0x%08x and 0x%08x. New size: %d bytes\n",
				//CHUNK(i).addr, CHUNK(j).addr, CHUNK(i).size);
				
				j = FindOffsetForChunk(heap, NEXTADDR(i));
			}
		} 
       	i = CHUNK(i).nextInUse;
		// Check Address ordering
		// If out of order, quicksort then start this loop again
		// from first in use 
    }

}

struct HPool *getHeap(struct HeapState *heapModel, PVOID heapHandle) {
	ULONG					i;
	struct HPool			*newHeap = NULL;

	for (i = 0; i < heapModel->hPoolListLen; i++) {
		if ((heapModel->heaps[i]).base == heapHandle)
			return (&(heapModel->heaps[i]));
		if (heapModel->numHeaps == heapModel->hPoolListLen)	// Add some short circuits here
			continue;
		if (newHeap != NULL)
			continue;
		if ((heapModel->heaps[i]).inUse == FALSE)
			newHeap = &(heapModel->heaps[i]);
	}

	// If we get here we haven't found a heap, so lets make one
	//dprintf("[T] Creating entry for heap: 0x%08x\n", heapHandle);

	if (newHeap == NULL) {
		heapModel->hPoolListLen = heapModel->hPoolListLen * 2;
		newHeap    = heapModel->heaps;
		heapModel->heaps = (struct HPool *) realloc(heapModel->heaps,
				            heapModel->hPoolListLen * sizeof(struct HPool));
		if (heapModel->heaps == NULL) {
            heapModel->heaps = newHeap;
            //crushModel(heapModel);    ADD ME XXX
			#ifndef THREEDHEAPFU_ENABLED
            dprintf("[T] OOM getting new heaps!\n\n");
			#endif
            return (NULL);
        }
		newHeap = &(heapModel->heaps[heapModel->numHeaps]);
		// Clean the newly allocated memory
		memset(newHeap, 0, (sizeof (struct HPool) * (heapModel->hPoolListLen - heapModel->numHeaps)));
	}

	heapModel->numHeaps++;
	newHeap->base			= heapHandle;
    newHeap->inUse			= TRUE;
	newHeap->chunkListLen	= 32;
	newHeap->chunks			= (struct HeapChunk *) calloc(newHeap->chunkListLen, 
								sizeof (struct HeapChunk));
	newHeap->map			= (ULONG *) malloc((0x007fffff/8) * sizeof (ULONG));
	memset(newHeap->map, 0xff, (0x007fffff/8) * sizeof (ULONG));
	newHeap->inUseHead = newHeap->lastInUse = NULLNODE;

	return (newHeap);
}

struct HeapChunk *getChunk(struct HPool *heap, PVOID memoryPointer, ULONG inAfter) {
	ULONG					i, *oldMap;
	struct HeapChunk		*newChunk, *niuChunk = NULL;

	i = hash(memoryPointer, heap);
	i = heap->map[i];
	while (i != NULLNODE) {
		if (CHUNK(i).addr == memoryPointer)
			return (&CHUNK(i));
		i = CHUNK(i).nextBucket;
	}

	if (niuChunk == NULL) {
		if (heap->numChunks < heap->chunkListLen) {
			if ((heap->chunks[heap->numChunks]).inUse == FALSE) {
				//dprintf("[XXX] FOUND CHUNK WHERE EXPECTED! :)\n\n");
				niuChunk = &(heap->chunks[heap->numChunks]);
    			niuChunk->addr			= memoryPointer;
				niuChunk->heapHandle	= heap->base;
				insertBucket(heap->numChunks, heap, inAfter);
				return (niuChunk);
			}
			// Heap has been coalesced and there are gaps
			// Work backwards in this case - should be MUCH faster
			// If this is noticably slow, we'll switch to a stack of unused chunks
			// (realloc stack with heap)
			for (i = 0; i < heap->chunkListLen;  i++) {
				if ((heap->chunks[i]).inUse == FALSE) {
					niuChunk = &(heap->chunks[i]);
    				niuChunk->addr  		= memoryPointer;
					niuChunk->heapHandle	= heap->base;
					insertBucket(i, heap, inAfter);
					return (niuChunk);
				}
			}
			dprintf("[XXX] Totally fucked up - chunk info doesnt jive with heap\n\n");
		}

		heap->chunkListLen = heap->chunkListLen * 2;
		niuChunk = heap->chunks;
		heap->chunks = (struct HeapChunk *) realloc(heap->chunks,
						heap->chunkListLen * sizeof (struct HeapChunk));
		
		if (heap->chunks == NULL) {
			heap->chunks = niuChunk;
			//crushHeap(heap);
			heap->chunkListLen = heap->chunkListLen/2;
			#ifndef THREEDHEAPFU_ENABLED
			dprintf("[T] OOM getting new chunks! %d -> %d\n\n",
					heap->chunkListLen, heap->chunkListLen*2);
			#endif
			return (NULL);
		}
        
		niuChunk = &(heap->chunks[heap->numChunks]);
		memset(niuChunk, 0, (sizeof (struct HeapChunk) * (heap->chunkListLen - heap->numChunks)));
	} 

	niuChunk->addr			= memoryPointer;
	niuChunk->heapHandle	= heap->base;
	insertBucket(heap->numChunks, heap, inAfter);
	return (niuChunk);
}
