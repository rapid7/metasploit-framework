#include "byakugan.h"
#include "heapStructs.h"

void initializeHeapModel(struct HeapState *heapModel) {
	
	memset(heapModel, 0, sizeof (struct HeapState));
	heapModel->hPoolListLen = 16;
	heapModel->heaps = (struct HPool *) calloc(heapModel->hPoolListLen, sizeof (struct HPool));
}

void heapAllocate(struct HeapState *heapModel, struct AllocateStruct *aStruct) {
	struct	HPool		*myHeap;
	struct	HeapChunk	*myChunk;

	if (aStruct->heapHandle == 0 || aStruct->ret == 0)
		return;

	myHeap	= getHeap(heapModel, aStruct->heapHandle);
	myChunk = getChunk(myHeap, aStruct->ret);
	
	if (myChunk == NULL)
		return;

	myChunk->size		= aStruct->size;
	myChunk->flags		= aStruct->flags;
	myChunk->free		= FALSE;
}

void heapReallocate(struct HeapState *heapModel, struct ReallocateStruct *rStruct) {
    struct  HPool   *myHeap; 
	struct	HeapChunk	*oChunk, *nChunk;
	    
    if (rStruct->heapHandle == 0 || rStruct->ret == 0)
        return;

	myHeap = getHeap(heapModel, rStruct->heapHandle);
	nChunk = getChunk(myHeap, rStruct->ret);
	if (nChunk == NULL)
		return;

	if (rStruct->ret != rStruct->memoryPointer && rStruct->memoryPointer != 0) {
		oChunk = getChunk(myHeap, rStruct->memoryPointer);
		if (oChunk != NULL)
			oChunk->free = TRUE;
	}

	nChunk->size	= rStruct->size;
	nChunk->flags	= rStruct->flags;
	nChunk->free	= FALSE;
}

void heapFree(struct HeapState *heapModel, struct FreeStruct *fStruct) {
    struct  HPool   *myHeap; 
	struct	HeapChunk	*myChunk;
	   
	if (fStruct->heapHandle == 0 || fStruct->memoryPointer == 0x00000000) { 
		// So many of these that it slows us down :(
		//dprintf("[T] Program attempted to free a NULL pointer.\n\n");
		return;
	}

	myHeap	= getHeap(heapModel, fStruct->heapHandle);
	myChunk	= getChunk(myHeap, fStruct->memoryPointer);
	if (myChunk == NULL)
		return;

	if (myChunk->free == TRUE)
		dprintf("[T] Possible 'double free' of chunk @ 0x%08x:0x%08x\n\n", 
				myChunk->addr, fStruct->memoryPointer);

	myChunk->flags	= fStruct->flags;
	myChunk->free	= TRUE;
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
            dprintf("[T] OOM getting new heaps!\n\n");
            return (NULL);
        }
		newHeap = &(heapModel->heaps[heapModel->numHeaps]);
		// Clean the newly allocated memory
		memset(newHeap, 0, (sizeof (struct HPool) * (heapModel->hPoolListLen - heapModel->numHeaps)));
	}

	heapModel->numHeaps++;
	newHeap->base			= heapHandle;
    newHeap->inUse			= TRUE;
	newHeap->chunkListLen	= 0x007fffff/8;
	newHeap->chunks			= (struct HeapChunk *) calloc(newHeap->chunkListLen, 
								sizeof (struct HeapChunk));

	return (newHeap);
}

// CRRRRAAAAZZYYY splay tree action on top of our chunk code...
// Many thanks to Sedgewick and Sleator :)
struct HeapChunk *splay(PVOID addr, struct HeapChunk *t) {
    struct HeapChunk N, *l, *r, *y;
    
	if (t == NULL) { 
		return (t);
	}
    memset(&N, 0, sizeof (HeapChunk));
	l = r = &N;

    for (;;) {
		if (addr < t->addr) {
			if (t->left == NULL) break;
			if (addr < (t->left)->addr) {
				y			= t->left; 
				t->left		= y->right; 
				y->right	= t; 
				t			= y;
				if (t->left == NULL) break;
			}
			r->left		= t; 
			r			= t; 
			t			= t->left;
		} else if (addr > t->addr) {
			if (t->right == NULL) break;
			if (addr > (t->right)->addr) {
				y			= t->right; 
				t->right	= y->left; 
				y->left		= t; 
				t			= y;
				if (t->right == NULL) break;
			}
			l->right	= t; 
			l			= t; 
			t			= t->right;
		} else {
				break;
		}
    }
    l->right	= t->left; 
	r->left		= t->right; 
	t->left		= N.right; 
	t->right	= N.left;
    
	return (t);
}

struct HeapChunk *insert(struct HeapChunk *newC, struct HPool *heap) {
/* Insert i into the tree t, unless it's already there.    */
/* Return a pointer to the resulting tree.                 */
	struct HeapChunk *t;

    heap->numChunks++;
    newC->inUse = TRUE;

	t = heap->t;
    if (t == NULL) {
		heap->t = newC;
        return (newC);
    }
    t = splay(newC->addr,t);
    if (newC->addr < t->addr) {
        newC->left = t->left;
        newC->right = t;
        t->left = NULL;
		heap->t = newC;
        return (newC);
    } else if (newC->addr > t->addr) {
        newC->right = t->right;
        newC->left = t;
        t->right = NULL;
		heap->t = newC;
        return (newC);
    } else { /* We get here if it's already in the tree */
             /* Don't add it again                      */
		dprintf("[XXX] WTF?? Inserting the same address twice!\nBase: 0x%08x\tAddr: 0x%08x:0x%08x\n\n",
				heap->base, newC->addr, t->addr);
        t->inUse = TRUE;
		heap->t = t;
		return (t);
    }
}


struct HeapChunk *getChunk(struct HPool *heap, PVOID memoryPointer) {
	ULONG					i;
	struct HeapChunk		*newChunk, *niuChunk = NULL;

// Old and slow - O(n)
#if 0
	for (i = 0; i < heap->chunkListLen; i++) {
		newChunk = &(heap->chunks[i]);
		if (newChunk->addr == memoryPointer)
			return (newChunk);
		if (heap->numChunks == heap->chunkListLen)
			continue;
		if (niuChunk != NULL)
			continue;
		if (newChunk->inUse == FALSE)
			niuChunk = newChunk;
	}

// New splayness - O(log n)
	newChunk = heap->t;
	i = 0;
	while (newChunk != NULL) {
		if (newChunk->addr == memoryPointer) {
			return (newChunk);
		}

		if (newChunk->inUse == FALSE) {
			dprintf("[XXX] Unused chunk in the tree!! L%d 0x%08x\n\n", 
					i, newChunk->addr);
			niuChunk = newChunk;
		}
		
		if (memoryPointer < newChunk->addr) {
			newChunk = newChunk->left;
			i++;
		} else {
			newChunk = newChunk->right;
			i++;
		}
	}
#endif
	heap->t = splay(memoryPointer, heap->t);
	if (heap->t != NULL && (heap->t)->addr == memoryPointer)
		return (heap->t);

	if (niuChunk == NULL) {
		if (heap->numChunks < heap->chunkListLen) {
			if ((heap->chunks[heap->numChunks]).inUse == FALSE) {
				//dprintf("[XXX] FOUND CHUNK WHERE EXPECTED! :)\n\n");
				niuChunk = &(heap->chunks[heap->numChunks]);
    			niuChunk->addr			= memoryPointer;
				niuChunk->heapHandle	= heap->base;
				insert(niuChunk, heap);
				return (niuChunk);
			}
			// Worst muddahfuggin case...
			dprintf("[XXX] Unused chunks should be at the END of the list!\n\n");
			for (i = 0; i < heap->chunkListLen; i++) {
				if ((heap->chunks[i]).inUse == FALSE) {
					niuChunk = &(heap->chunks[i]);
    				niuChunk->addr  		= memoryPointer;
					niuChunk->heapHandle	= heap->base;
					insert(niuChunk, heap);
					return (niuChunk);
				}
			}
		}

		heap->chunkListLen = heap->chunkListLen * 2;
		niuChunk = heap->chunks;
		heap->chunks = (struct HeapChunk *) realloc(heap->chunks,
						heap->chunkListLen * sizeof (struct HeapChunk));
		if (heap->chunks == NULL) {
			heap->chunks = niuChunk;
			//crushHeap(heap);
			heap->chunkListLen = heap->chunkListLen/2;
			dprintf("[T] OOM getting new chunks! %d -> %d\n\n",
					heap->chunkListLen, heap->chunkListLen*2);
			return (NULL);
		}
		niuChunk = &(heap->chunks[heap->numChunks]);
		memset(niuChunk, 0, (sizeof (struct HeapChunk) * (heap->chunkListLen - heap->numChunks)));
	} 

	niuChunk->addr			= memoryPointer;
	niuChunk->heapHandle	= heap->base;
	insert(niuChunk, heap);
	return (niuChunk);
}
