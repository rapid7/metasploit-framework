#include "priority_queue.h"
#include "heap.h"

PriorityQueue *__newPriorityQueueSize(size_t elemSize, size_t cap, int (*cmp)(void *, void *)) {
    PriorityQueue *pq = malloc(sizeof(PriorityQueue));
    pq->v = __newVectorSize(elemSize, cap);
    pq->cmp = cmp;
    return pq;
}

inline size_t Priority_Queue_Size(PriorityQueue *pq) {
    return Vector_Size(pq->v);
}

inline int Priority_Queue_Top(PriorityQueue *pq, void *ptr) {
    return Vector_Get(pq->v, 0, ptr);
}

inline size_t __priority_Queue_PushPtr(PriorityQueue *pq, void *elem) {
    size_t top = __vector_PushPtr(pq->v, elem);
    Heap_Push(pq->v, 0, top, pq->cmp);
    return top;
}

inline void Priority_Queue_Pop(PriorityQueue *pq) {
    if (pq->v->top == 0) {
        return;
    }
    Heap_Pop(pq->v, 0, pq->v->top, pq->cmp);
    pq->v->top--;
}

void Priority_Queue_Free(PriorityQueue *pq) {
    Vector_Free(pq->v);
    free(pq);
}
