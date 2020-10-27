#ifndef __PRIORITY_QUEUE_H__
#define __PRIORITY_QUEUE_H__

#include "vector.h"

/* Priority queue
 * Priority queues are designed such that its first element is always the greatest of the elements it contains.
 * This context is similar to a heap, where elements can be inserted at any moment, and only the max heap element can be
 * retrieved (the one at the top in the priority queue).
 * Priority queues are implemented as Vectors. Elements are popped from the "back" of Vector, which is known as the top
 * of the priority queue.
 */
typedef struct {
    Vector *v;

    int (*cmp)(void *, void *);
} PriorityQueue;

/* Construct priority queue
 * Constructs a priority_queue container adaptor object.
 */
PriorityQueue *__newPriorityQueueSize(size_t elemSize, size_t cap, int (*cmp)(void *, void *));

#define NewPriorityQueue(type, cap, cmp) __newPriorityQueueSize(sizeof(type), cap, cmp)

/* Return size
 * Returns the number of elements in the priority_queue.
 */
size_t Priority_Queue_Size(PriorityQueue *pq);

/* Access top element
 * Copy the top element in the priority_queue to ptr.
 * The top element is the element that compares higher in the priority_queue.
 */
int Priority_Queue_Top(PriorityQueue *pq, void *ptr);

/* Insert element
 * Inserts a new element in the priority_queue.
 */
size_t __priority_Queue_PushPtr(PriorityQueue *pq, void *elem);

#define Priority_Queue_Push(pq, elem) __priority_Queue_PushPtr(pq, &(typeof(elem)){elem})

/* Remove top element
 * Removes the element on top of the priority_queue, effectively reducing its size by one. The element removed is the
 * one with the highest value.
 * The value of this element can be retrieved before being popped by calling Priority_Queue_Top.
 */
void Priority_Queue_Pop(PriorityQueue *pq);

/* free the priority queue and the underlying data. Does not release its elements if
 * they are pointers */
void Priority_Queue_Free(PriorityQueue *pq);

#endif //__PRIORITY_QUEUE_H__
