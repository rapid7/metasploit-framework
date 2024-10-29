#include "heap.h"

/* Byte-wise swap two items of size SIZE. */
#define SWAP(a, b, size)                      \
  do                                          \
    {                                         \
      register size_t __size = (size);        \
      register char *__a = (a), *__b = (b);   \
      do                                      \
        {                                     \
          char __tmp = *__a;                  \
          *__a++ = *__b;                      \
          *__b++ = __tmp;                     \
        } while (--__size > 0);               \
    } while (0)

inline char *__vector_GetPtr(Vector *v, size_t pos) {
    return v->data + (pos * v->elemSize);
}

void __sift_up(Vector *v, size_t first, size_t last, int (*cmp)(void *, void *)) {
    size_t len = last - first;
    if (len > 1) {
        len = (len - 2) / 2;
        size_t ptr = first + len;
        if (cmp(__vector_GetPtr(v, ptr), __vector_GetPtr(v, --last)) < 0) {
            char t[v->elemSize];
            memcpy(t, __vector_GetPtr(v, last), v->elemSize);
            do {
                memcpy(__vector_GetPtr(v, last), __vector_GetPtr(v, ptr), v->elemSize);
                last = ptr;
                if (len == 0)
                    break;
                len = (len - 1) / 2;
                ptr = first + len;
            } while (cmp(__vector_GetPtr(v, ptr), t) < 0);
            memcpy(__vector_GetPtr(v, last), t, v->elemSize);
        }
    }
}

void __sift_down(Vector *v, size_t first, size_t last, int (*cmp)(void *, void *), size_t start) {
    // left-child of __start is at 2 * __start + 1
    // right-child of __start is at 2 * __start + 2
    size_t len = last - first;
    size_t child = start - first;

    if (len < 2 || (len - 2) / 2 < child)
        return;

    child = 2 * child + 1;

    if ((child + 1) < len && cmp(__vector_GetPtr(v, first + child), __vector_GetPtr(v, first + child + 1)) < 0) {
        // right-child exists and is greater than left-child
        ++child;
    }

    // check if we are in heap-order
    if (cmp(__vector_GetPtr(v, first + child), __vector_GetPtr(v, start)) < 0)
        // we are, __start is larger than it's largest child
        return;

    char top[v->elemSize];
    memcpy(top, __vector_GetPtr(v, start), v->elemSize);
    do {
        // we are not in heap-order, swap the parent with it's largest child
        memcpy(__vector_GetPtr(v, start), __vector_GetPtr(v, first + child), v->elemSize);
        start = first + child;

        if ((len - 2) / 2 < child)
            break;

        // recompute the child based off of the updated parent
        child = 2 * child + 1;

        if ((child + 1) < len && cmp(__vector_GetPtr(v, first + child), __vector_GetPtr(v, first + child + 1)) < 0) {
            // right-child exists and is greater than left-child
            ++child;
        }

        // check if we are in heap-order
    } while (cmp(__vector_GetPtr(v, first + child), top) >= 0);
    memcpy(__vector_GetPtr(v, start), top, v->elemSize);
}


void Make_Heap(Vector *v, size_t first, size_t last, int (*cmp)(void *, void *)) {
    if (last - first > 1) {
        // start from the first parent, there is no need to consider children
        for (int start = (last - first - 2) / 2; start >= 0; --start) {
            __sift_down(v, first, last, cmp, first + start);
        }
    }
}


inline void Heap_Push(Vector *v, size_t first, size_t last, int (*cmp)(void *, void *)) {
    __sift_up(v, first, last, cmp);
}


inline void Heap_Pop(Vector *v, size_t first, size_t last, int (*cmp)(void *, void *)) {
    if (last - first > 1) {
        SWAP(__vector_GetPtr(v, first), __vector_GetPtr(v, --last), v->elemSize);
        __sift_down(v, first, last, cmp, first);
    }
}
