/* $OpenBSD: thread_private.h,v 1.18 2006/02/22 07:16:31 otto Exp $ */

/* PUBLIC DOMAIN: No Rights Reserved. Marco S Hyman <marc@snafu.org> */

#ifndef _THREAD_PRIVATE_H_
#define _THREAD_PRIVATE_H_

#include <pthread.h>

/*
 * This file defines the thread library interface to libc.  Thread
 * libraries must implement the functions described here for proper
 * inter-operation with libc.   libc contains weak versions of the
 * described functions for operation in a non-threaded environment.
 */

/*
 * This variable is 0 until a second thread is created.
 */
extern int __isthreaded;

/*
 * Weak symbols are used in libc so that the thread library can
 * efficiently wrap libc functions.
 * 
 * Use WEAK_NAME(n) to get a libc-private name for n (_weak_n),
 *     WEAK_ALIAS(n) to generate the weak symbol n pointing to _weak_n,
 *     WEAK_PROTOTYPE(n) to generate a prototype for _weak_n (based on n).
 */
#define WEAK_NAME(name)		__CONCAT(_weak_,name)
#define WEAK_ALIAS(name)	__weak_alias(name, WEAK_NAME(name))
#ifdef __GNUC__
#define WEAK_PROTOTYPE(name)	__typeof__(name) WEAK_NAME(name)
#else
#define WEAK_PROTOTYPE(name)	/* typeof() only in gcc */
#endif

/*
 * helper macro to make unique names in the thread namespace
 */
#define __THREAD_NAME(name)	__CONCAT(_thread_tagname_,name)

struct __thread_private_tag_t {
    pthread_mutex_t    _private_lock;
    pthread_key_t      _private_key;
};

#define _THREAD_PRIVATE_MUTEX(name)  \
	static struct __thread_private_tag_t  __THREAD_NAME(name) = { PTHREAD_MUTEX_INITIALIZER, -1 }
#define _THREAD_PRIVATE_MUTEX_LOCK(name)  \
	pthread_mutex_lock( &__THREAD_NAME(name)._private_lock )
#define _THREAD_PRIVATE_MUTEX_UNLOCK(name) \
	pthread_mutex_unlock( &__THREAD_NAME(name)._private_lock )

#define _THREAD_PRIVATE_KEY(name)    \
	static struct __thread_private_tag_t  __THREAD_NAME(name) = { PTHREAD_MUTEX_INITIALIZER, -1 }

extern void*  __bionic_thread_private_storage( struct __thread_private_tag_t*  ptag, void*  storage, size_t  objsize, void*  error );

#define _THREAD_PRIVATE(name, storage, error)    \
	__bionic_thread_private_storage( &__THREAD_NAME(name), &(storage),sizeof(storage), error)
	
#if 0
/*
 * helper functions that exist as (weak) null functions in libc and
 * (strong) functions in the thread library.   These functions:
 *
 * _thread_tag_lock:
 *	lock the mutex associated with the given tag.   If the given
 *	tag is NULL a tag is first allocated.
 *
 * _thread_tag_unlock:
 *	unlock the mutex associated with the given tag.   If the given
 *	tag is NULL a tag is first allocated.
 *
 * _thread_tag_storage:
 *	return a pointer to per thread instance of data associated
 *	with the given tag.  If the given tag is NULL a tag is first
 *	allocated.
 */
void	_thread_tag_lock(void **);
void	_thread_tag_unlock(void **);
void   *_thread_tag_storage(void **, void *, size_t, void *);

/*
 * Macros used in libc to access thread mutex, keys, and per thread storage.
 * _THREAD_PRIVATE_KEY and _THREAD_PRIVATE_MUTEX are different macros for
 * historical reasons.   They do the same thing, define a static variable
 * keyed by 'name' that identifies a mutex and a key to identify per thread
 * data.
 */
#define _THREAD_PRIVATE_KEY(name)					\
	static void *__THREAD_NAME(name)
#define _THREAD_PRIVATE_MUTEX(name)					\
	static void *__THREAD_NAME(name)
#define _THREAD_PRIVATE_MUTEX_LOCK(name)				\
	_thread_tag_lock(&(__THREAD_NAME(name)))
#define _THREAD_PRIVATE_MUTEX_UNLOCK(name)				\
	_thread_tag_unlock(&(__THREAD_NAME(name)))
#define _THREAD_PRIVATE(keyname, storage, error)			\
	_thread_tag_storage(&(__THREAD_NAME(keyname)), &(storage),	\
			    sizeof (storage), error)
/*
 * Resolver code is special cased in that it uses global keys.
 */
extern void *__THREAD_NAME(_res);
extern void *__THREAD_NAME(_res_ext);
extern void *__THREAD_NAME(serv_mutex);
#endif

/*
 * File descriptor locking definitions.
 */
#define FD_READ		0x1
#define FD_WRITE	0x2
#define FD_RDWR		(FD_READ | FD_WRITE)

struct timespec;
int	_thread_fd_lock(int, int, struct timespec *);
void	_thread_fd_unlock(int, int);

/*
 * Macros are used in libc code for historical (debug) reasons.
 * Define them here.
 */
#define _FD_LOCK(_fd,_type,_ts)	_thread_fd_lock(_fd, _type, _ts)
#define _FD_UNLOCK(_fd,_type)	_thread_fd_unlock(_fd, _type)


/*
 * malloc lock/unlock prototypes and definitions
 */
void	_thread_malloc_init(void);
void	_thread_malloc_lock(void);
void	_thread_malloc_unlock(void);

#define _MALLOC_LOCK()		do {					\
					if (__isthreaded)		\
						_thread_malloc_lock();	\
				} while (0)
#define _MALLOC_UNLOCK()	do {					\
					if (__isthreaded)		\
						_thread_malloc_unlock();\
				} while (0)
#define _MALLOC_LOCK_INIT()	do {					\
					if (__isthreaded)		\
						_thread_malloc_init();\
				} while (0)

void	_thread_atexit_lock(void);
void	_thread_atexit_unlock(void);

#define _ATEXIT_LOCK()		do {					\
					if (__isthreaded)		\
						_thread_atexit_lock();	\
				} while (0)
#define _ATEXIT_UNLOCK()	do {					\
					if (__isthreaded)		\
						_thread_atexit_unlock();\
				} while (0)

#endif /* _THREAD_PRIVATE_H_ */
