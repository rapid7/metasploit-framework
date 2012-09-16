#ifndef _METERPRETER_LIB_THREAD_H
#define _METERPRETER_LIB_THREAD_H

#ifdef _WIN32

/*****************************************************************************************/
// Win32/64 specific definitions...

typedef struct __UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} _UNICODE_STRING, * _PUNICODE_STRING;

typedef struct __OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	_PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} _OBJECT_ATTRIBUTES, * _POBJECT_ATTRIBUTES;

typedef struct __CLIENT_ID
{
  PVOID UniqueProcess;
  PVOID UniqueThread;
} _CLIENT_ID, * _PCLIENT_ID;

typedef HANDLE (WINAPI * OPENTHREAD)( DWORD, BOOL, DWORD ); // kernel32!OpenThread

typedef DWORD (WINAPI * NTOPENTHREAD)( PHANDLE, ACCESS_MASK, _POBJECT_ATTRIBUTES, _PCLIENT_ID ); // ntdll!NtOpenThread

/*****************************************************************************************/

#else
#include "pthread.h"

/*
 *  are we running on a linux 2.4 kernel ?
 * if this is the case, as we're using pthread, a "few" things might not work
 * pthread_join will return immediately (sys_futex3 returns immediately as there's no support for futex in 2.4 kernels)
 * terminated threads end up as zombies in the system, we need to reap them
 * ...
 * empiric way observed during testing : if getpid() == getppid(), we're on a 2.4 kernel (didn't happen during testing on a 2.6/3.x kernel)
 */

extern int is_kernel_24;
extern pthread_t reaper_tid;

typedef struct pthread_internal_t
{
    struct pthread_internal_t*  next;
    struct pthread_internal_t** pref;
    pthread_attr_t              attr;
    pid_t                       kernel_id;
    pthread_cond_t              join_cond;
    int                         join_count;
    void*                       return_value;
    int                         intern;
    __pthread_cleanup_t*        cleanup_stack;
    void**                      tls;         /* thread-local storage area */
} pthread_internal_t;

#endif // _WIN32

typedef struct _LOCK
{
#ifdef _WIN32
	HANDLE handle;
#else
	pthread_mutex_t *handle;
#endif // _WIN32
} LOCK, * LPLOCK;

typedef struct _EVENT
{
	HANDLE handle;
} EVENT, * LPEVENT;

typedef struct _THREAD
{
	DWORD id;
	HANDLE handle;
	EVENT * sigterm;
	LPVOID parameter1;
	LPVOID parameter2;
#ifndef _WIN32 
	void *suspend_thread_data;
	pthread_t pid;
	int thread_started;
#endif
} THREAD, * LPTHREAD;

#ifdef __GNUC__
#define THREADCALL __attribute__((stdcall))
#else // ! gcc
#define THREADCALL __stdcall
#endif

typedef DWORD (THREADCALL * THREADFUNK)( THREAD * thread );

/*****************************************************************************************/

LOCK * lock_create( VOID );

VOID lock_destroy( LOCK * lock );

VOID lock_acquire( LOCK * lock );

VOID lock_release( LOCK * lock );

/*****************************************************************************************/

EVENT * event_create( VOID );

BOOL event_destroy( EVENT * event );

BOOL event_signal( EVENT * event );

BOOL event_poll( EVENT * event, DWORD timeout );

/*****************************************************************************************/

THREAD * thread_open( VOID );

THREAD * thread_create( THREADFUNK funk, LPVOID param1, LPVOID param2 );

BOOL thread_run( THREAD * thread );

BOOL thread_sigterm( THREAD * thread );

BOOL thread_kill( THREAD * thread );

BOOL thread_join( THREAD * thread );

BOOL thread_destroy( THREAD * thread );

/*****************************************************************************************/

#endif
