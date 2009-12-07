#ifndef _METERPRETER_LIB_THREAD_H
#define _METERPRETER_LIB_THREAD_H

/*****************************************************************************************/

typedef struct _LOCK
{
	HANDLE handle;
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
} THREAD, * LPTHREAD;

#define THREADCALL __stdcall

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

THREAD * thread_create( THREADFUNK funk, LPVOID param1, LPVOID param2 );

BOOL thread_run( THREAD * thread );

BOOL thread_sigterm( THREAD * thread );

BOOL thread_kill( THREAD * thread );

BOOL thread_join( THREAD * thread );

BOOL thread_destroy( THREAD * thread );

/*****************************************************************************************/

#endif