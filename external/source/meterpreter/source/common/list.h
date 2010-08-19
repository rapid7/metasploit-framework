#ifndef _METERPRETER_LIB_LIST_H
#define _METERPRETER_LIB_LIST_H

/*****************************************************************************************/

typedef struct _NODE
{
	struct _NODE * next;
	struct _NODE * prev;
	LPVOID data;
} NODE;

typedef struct _LIST
{
	NODE * start;
	NODE * end;
	DWORD count;
	LOCK * lock;
} LIST;

/*****************************************************************************************/

LIST * list_create( VOID );

VOID list_destroy( LIST * list );

DWORD list_count( LIST * list );

LPVOID list_get( LIST * list, DWORD index );

BOOL list_add( LIST * list, LPVOID data );

BOOL list_remove( LIST * list, LPVOID data );

BOOL list_delete( LIST * list, DWORD index );

BOOL list_push( LIST * list, LPVOID data );

LPVOID list_pop( LIST * list );

LPVOID list_shift( LIST * list );

/*****************************************************************************************/

#endif