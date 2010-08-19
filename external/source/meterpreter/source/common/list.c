#include "common.h"

/*
 * An implementation of a simple thread safe double linked list structure. Can be used as either
 * a stack (via pop/push), a queue (via push/shift) or an array (via get/add/insert/remove). If
 * performing a group of actions on a list based on results from list actions, acquire the list 
 * lock before the group of actions and release lock when done.
 */

/*
 * Create a thread safe double linked list.
 */
LIST * list_create( VOID )
{
	LIST * list  = (LIST *)malloc( sizeof(LIST) );
	if( list != NULL )
	{
		list->start = NULL;
		list->end   = NULL;
		list->count = 0;
		list->lock  = lock_create();
		
		if( list->lock == NULL )
		{
			list_destroy( list );
			return NULL;
		}
	}
	return list;
}

/*
 * Destroy an existing linked list. This destroys all nodes and the list itself
 * but not the data held in the linked list. This is the responsibility of the 
 * caller to destroy.
 */
VOID list_destroy( LIST * list )
{
	NODE * current_node;
	NODE * next_node;

	if( list != NULL )
	{
		lock_acquire( list->lock );

		current_node = list->start;

		while( current_node != NULL )
		{
    		next_node = current_node->next;
			
			current_node->next = NULL;
			
			current_node->prev = NULL;

			free( current_node );

			current_node = next_node;
		}

		list->count = 0;

		lock_release( list->lock );
		
		lock_destroy( list->lock );

		free( list );
	}
}

/*
 * Return the number of items in the list. If using this coung value to itterate through the list
 * with list_get, acquire the lists lock before the list_count/list_get block and release it afterwards.
 */
DWORD list_count( LIST * list )
{
	DWORD count = 0;

	if( list != NULL )
	{
		lock_acquire( list->lock );

		count = list->count;

		lock_release( list->lock );
	}

	return count;
}

/*
 * Get the data value held in the list and a specified index. This will perform a linear search from
 * the begining of the list returning the data value if found or NULL if not found.
 */
LPVOID list_get( LIST * list, DWORD index )
{
	LPVOID data         = NULL;
	NODE * current_node = NULL;

	if( list == NULL )
		return NULL;

	lock_acquire( list->lock );

	if( list->count <= index )
	{
		lock_release( list->lock );
		return NULL;
	}

	current_node = list->start;

	while( current_node != NULL )
	{
		if( index == 0 )
			break;

		current_node = current_node->next;

		index--;
	}

	if( current_node != NULL )
		data = current_node->data;

	lock_release( list->lock );
	
	return data;
}

/*
 * Adds a data item onto the end of the list.
 */
BOOL list_add( LIST * list, LPVOID data )
{
	return list_push( list, data );
}

/*
 * Internal function to remove a node from a list. Assumes caller has aquired the appropriate lock first.
 */
BOOL list_remove_node( LIST * list, NODE * node )
{
	if( list == NULL || node == NULL)
		return FALSE;

	if( list->count - 1 == 0 )
	{
		list->start = NULL;
		list->end = NULL;
	}
	else
	{
		if( list->start == node )
		{
			list->start = list->start->next;
			list->start->prev = NULL;
		}
		else if( list->end == node )
		{
			list->end = list->end->prev;
			list->end->next = NULL;
		}
		else 
		{
			node->next->prev = node->prev;
			node->prev->next = node->next;
		}
	}

	list->count -= 1;

	node->next = NULL;
			
	node->prev = NULL;

	free( node );

	return TRUE;
}

/*
 * Remove a given data item from the list. Assumes data items are unqique as only the first occurrence is removed. 
 */
BOOL list_remove( LIST * list, LPVOID data )
{
	BOOL result         = FALSE;
	NODE * current_node = NULL;

	if( list == NULL || data == NULL )
		return FALSE;

	lock_acquire( list->lock );

	current_node = list->start;

	while( current_node != NULL )
	{
		if( current_node->data == data )
			break;

		current_node = current_node->next;
	}

	result = list_remove_node( list, current_node );

	lock_release( list->lock );
	
	return result;
}

/*
 * Remove a list item at the specified index. 
 */
BOOL list_delete( LIST * list, DWORD index )
{
	BOOL result         = FALSE;
	LPVOID data         = NULL;
	NODE * current_node = NULL;

	if( list == NULL )
		return FALSE;

	lock_acquire( list->lock );

	if( list->count > index )
	{
		current_node = list->start;

		while( current_node != NULL )
		{
			if( index == 0 )
			{
				result = list_remove_node( list, current_node );
				break;
			}

			current_node = current_node->next;

			index--;
		}
	}

	lock_release( list->lock );
	
	return result;
}

/*
 * Push a data item onto the end of the list.
 */
BOOL list_push( LIST * list, LPVOID data )
{
	NODE * node = NULL;
	
	if( list == NULL )
		return FALSE;

	node = (NODE *)malloc( sizeof(NODE) );
	if( node == NULL )
		return FALSE;

	node->data  = data;
	node->next  = NULL;
	node->prev  = NULL;

	lock_acquire( list->lock );

    if ( list->end != NULL )
    {
	    list->end->next = node;

		node->prev = list->end;

		list->end = node;
	}
	else
	{
		list->start = node;
		list->end   = node;
	}

	list->count += 1;

	lock_release( list->lock );

	return TRUE;
}

/*
 * Pop a data value off the end of the list.
 */
LPVOID list_pop( LIST * list )
{
	LPVOID data = NULL;

	if( list == NULL )
		return NULL;

	lock_acquire( list->lock );

	if( list->end != NULL )
	{
		data = list->end->data;

		list_remove_node( list, list->end );
	}

	lock_release( list->lock );

	return data;
}

/*
 * Pop a data value off the start of the list.
 */
LPVOID list_shift( LIST * list )
{
	LPVOID data = NULL;

	if( list == NULL )
		return NULL;

	lock_acquire( list->lock );

	if( list->start != NULL )
	{
		data = list->start->data;

		list_remove_node( list, list->start );
	}

	lock_release( list->lock );

	return data;
}