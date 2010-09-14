/*
# Copyright (c) 2010, patrickHVE@googlemail.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * The names of the author may not be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL patrickHVE@googlemail.com BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * sf - Sept 2010 - Modified for x64 support and merged into stdapi.
 */

#include "precomp.h"
#include "railgun.h"

// Gives me a copy of a data item of type TLV_META_TYPE_RAW
// caller has to free() it.
// returns NULL on fail
BYTE * getRawDataCopy(Packet *packet,TlvType type, DWORD * size){
	Tlv tlv;
	BYTE * bufferCopy;
	if (packet_get_tlv(packet, type, &tlv) != ERROR_SUCCESS){
		dprintf("getRawDataCopy: packet_get_tlv failed");
		*size = 0;
		return NULL;
	}
	*size = tlv.header.length;
	bufferCopy = (BYTE *)malloc(*size);
	if( bufferCopy )
		memcpy(bufferCopy,tlv.buffer,*size);
	return bufferCopy;
}

// Gives me a copy of a data item of type TLV_META_TYPE_RAW
// caller has to free() it.
// returns NULL on fail
BYTE * getRawDataCopyFromGroup(Packet *packet, Tlv *group, TlvType type, DWORD * size){
	Tlv tlv;
	BYTE * bufferCopy;

	if( packet_get_tlv_group_entry(packet, group, type, &tlv) != ERROR_SUCCESS ) {
		dprintf("getRawDataCopyFromGroup: packet_get_tlv failed");
		*size = 0;
		return NULL;
	}

	*size = tlv.header.length;
	bufferCopy = (BYTE *)malloc(*size);
	if( bufferCopy )
		memcpy(bufferCopy,tlv.buffer,*size);
	return bufferCopy;
}

/*
 * Perform a call to a Windows API function!
 */
DWORD railgun_call( RAILGUN_INPUT * pInput, RAILGUN_OUTPUT * pOutput )
{
	DWORD dwResult                           = ERROR_SUCCESS;
	HMODULE hDll                             = NULL;
	VOID * pFuncAddr                         = NULL;
	ULONG_PTR * pStack                       = NULL;
	const ULONG_PTR * pStackDescriptorBuffer = NULL; // do not free! Just convenience ptr to TLV
	DWORD dwStackSizeInElements              = 0;
	DWORD dwIndex                            = 0; 

	do
	{
		if( !pInput || !pOutput )
			BREAK_WITH_ERROR( "[RAILGUN] railgun_call: Input || !pOutput", ERROR_INVALID_PARAMETER );
		
		// debugprint the inputs...
#ifdef _WIN64
		dprintf("[RAILGUN] railgun_call: TLV_TYPE_RAILGUN_BUFFERBLOB_IN - dwBufferSizeIN=%d, pBufferIN=0x%llX", pInput->dwBufferSizeIN, pInput->pBufferIN );
		dprintf("[RAILGUN] railgun_call: TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT - dwBufferSizeINOUT=%d, pBufferINOUT=0x%llX", pInput->dwBufferSizeINOUT, pInput->pBufferINOUT );
		dprintf("[RAILGUN] railgun_call: Got TLV_TYPE_RAILGUN_STACKBLOB, pStack blob size=%d", pInput->pStackDescriptorTlv.header.length );
#else
		dprintf("[RAILGUN] railgun_call: TLV_TYPE_RAILGUN_BUFFERBLOB_IN - dwBufferSizeIN=%d, pBufferIN=0x%08X", pInput->dwBufferSizeIN, pInput->pBufferIN );
		dprintf("[RAILGUN] railgun_call: TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT - dwBufferSizeINOUT=%d, pBufferINOUT=0x%08X", pInput->dwBufferSizeINOUT, pInput->pBufferINOUT );
		dprintf("[RAILGUN] railgun_call: Got TLV_TYPE_RAILGUN_STACKBLOB, pStack blob size=%d", pInput->pStackDescriptorTlv.header.length );
#endif

		// fixup the outputs...
		pOutput->dwLastError       = ERROR_SUCCESS;
		pOutput->qwReturnValue     = 0;
		pOutput->pBufferOUT        = NULL;
		pOutput->pBufferINOUT      = pInput->pBufferINOUT;
		pOutput->dwBufferSizeOUT   = pInput->dwBufferSizeOUT;
		pOutput->dwBufferSizeINOUT = pInput->dwBufferSizeINOUT;

		if( pOutput->dwBufferSizeOUT )
		{
			pOutput->pBufferOUT = (BYTE *)malloc( pOutput->dwBufferSizeOUT );
			memset( pOutput->pBufferOUT, 'A', pOutput->dwBufferSizeOUT ); // this might help catch bugs
		}

#ifdef _WIN64
		dprintf("[RAILGUN] railgun_call: TLV_TYPE_RAILGUN_SIZE_OUT - dwBufferSizeOUT=%d, pBufferOUT=0x%llX", pOutput->dwBufferSizeOUT, pOutput->pBufferOUT );
#else
		dprintf("[RAILGUN] railgun_call: TLV_TYPE_RAILGUN_SIZE_OUT - dwBufferSizeOUT=%d, pBufferOUT=0x%08X", pOutput->dwBufferSizeOUT, pOutput->pBufferOUT );
#endif

		// get address of function
		hDll = LoadLibraryA( pInput->cpDllName ); // yes this increases the counter. lib should never be released. maybe the user just did a WSAStartup etc.
		if( !hDll )
			BREAK_ON_ERROR( "[RAILGUN] railgun_call: LoadLibraryA Failed." );

		pFuncAddr = (VOID *)GetProcAddress( hDll, pInput->cpFuncName );
		if( !pFuncAddr )
			BREAK_ON_ERROR( "[RAILGUN] railgun_call: GetProcAddress Failed." );
		
		if( ( pInput->pStackDescriptorTlv.header.length % ( 2 * sizeof(ULONG_PTR) ) ) != 0 )
			dprintf( "[RAILGUN] railgun_call: Warning: blob size makes no sense." );

		dwStackSizeInElements = pInput->pStackDescriptorTlv.header.length / ( 2 * sizeof(ULONG_PTR) );

		pStackDescriptorBuffer = (ULONG_PTR *)pInput->pStackDescriptorTlv.buffer;

		pStack = (ULONG_PTR *)malloc( dwStackSizeInElements * sizeof(ULONG_PTR) );
		if( !pStack )
			BREAK_WITH_ERROR( "[RAILGUN] railgun_call: malloc pStack Failed.", ERROR_OUTOFMEMORY );

#ifdef _WIN64
		dprintf( "[RAILGUN] railgun_call: dwStackSizeInElements=%d, pStack=0x%llX", dwStackSizeInElements, pStack );
#else
		dprintf( "[RAILGUN] railgun_call: dwStackSizeInElements=%d, pStack=0x%08X", dwStackSizeInElements, pStack );
#endif

		// To build the pStack we have to process the items.
		// depending on their types the items are
		// 0 - literal values
		// 1 = relative pointers to pBufferIN. Must be converted to absolute pointers
		// 2 = relative pointers to pBufferOUT. Must be converted to absolute pointers
		// 3 = relative pointers to pBufferINOUT. Must be converted to absolute pointers
		for( dwIndex=0 ; dwIndex<dwStackSizeInElements ; dwIndex++ )
		{
			ULONG_PTR dwItem = pStackDescriptorBuffer[ dwIndex*2+1 ];
			switch( pStackDescriptorBuffer[ dwIndex*2 ] )
			{
				case 0:	// do nothing. item is a literal value
#ifdef _WIN64
					dprintf("[RAILGUN] railgun_call: Param %d is literal:0x%llX", dwIndex, dwItem );
#else
					dprintf("[RAILGUN] railgun_call: Param %d is literal:0x%08X", dwIndex, dwItem );
#endif
					pStack[dwIndex] = dwItem;
					break;
				case 1:	// relative ptr to pBufferIN. Convert to absolute Ptr
					pStack[dwIndex] = dwItem + ( (ULONG_PTR)pInput->pBufferIN );
#ifdef _WIN64
					dprintf("[RAILGUN] railgun_call: Param %d is relative to pBufferIN: 0x%llX => 0x%llX", dwIndex, dwItem, pStack[dwIndex] );
#else
					dprintf("[RAILGUN] railgun_call: Param %d is relative to pBufferIN: 0x%08X => 0x%08X", dwIndex, dwItem, pStack[dwIndex] );
#endif
					break;
				case 2:	// relative ptr to pBufferOUT. Convert to absolute Ptr
					pStack[dwIndex] = dwItem + ( (ULONG_PTR)pOutput->pBufferOUT );
#ifdef _WIN64
					dprintf("[RAILGUN] railgun_call: Param %d is relative to pBufferOUT: 0x%llX => 0x%llX", dwIndex, dwItem, pStack[dwIndex] );
#else
					dprintf("[RAILGUN] railgun_call: Param %d is relative to pBufferOUT: 0x%08X => 0x%08X", dwIndex, dwItem, pStack[dwIndex] );
#endif
					break;
				case 3:	// relative ptr to pBufferINOUT. Convert to absolute Ptr
					pStack[dwIndex] = dwItem + ( (ULONG_PTR)pInput->pBufferINOUT );
#ifdef _WIN64
					dprintf("[RAILGUN] railgun_call: Param %d is relative to pBufferINOUT: 0x%llX => 0x%llX", dwIndex, dwItem, pStack[dwIndex] );
#else
					dprintf("[RAILGUN] railgun_call: Param %d is relative to pBufferINOUT: 0x%08X => 0x%08X", dwIndex, dwItem, pStack[dwIndex] );
#endif
					break;
				default:
					dprintf("[RAILGUN] railgun_call: Invalid pStack item description %d for item %d", pStackDescriptorBuffer[ dwIndex*2 ], dwIndex );
					dwResult = ERROR_INVALID_PARAMETER;
					break;
			}
		}

		if( dwResult != ERROR_SUCCESS )
			break;
		
#ifdef _WIN64
		dprintf( "[RAILGUN] railgun_call: Calling %s!%s @ 0x%llX...", pInput->cpDllName, pInput->cpFuncName, pFuncAddr );
#else
		dprintf( "[RAILGUN] railgun_call: Calling %s!%s @ 0x%08X...", pInput->cpDllName, pInput->cpFuncName, pFuncAddr );
#endif

		SetLastError( ERROR_SUCCESS );

		__try
		{
			switch( dwStackSizeInElements )
			{
				case  0: pOutput->qwReturnValue = function( 00 )(); break;
				case  1: pOutput->qwReturnValue = function( 01 )( p(0) ); break;
				case  2: pOutput->qwReturnValue = function( 02 )( p(0), p(1) ); break;
				case  3: pOutput->qwReturnValue = function( 03 )( p(0), p(1), p(2) ); break;
				case  4: pOutput->qwReturnValue = function( 04 )( p(0), p(1), p(2), p(3) );break;
				case  5: pOutput->qwReturnValue = function( 05 )( p(0), p(1), p(2), p(3), p(4) );break;
				case  6: pOutput->qwReturnValue = function( 06 )( p(0), p(1), p(2), p(3), p(4), p(5) );break;
				case  7: pOutput->qwReturnValue = function( 07 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6) );break;
				case  8: pOutput->qwReturnValue = function( 08 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7) );break;
				case  9: pOutput->qwReturnValue = function( 09 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8) );break;
				case 10: pOutput->qwReturnValue = function( 10 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9) );break;	
				case 11: pOutput->qwReturnValue = function( 11 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10) );break;
				case 12: pOutput->qwReturnValue = function( 12 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11) );break;
				case 13: pOutput->qwReturnValue = function( 13 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12) );break;
				case 14: pOutput->qwReturnValue = function( 14 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13) );break;
				case 15: pOutput->qwReturnValue = function( 15 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14) );break;
				case 16: pOutput->qwReturnValue = function( 16 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15) );break;
				case 17: pOutput->qwReturnValue = function( 17 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16) );break;
				case 18: pOutput->qwReturnValue = function( 18 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17) );break;
				case 19: pOutput->qwReturnValue = function( 19 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18) );break;
				case 20: pOutput->qwReturnValue = function( 20 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19) );break;
				case 21: pOutput->qwReturnValue = function( 21 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20) );break;
				case 22: pOutput->qwReturnValue = function( 22 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21) );break;
				case 23: pOutput->qwReturnValue = function( 23 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21), p(22) );break;
				case 24: pOutput->qwReturnValue = function( 24 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21), p(22), p(23) );break;
				case 25: pOutput->qwReturnValue = function( 25 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21), p(22), p(23), p(24) );break;

				default:
					dprintf( "[RAILGUN] railgun_call: Can't call function: dwStackSizeInElements (%d) is > 25", dwStackSizeInElements );
					pOutput->qwReturnValue = -1;
					SetLastError( ERROR_INVALID_PARAMETER );
					break;
			}

		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			dprintf("[RAILGUN] railgun_call: EXCEPTION RAISED!!!" );
			pOutput->qwReturnValue = -1;
			SetLastError( ERROR_UNHANDLED_EXCEPTION );
		}
			
		pOutput->dwLastError = GetLastError();

#ifdef _WIN64
		dprintf("[RAILGUN] railgun_call: pOutput->dwLastError=0x%08X, pOutput->qwReturnValue=0x%llX", pOutput->dwLastError, pOutput->qwReturnValue );
#else
		dprintf("[RAILGUN] railgun_call: pOutput->dwLastError=0x%08X, pOutput->qwReturnValue=0x%08X", pOutput->dwLastError, pOutput->qwReturnValue );
#endif

	} while( 0 );

	if( pStack )
		free( pStack );

	SetLastError( dwResult );

	return dwResult;
}

// Multi-request railgun API
DWORD request_railgun_api_multi( Remote * remote, Packet * packet )
{
	Packet * response      = packet_create_response(packet);
	DWORD dwResult         = ERROR_SUCCESS;
	DWORD index            = 0;
	Tlv reqTlv             = {0};
	Tlv tmpTlv             = {0};
	Tlv   tlvs[4]          = {0};
	RAILGUN_INPUT rInput   = {0};
	RAILGUN_OUTPUT rOutput = {0};

	dprintf("[RAILGUN] request_railgun_api_multi: Starting...");

	dprintf( "[RAILGUN] request_railgun_api_multi: processing %d elements (%d | %d)", TLV_TYPE_RAILGUN_MULTI_GROUP, packet->header.type, packet->header.length);

	while( packet_enum_tlv( packet, index++, TLV_TYPE_RAILGUN_MULTI_GROUP, &reqTlv ) == ERROR_SUCCESS )
	{
		dprintf( "[RAILGUN] request_railgun_api_multi: index=%d", index );

		memset( &rInput, 0, sizeof(RAILGUN_INPUT) );
		memset( &rOutput, 0, sizeof(RAILGUN_OUTPUT) );

		// get ths inputs for this call...
		if( packet_get_tlv_group_entry( packet, &reqTlv, TLV_TYPE_RAILGUN_SIZE_OUT, &tmpTlv ) != ERROR_SUCCESS )
		{
			dprintf( "[RAILGUN] request_railgun_api_multi: Could not get TLV_TYPE_RAILGUN_SIZE_OUT" );
			goto cleanup;
		}

		rInput.dwBufferSizeOUT = ntohl( *(LPDWORD)tmpTlv.buffer );

		rInput.pBufferIN = getRawDataCopyFromGroup( packet, &reqTlv, TLV_TYPE_RAILGUN_BUFFERBLOB_IN, (DWORD *)&rInput.dwBufferSizeIN );
		if( !rInput.pBufferIN )
		{
			dprintf( "[RAILGUN] request_railgun_api_multi: Could not get TLV_TYPE_RAILGUN_BUFFERBLOB_IN" );
			goto cleanup;
		}

		rInput.pBufferINOUT = getRawDataCopyFromGroup( packet, &reqTlv, TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, (DWORD *)&rInput.dwBufferSizeINOUT );
		if( !rInput.pBufferINOUT )
		{
			dprintf( "[RAILGUN] request_railgun_api_multi: Could not get TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT" );
			goto cleanup;
		}

		if( packet_get_tlv_group_entry( packet, &reqTlv, TLV_TYPE_RAILGUN_DLLNAME, &tmpTlv ) != ERROR_SUCCESS )
		{
			dprintf( "[RAILGUN] request_railgun_api_multi: Could not get TLV_TYPE_RAILGUN_DLLNAME" );
			goto cleanup;
		}

		rInput.cpDllName = (PCHAR)tmpTlv.buffer;
		if( !rInput.cpDllName )
		{
			dprintf( "[RAILGUN] request_railgun_api_multi: Could not get TLV_TYPE_RAILGUN_DLLNAME" );
			goto cleanup;
		}

		if( packet_get_tlv_group_entry( packet, &reqTlv, TLV_TYPE_RAILGUN_FUNCNAME, &tmpTlv ) != ERROR_SUCCESS )
		{
			dprintf( "[RAILGUN] request_railgun_api_multi: Could not get TLV_TYPE_RAILGUN_FUNCNAME" );
			goto cleanup;
		}

		rInput.cpFuncName = (PCHAR)tmpTlv.buffer;
		if( !rInput.cpFuncName )
		{
			dprintf( "[RAILGUN] request_railgun_api_multi: Could not get TLV_TYPE_RAILGUN_FUNCNAME" );
			goto cleanup;
		}

		if( packet_get_tlv_group_entry( packet, &reqTlv, TLV_TYPE_RAILGUN_STACKBLOB, &rInput.pStackDescriptorTlv ) != ERROR_SUCCESS )
		{
			dprintf( "[RAILGUN] request_railgun_api_multi: packet_get_tlv_group_entry failed" );
			goto cleanup;
		}

		dwResult = railgun_call( &rInput, &rOutput );

		// time to ship stuff back
		tlvs[0].header.length = sizeof(DWORD);
		tlvs[0].header.type   = TLV_TYPE_RAILGUN_BACK_ERR;
		tlvs[0].buffer        = (PUCHAR)&rOutput.dwLastError;
		tlvs[1].header.length = sizeof(QWORD);
		tlvs[1].header.type   = TLV_TYPE_RAILGUN_BACK_RET;
		tlvs[1].buffer        = (PUCHAR)&rOutput.qwReturnValue;
		tlvs[2].header.length = (DWORD)rOutput.dwBufferSizeOUT;
		tlvs[2].header.type   = TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT;
		tlvs[2].buffer        = (PUCHAR)rOutput.pBufferOUT;
		tlvs[3].header.length = (DWORD)rOutput.dwBufferSizeINOUT;
		tlvs[3].header.type   = TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT;
		tlvs[3].buffer        = (PUCHAR)rOutput.pBufferINOUT;

		packet_add_tlv_group( response, TLV_TYPE_RAILGUN_MULTI_GROUP, tlvs, 4 );

	cleanup:

		if( rInput.pBufferIN )
			free( rInput.pBufferIN );

		if( rInput.pBufferINOUT )
			free( rInput.pBufferINOUT );

		if( rOutput.pBufferOUT )
			free( rOutput.pBufferOUT );
	}

	packet_transmit_response( dwResult, remote, response );

	dprintf( "[RAILGUN] request_railgun_api_multi: Finished." );

	return dwResult;
}

// Single-request railgun API
DWORD request_railgun_api( Remote * pRemote, Packet * pPacket )
{
	DWORD dwResult         = ERROR_SUCCESS;
	Packet * pResponse     = NULL;
	RAILGUN_INPUT rInput   = {0};
	RAILGUN_OUTPUT rOutput = {0};

	dprintf("[RAILGUN] request_railgun_api: Starting...");
	
	do
	{
		pResponse = packet_create_response( pPacket );
		if( !pResponse )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_api: !pResponse", ERROR_INVALID_HANDLE );

		memset( &rInput, 0, sizeof(RAILGUN_INPUT) );
		memset( &rOutput, 0, sizeof(RAILGUN_OUTPUT) );

		// Prepare the OUT-Buffer (undefined content)
		rInput.dwBufferSizeOUT = packet_get_tlv_value_uint( pPacket, TLV_TYPE_RAILGUN_SIZE_OUT );

		// get the IN-Buffer
		rInput.pBufferIN = getRawDataCopy( pPacket,TLV_TYPE_RAILGUN_BUFFERBLOB_IN, (DWORD *)&rInput.dwBufferSizeIN);
		if( !rInput.pBufferIN )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_api: Could not get TLV_TYPE_RAILGUN_BUFFERBLOB_IN", ERROR_INVALID_PARAMETER );

		// get the INOUT-Buffer
		rInput.pBufferINOUT = getRawDataCopy( pPacket, TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, (DWORD *)&rInput.dwBufferSizeINOUT );
		if( !rInput.pBufferINOUT )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_api: Could not get TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT", ERROR_INVALID_PARAMETER );
		
		// Get cpDllName
		rInput.cpDllName = packet_get_tlv_value_string( pPacket, TLV_TYPE_RAILGUN_DLLNAME );
		if( !rInput.cpDllName )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_api: Could not get TLV_TYPE_RAILGUN_DLLNAME", ERROR_INVALID_PARAMETER );

		// Get cpFuncName
		rInput.cpFuncName = packet_get_tlv_value_string( pPacket, TLV_TYPE_RAILGUN_FUNCNAME );
		if( !rInput.cpFuncName )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_api: Could not get TLV_TYPE_RAILGUN_FUNCNAME", ERROR_INVALID_PARAMETER );

		// get the pStack-description (1 ULONG_PTR description, 1 ULONG_PTR data)
		if( packet_get_tlv( pPacket, TLV_TYPE_RAILGUN_STACKBLOB, &rInput.pStackDescriptorTlv ) != ERROR_SUCCESS)
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_api: Could not get TLV_TYPE_RAILGUN_STACKBLOB", ERROR_INVALID_PARAMETER );

		dwResult = railgun_call( &rInput, &rOutput );

	} while( 0 );

	if( pResponse )
	{
		packet_add_tlv_uint( pResponse, TLV_TYPE_RESULT, dwResult );
		
		if( dwResult == ERROR_SUCCESS )
		{
			packet_add_tlv_uint( pResponse, TLV_TYPE_RAILGUN_BACK_ERR, rOutput.dwLastError );
			packet_add_tlv_qword( pResponse, TLV_TYPE_RAILGUN_BACK_RET, rOutput.qwReturnValue );
			packet_add_tlv_raw( pResponse, TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT, rOutput.pBufferOUT, (DWORD)rOutput.dwBufferSizeOUT );
			packet_add_tlv_raw( pResponse, TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT, rOutput.pBufferINOUT, (DWORD)rOutput.dwBufferSizeINOUT );
		}

		dwResult = packet_transmit( pRemote, pResponse, NULL );
	}
	
	if( rInput.pBufferIN )
		free( rInput.pBufferIN );

	if( rInput.pBufferINOUT )
		free( rInput.pBufferINOUT );
	
	if( rOutput.pBufferOUT )
		free( rOutput.pBufferOUT );

	dprintf("[RAILGUN] request_railgun_api: Finished.");

	return dwResult;
}

/*
 * Read a user supplied ammount of data from a user supplied address in memory.
 */
DWORD request_railgun_memread( Remote * pRemote, Packet * pPacket )
{
	DWORD dwResult     = ERROR_SUCCESS;
	Packet * pResponse = NULL;
	LPVOID lpAddress   = NULL;
	BYTE * pData       = NULL;
	DWORD dwLength     = 0;

	dprintf("[RAILGUN] request_railgun_memread: Starting...");
	
	do
	{
		pResponse = packet_create_response( pPacket );
		if( !pResponse )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_memread: !pResponse", ERROR_INVALID_HANDLE );

		lpAddress = (LPVOID)packet_get_tlv_value_qword( pPacket, TLV_TYPE_RAILGUN_MEM_ADDRESS );
		if( !lpAddress )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_memread: !lpAddress", ERROR_INVALID_PARAMETER );

		dwLength = packet_get_tlv_value_uint( pPacket, TLV_TYPE_RAILGUN_MEM_LENGTH );
		if( !dwLength )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_memread: !dwLength", ERROR_INVALID_PARAMETER );

		pData = (BYTE *)malloc( dwLength );
		if( !pData )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_memread: !pData", ERROR_NOT_ENOUGH_MEMORY );

		__try
		{
			memcpy( pData, lpAddress, dwLength );
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			dwResult = ERROR_UNHANDLED_EXCEPTION;
		}
			
	} while( 0 );

	if( pResponse )
	{
		packet_add_tlv_uint( pResponse, TLV_TYPE_RESULT, dwResult );

		if( pData )
			packet_add_tlv_raw( pResponse, TLV_TYPE_RAILGUN_MEM_DATA, pData, dwLength );

		dwResult = packet_transmit( pRemote, pResponse, NULL );
	}

	if( pData )
		free( pData );

	dprintf("[RAILGUN] request_railgun_memread: Finished.");

	return dwResult;
}

/*
 * Write a user supplied buffer to a user supplied address in memory.
 */
DWORD request_railgun_memwrite( Remote * pRemote, Packet * pPacket )
{
	DWORD dwResult     = ERROR_SUCCESS;
	Packet * pResponse = NULL;
	LPVOID lpAddress   = NULL;
	BYTE * pData       = NULL;
	DWORD dwLength     = 0;

	dprintf("[RAILGUN] request_railgun_memwrite: Starting...");
	
	do
	{
		pResponse = packet_create_response( pPacket );
		if( !pResponse )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_memwrite: !pResponse", ERROR_INVALID_HANDLE );

		lpAddress = (LPVOID)packet_get_tlv_value_qword( pPacket, TLV_TYPE_RAILGUN_MEM_ADDRESS );
		if( !lpAddress )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_memwrite: !lpAddress", ERROR_INVALID_PARAMETER );

		pData = packet_get_tlv_value_raw( pPacket, TLV_TYPE_RAILGUN_MEM_DATA );
		if( !pData )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_memwrite: !pData", ERROR_INVALID_PARAMETER );
		
		dwLength = packet_get_tlv_value_uint( pPacket, TLV_TYPE_RAILGUN_MEM_LENGTH );
		if( !dwLength )
			BREAK_WITH_ERROR( "[RAILGUN] request_railgun_memwrite: !dwLength", ERROR_INVALID_PARAMETER );

		__try
		{
			memcpy( lpAddress, pData, dwLength );
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			dwResult = ERROR_UNHANDLED_EXCEPTION;
		}
			
	} while( 0 );

	if( pResponse )
	{
		packet_add_tlv_uint( pResponse, TLV_TYPE_RESULT, dwResult );

		dwResult = packet_transmit( pRemote, pResponse, NULL );
	}

	dprintf("[RAILGUN] request_railgun_memwrite: Finished.");

	return dwResult;
}
