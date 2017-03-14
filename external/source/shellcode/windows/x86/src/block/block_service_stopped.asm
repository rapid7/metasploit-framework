;-----------------------------------------------------------------------------;
; Author: agix (florian.gaultier[at]gmail[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Size: 448 bytes
;-----------------------------------------------------------------------------;

[BITS 32]
; Input: EBP must be the address of 'api_call'.

call me3
me3:
pop edi
jmp 0x7
pop eax
pop eax
pop eax
pop eax
xor eax,eax
ret
push 0x00464349
push 0x56524553
mov ecx, esp	;SVCNAME
lea eax, [edi+0x3];SvcCtrlHandler
push 0x00000000
push eax
push ecx
push 0x5244AA0B
call ebp		;RegisterServiceCtrlHandlerExA
push 0x00000000
push 0x00000000
push 0x00000000
push 0x00000000
push 0x00000000
push 0x00000000
push 0x00000001
push 0x00000010
mov ecx, esp
push 0x00000000
push ecx
push eax
push 0x7D3755C6
call ebp		;SetServiceStatus RUNNING
push 0x0
push 0x56a2b5f0
call ebp 		;ExitProcess